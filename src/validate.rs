//! The check lane: raw hyper `client::conn` over an already-dial-verified
//! socket — one handshake per proxy, no connection pool (proxies are
//! touched exactly once; a pooled client keys by authority, which is
//! meaningless across a fan-out).
//!
//! `validate.check_url` decides the wire shape:
//!   http target  → http proxies: absolute-form GET straight at the proxy;
//!                   https proxies: same inside their TLS listener;
//!                   socks: tunnel + origin-form GET.
//!   https target → every proxy CONNECT-tunnelled, then a certificate-
//!                   VERIFIED TLS session to the target runs an origin-form
//!                   GET — the proxy cannot fake the answer.
//!
//! `validate.backup_urls` spreads probes round-robin over several echo
//! endpoints, each with an auto in-flight budget (concurrency ÷ target count): a
//! single host hammered at 2k concurrency starts rate-limiting, and
//! throttled drops are indistinguishable from dead proxies — wrong
//! verdicts are worse than slow runs.
//!
//! Credentials from the list are applied per protocol: Proxy-Authorization
//! (http/https), RFC1929 username/password (socks5), USERID (socks4).
//!
//! Statuses: live | auth-required | tls-fail | socks-rejected | tcp-alive | dead

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use rustls::pki_types::ServerName;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;

use crate::config::{CheckTarget, Validate};
use crate::model::{Auth, Candidate, ProbeResult, Scheme};

#[derive(Clone)]
pub struct CheckCfg {
    pub concurrency: usize,
    pub connect_timeout: Duration,
    pub total_timeout: Duration,
    pub debug: bool,
}

impl CheckCfg {
    /// Raise the OS fd soft limit toward the requested concurrency and
    /// honour whatever the kernel grants (each in-flight check holds one
    /// socket, plus TLS buffers).
    pub fn from_validate(v: &Validate, debug: bool) -> Result<Self, String> {
        let want = v.max_concurrent_checks;
        let cap = match rlimit::increase_nofile_limit(want as u64 + 64) {
            Ok(granted) => granted.saturating_sub(64).max(16) as usize,
            Err(_) => want.min(256),
        };
        Ok(Self {
            concurrency: want.min(cap).max(16),
            connect_timeout: Duration::from_secs_f64(v.connect_timeout),
            total_timeout: Duration::from_secs_f64(v.timeout),
            debug,
        })
    }
}

/// One echo endpoint with its own in-flight budget.
pub struct TargetSlot {
    pub target: CheckTarget,
    /// resolved addresses, IPv4 first (SOCKS4 needs a v4 literal)
    pub ips: Vec<IpAddr>,
    pub authority: String,
    sem: Arc<Semaphore>,
}

/// (bucket, human detail). Buckets are the stable vocabulary; detail shows
/// up in logs only under debug.
type Fail = (&'static str, String);

pub struct Validator {
    cfg: CheckCfg,
    slots: Vec<TargetSlot>,
    rr: AtomicUsize,
    own_egress: Option<IpAddr>,
    tls_verify_off: Arc<rustls::ClientConfig>,
    tls_verified: Arc<rustls::ClientConfig>,
    done: Arc<AtomicUsize>,
}

impl Validator {
    /// targets[0] is the primary; unresolvable backups are dropped with a
    /// warning, an unresolvable primary is fatal.
    pub async fn new(cfg: CheckCfg, targets: Vec<CheckTarget>) -> Result<Self, String> {
        if targets.is_empty() {
            return Err("no check targets configured".into());
        }
        let targets_len = targets.len();
        let tls_verify_off = Arc::new(tls_config(false)?);
        let tls_verified = Arc::new(tls_config(true)?);
        let mut slots = Vec::new();
        for (i, t) in targets.into_iter().enumerate() {
            match resolve(&t).await {
                Ok(ips) => {
                    let authority = authority_of(&t);
                    slots.push(TargetSlot {
                        sem: Arc::new(Semaphore::new(
                            cfg.concurrency.div_ceil(targets_len).max(16),
                        )),
                        target: t,
                        ips,
                        authority,
                    });
                }
                Err(e) if i == 0 => return Err(e),
                Err(e) => eprintln!("[validate] backup target {} dropped: {e}", t.url),
            }
        }
        let mut me = Self {
            cfg,
            slots,
            rr: AtomicUsize::new(0),
            own_egress: None,
            tls_verify_off,
            tls_verified,
            done: Arc::new(AtomicUsize::new(0)),
        };
        // Health-check each echo's BODY SHAPE at startup: an echo that
        // answers but whose body we cannot read as an IP would silently
        // null out exit_ip/anonymity for every proxy assigned to it — a
        // wrong verdict, so drop it loudly instead.
        let mut i = 0usize;
        while i < me.slots.len() {
            let shape = me.check_shape(&me.slots[i]).await;
            let url = me.slots[i].target.url.clone();
            match shape {
                Shape::Ok(ip) => {
                    if i == 0 {
                        me.own_egress = Some(ip);
                    }
                    i += 1;
                }
                Shape::Unreachable if i == 0 => {
                    eprintln!(
                        "[validate] primary {url} unreachable now; transparent-detection degraded, liveness still runs"
                    );
                    i += 1;
                }
                Shape::Unreachable => {
                    eprintln!("[validate] backup {url} unreachable at startup, dropped");
                    me.slots.remove(i);
                }
                Shape::Wrong(detail) if i == 0 => {
                    return Err(format!(
                        "primary check_url {url} body is not an exit IP: {detail}"
                    ));
                }
                Shape::Wrong(detail) => {
                    eprintln!("[validate] backup {url} wrong body shape ({detail}), dropped");
                    me.slots.remove(i);
                }
            }
        }
        Ok(me)
    }

    /// echo endpoints still active after startup shape verification, in slot order
    pub fn active_targets(&self) -> Vec<String> {
        self.slots.iter().map(|s| s.target.url.clone()).collect()
    }

    pub async fn run(self: &Arc<Self>, candidates: Vec<Candidate>, tx: mpsc::Sender<ProbeResult>) {
        let total = candidates.len();
        let done = self.done.clone();
        let progress = tokio::spawn(async move {
            let t0 = Instant::now();
            let mut last = usize::MAX;
            loop {
                tokio::time::sleep(Duration::from_millis(300)).await;
                let d = done.load(Ordering::Relaxed);
                if d == last {
                    continue; // only redraw on movement: no identical-line spam
                }
                last = d;
                if d >= total {
                    break;
                }
                let secs = t0.elapsed().as_secs_f64().max(0.001);
                let rate = d as f64 / secs;
                let eta = (total - d) as f64 / rate;
                eprint!(
                    "\r[check ] {d:>7}/{total:<7} {:>3}%  {rate:>5.0}/s  eta {eta:>4.0}s ",
                    d * 100 / total
                );
            }
            eprint!(
                "\r[check ] {total:>7}/{total:<7} 100%  {:>5.1}/s  done in {:>5.1}s\n",
                total as f64 / t0.elapsed().as_secs_f64().max(0.001),
                t0.elapsed().as_secs_f64()
            );
        });
        let mut set = JoinSet::new();
        for c in candidates {
            while set.len() >= self.cfg.concurrency {
                set.join_next().await;
            }
            let me = self.clone();
            let tx = tx.clone();
            let done = self.done.clone();
            set.spawn(async move {
                let (mut r, fail) = me.probe(&c).await;
                // Label formatting deferred: the dead majority never needs it.
                if r.proxy.is_empty()
                    && (me.cfg.debug || matches!(r.status, "live" | "auth-required"))
                {
                    r.proxy = proxy_label(&c);
                }
                r.input = c.input;
                if let Some((_, reason)) = fail {
                    if me.cfg.debug {
                        eprintln!("\n[{}] {} {reason}", r.status, r.proxy);
                    }
                    r.fail_reason = Some(reason);
                }
                let _ = tx.send(r).await;
                done.fetch_add(1, Ordering::Relaxed);
            });
        }
        drop(tx);
        while set.join_next().await.is_some() {}
        let _ = progress.await;
    }

    async fn probe(&self, c: &Candidate) -> (ProbeResult, Option<Fail>) {
        // Round-robin the echo target. SOCKS4 has no proxy-side DNS: only
        // slots with an IPv4 address may serve it, or a healthy v4 relay gets
        // a wrong "socks-rejected".
        let start = Instant::now();
        let slot_idx = match pick_slot(
            &self.slots,
            self.rr.fetch_add(1, Ordering::Relaxed),
            matches!(c.scheme, Scheme::Socks4),
        ) {
            Some(i) => i,
            None => {
                return (
                    self.blank(c, "socks-rejected", start, start, -1),
                    Some((
                        "socks-rejected",
                        "no IPv4-capable echo target for socks4".into(),
                    )),
                );
            }
        };
        let slot = &self.slots[slot_idx];
        // Dial FIRST: ~70% of candidates die at the socket and never touch an
        // echo, so taking the permit before the dial let dead probes squat on
        // echo budget (measured utilization ≈201/512 with that order).
        let tcp = match tokio::time::timeout(self.cfg.connect_timeout, TcpStream::connect(c.addr))
            .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                return (
                    self.blank(c, "dead", start, start, -1),
                    Some(("dead", e.to_string())),
                );
            }
            Err(_) => {
                return (
                    self.blank(c, "dead", start, start, -1),
                    Some(("dead", "connect timeout".into())),
                );
            }
        };
        let _ = tcp.set_nodelay(true);
        let connected = Instant::now();
        let permit =
            match tokio::time::timeout(self.remaining(connected), slot.sem.clone().acquire_owned())
                .await
            {
                Ok(Ok(p)) => p,
                Ok(Err(_)) => {
                    return (
                        self.blank(c, "tcp-alive", start, connected, slot_idx as i16),
                        Some(("tcp-alive", "target closed".into())),
                    );
                }
                Err(_) => {
                    return (
                        self.blank(c, "tcp-alive", start, connected, slot_idx as i16),
                        Some(("tcp-alive", "echo target saturated".into())),
                    );
                }
            };
        let out = match (c.scheme, slot.target.tls) {
            (Scheme::Http, false) => self.forward_get(tcp, connected, c, slot).await,
            (Scheme::Https, false) => self.tls_proxy_get(tcp, connected, c, slot).await,
            (Scheme::Http, true) => self.connect_tls_get(tcp, connected, c, slot).await,
            (Scheme::Https, true) => self.tls_connect_tls_get(tcp, connected, c, slot).await,
            (Scheme::Socks5, plain) => self.socks5_get(tcp, connected, plain, c, slot).await,
            (Scheme::Socks4, plain) => self.socks4_get(tcp, connected, plain, c, slot).await,
        };
        drop(permit);
        match out {
            Ok(mut r) => {
                r.proxy = proxy_label(c);
                r.scheme = c.scheme.as_str();
                r.slot = slot_idx as i16;
                r.connect_ms = connected.duration_since(start).as_millis() as u32;
                r.total_ms = start.elapsed().as_millis() as u32;
                (r, None)
            }
            Err(fail) => {
                let mut r = self.blank(c, fail.0, start, connected, slot_idx as i16);
                r.proxy = proxy_label(c);
                (r, Some(fail))
            }
        }
    }

    fn blank(
        &self,
        c: &Candidate,
        status: &'static str,
        start: Instant,
        connected: Instant,
        slot: i16,
    ) -> ProbeResult {
        ProbeResult {
            proxy: String::new(),
            scheme: c.scheme.as_str(),
            input: String::new(),
            status,
            anonymity: None,
            connect_ms: connected.duration_since(start).as_millis() as u32,
            ttfb_ms: None,
            total_ms: start.elapsed().as_millis() as u32,
            exit_ip: None,
            slot,
            fail_reason: None,
        }
    }

    // ---- scheme flows -------------------------------------------------

    /// http proxy + http target: absolute-form GET straight at the proxy.
    async fn forward_get(
        &self,
        tcp: TcpStream,
        connected: Instant,
        c: &Candidate,
        slot: &TargetSlot,
    ) -> Result<ProbeResult, Fail> {
        let req = self.request(&slot.target.url, None, c.auth.as_ref())?;
        self.run_conn(tcp, req, connected, c.addr.ip()).await
    }

    /// https proxy + http target: TLS to the proxy (self-signed endpoints
    /// are the norm → verification off for the outer hop), then the
    /// absolute-form GET inside.
    async fn tls_proxy_get(
        &self,
        tcp: TcpStream,
        connected: Instant,
        c: &Candidate,
        slot: &TargetSlot,
    ) -> Result<ProbeResult, Fail> {
        let tls = self
            .tls_wrap(&self.tls_verify_off, tcp, connected, &slot.target.host)
            .await?;
        let req = self.request(&slot.target.url, None, c.auth.as_ref())?;
        self.run_conn(tls, req, connected, c.addr.ip())
            .await
            .map_err(bump_tls)
    }

    /// http proxy + https target: CONNECT → verified TLS → origin GET.
    async fn connect_tls_get(
        &self,
        tcp: TcpStream,
        connected: Instant,
        c: &Candidate,
        slot: &TargetSlot,
    ) -> Result<ProbeResult, Fail> {
        let mut tcp = tcp;
        self.connect_phase(&mut tcp, connected, &slot.authority, c.auth.as_ref())
            .await?;
        let tls = self
            .tls_wrap(&self.tls_verified, tcp, connected, &slot.target.host)
            .await?;
        let req = self.request(&slot.target.path, Some(&slot.authority), c.auth.as_ref())?;
        self.run_conn(tls, req, connected, c.addr.ip())
            .await
            .map_err(bump_tls)
    }

    /// https proxy + https target: unverified TLS to the proxy, CONNECT,
    /// then a second VERIFIED TLS session to the target through the tunnel.
    async fn tls_connect_tls_get(
        &self,
        tcp: TcpStream,
        connected: Instant,
        c: &Candidate,
        slot: &TargetSlot,
    ) -> Result<ProbeResult, Fail> {
        let outer = self
            .tls_wrap(&self.tls_verify_off, tcp, connected, &slot.target.host)
            .await?;
        let mut outer = outer;
        self.connect_phase(&mut outer, connected, &slot.authority, c.auth.as_ref())
            .await?;
        let inner = self
            .tls_wrap(&self.tls_verified, outer, connected, &slot.target.host)
            .await?;
        let req = self.request(&slot.target.path, Some(&slot.authority), c.auth.as_ref())?;
        self.run_conn(inner, req, connected, c.addr.ip())
            .await
            .map_err(bump_tls)
    }

    /// socks5: domain-form CONNECT (proxy-side DNS); username/password
    /// sub-negotiation when the entry carried credentials; optional verified
    /// TLS on top for https targets.
    async fn socks5_get(
        &self,
        tcp: TcpStream,
        connected: Instant,
        plain_target: bool,
        c: &Candidate,
        slot: &TargetSlot,
    ) -> Result<ProbeResult, Fail> {
        let target = (slot.target.host.as_str(), slot.target.port);
        let handshake = async {
            match &c.auth {
                Some(a) if !a.user.is_empty() => match &a.password {
                    Some(p) => {
                        tokio_socks::tcp::Socks5Stream::connect_with_password_and_socket(
                            tcp, target, &a.user, p,
                        )
                        .await
                    }
                    None => tokio_socks::tcp::Socks5Stream::connect_with_socket(tcp, target).await,
                },
                _ => tokio_socks::tcp::Socks5Stream::connect_with_socket(tcp, target).await,
            }
        };
        let tunnel = tokio::time::timeout(self.remaining(connected), handshake)
            .await
            .map_err(|_| ("dead", "socks5 timeout".to_string()))?
            .map_err(|e| (socks_error_status(&format!("{e:?}")), format!("{e:?}")))?;
        let inner = tunnel.into_inner();
        self.tunneled_get(inner, connected, plain_target, c.addr.ip(), slot)
            .await
    }

    /// socks4: v4-literal handshake (no proxy-side DNS), optional TLS, GET.
    async fn socks4_get(
        &self,
        mut tcp: TcpStream,
        connected: Instant,
        plain_target: bool,
        c: &Candidate,
        slot: &TargetSlot,
    ) -> Result<ProbeResult, Fail> {
        let Some(&IpAddr::V4(ip)) = slot.ips.iter().find(|a| a.is_ipv4()) else {
            return Err((
                "socks-rejected",
                "target host has no IPv4 for socks4".into(),
            ));
        };
        let userid = match &c.auth {
            Some(a) => format!("{}\0", a.user),
            None => "proxalyze\0".to_string(),
        };
        let pkt: Vec<u8> = [
            &[0x04u8, 0x01u8][..],
            &slot.target.port.to_be_bytes(),
            &ip.octets(),
            userid.as_bytes(),
        ]
        .concat();
        let reply = tokio::time::timeout(self.remaining(connected), async {
            tcp.write_all(&pkt)
                .await
                .map_err(|e| ("socks-rejected", e.to_string()))?;
            let mut buf = [0u8; 8];
            tcp.read_exact(&mut buf)
                .await
                .map_err(|e| ("socks-rejected", e.to_string()))?;
            Ok::<_, Fail>(buf)
        })
        .await
        .map_err(|_| ("socks-rejected", "socks4 timeout".to_string()))??;
        // VN must be 0: GRANT 90 / REJECT 91 / IDENTD 92 / CHAIN 93.
        if reply[0] != 0 {
            return Err(("socks-rejected", format!("socks4 reply VN={}", reply[0])));
        }
        match reply[1] {
            90 => {}
            92 => return Err(("auth-required", "socks4 identd refusal".into())),
            code => return Err(("socks-rejected", format!("socks4 reply code {code}"))),
        }
        self.tunneled_get(tcp, connected, plain_target, c.addr.ip(), slot)
            .await
    }

    /// Shared post-tunnel shape: plain targets do an absolute GET (proxy
    /// resolves the host); https targets add a verified TLS layer first.
    async fn tunneled_get<I>(
        &self,
        io: I,
        connected: Instant,
        plain_target: bool,
        proxy_ip: IpAddr,
        slot: &TargetSlot,
    ) -> Result<ProbeResult, Fail>
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if plain_target {
            let uri = format!("http://{}{}", slot.authority, slot.target.path);
            let req = self.request(&uri, Some(&slot.authority), None)?;
            return self.run_conn(io, req, connected, proxy_ip).await;
        }
        let tls = self
            .tls_wrap(&self.tls_verified, io, connected, &slot.target.host)
            .await?;
        let req = self.request(&slot.target.path, Some(&slot.authority), None)?;
        self.run_conn(tls, req, connected, proxy_ip)
            .await
            .map_err(bump_tls)
    }

    // ---- shared pieces ------------------------------------------------

    fn remaining(&self, connected: Instant) -> Duration {
        self.cfg.total_timeout.saturating_sub(connected.elapsed())
    }

    /// Build the check request. `origin_host` = Some ⇒ origin-form GET with
    /// that Host header; None ⇒ absolute-form (hyper serializes the URI
    /// verbatim). Credentials ⇒ Proxy-Authorization: Basic.
    fn request(
        &self,
        uri: &str,
        origin_host: Option<&str>,
        auth: Option<&Auth>,
    ) -> Result<http::Request<Empty<Bytes>>, Fail> {
        let mut b = http::Request::get(uri);
        if let Some(h) = origin_host {
            b = b.header(http::header::HOST, h);
        }
        b = b
            .header(http::header::ACCEPT, "*/*")
            .header(http::header::CONNECTION, "close");
        if let Some(a) = auth {
            let pass = a.password.clone().unwrap_or_default();
            let value = format!("Basic {}", b64(&format!("{}:{}", a.user, pass)));
            b = b.header(http::header::PROXY_AUTHORIZATION, value);
        }
        b.body(Empty::new())
            .map_err(|e| ("tcp-alive", e.to_string()))
    }

    async fn tls_wrap<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        &self,
        conf: &Arc<rustls::ClientConfig>,
        io: S,
        connected: Instant,
        sni_host: &str,
    ) -> Result<tokio_rustls::client::TlsStream<S>, Fail> {
        let server =
            ServerName::try_from(sni_host.to_string()).map_err(|e| ("tls-fail", e.to_string()))?;
        let remaining = self.remaining(connected);
        if remaining.is_zero() {
            return Err(("tcp-alive", "budget exhausted before TLS".into()));
        }
        tokio::time::timeout(
            remaining,
            tokio_rustls::TlsConnector::from(conf.clone()).connect(server, io),
        )
        .await
        .map_err(|_| ("tls-fail", "TLS timeout".to_string()))?
        .map_err(|e| ("tls-fail", e.to_string()))
    }

    async fn connect_phase<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        connected: Instant,
        authority: &str,
        auth: Option<&Auth>,
    ) -> Result<(), Fail> {
        let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
        if let Some(a) = auth {
            let pass = a.password.clone().unwrap_or_default();
            req.push_str(&format!(
                "Proxy-Authorization: Basic {}\r\n",
                b64(&format!("{}:{}", a.user, pass))
            ));
        }
        req.push_str("\r\n");
        let remaining = self.remaining(connected);
        if remaining.is_zero() {
            return Err(("tcp-alive", "budget exhausted before CONNECT".into()));
        }
        tokio::time::timeout(remaining, async {
            stream
                .write_all(req.as_bytes())
                .await
                .map_err(|e| ("tcp-alive", e.to_string()))?;
            // Bulk-read the reply head. The old one-byte loop burned one
            // syscall per byte: a 25-byte 200 was ~25 calls, a chatty 407
            // error page 200–4000 — all serial, before TLS even starts.
            // Bytes past the head boundary are intentionally dropped: a
            // compliant CONNECT relay stays silent until our next write
            // (TLS ClientHello), and on a 407 we never read the body.
            let mut buf: Vec<u8> = Vec::with_capacity(256);
            let mut chunk = [0u8; 128];
            let head_end = loop {
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos + 4;
                }
                if buf.len() >= 4096 {
                    return Err(("tcp-alive", "oversized CONNECT reply".into()));
                }
                let n = stream
                    .read(&mut chunk)
                    .await
                    .map_err(|e| ("tcp-alive", e.to_string()))?;
                if n == 0 {
                    return Err(("tcp-alive", "CONNECT closed".into()));
                }
                buf.extend_from_slice(&chunk[..n]);
            };
            buf.truncate(head_end);
            let code = parse_status_line(&buf)
                .ok_or(("tcp-alive", "CONNECT reply unparsable".to_string()))?;
            match code {
                200..=299 => Ok(()),
                407 => Err(("auth-required", "CONNECT 407".to_string())),
                c => Err(("tcp-alive", format!("CONNECT status {c}"))),
            }
        })
        .await
        .map_err(|_| ("tcp-alive", "CONNECT timeout".to_string()))?
    }

    /// Drive one hyper HTTP/1 connection, read the body, classify.
    async fn run_conn<I>(
        &self,
        io: I,
        req: http::Request<Empty<Bytes>>,
        connected: Instant,
        proxy_ip: IpAddr,
    ) -> Result<ProbeResult, Fail>
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let remaining = self.remaining(connected);
        if remaining.is_zero() {
            return Err(("tcp-alive", "budget exhausted".into()));
        }
        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .title_case_headers(false)
            .handshake(hyper_util::rt::TokioIo::new(io))
            .await
            .map_err(|e| ("tcp-alive", e.to_string()))?;
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        let outcome = tokio::time::timeout(remaining, async {
            let t0 = Instant::now();
            let resp = sender
                .send_request(req)
                .await
                .map_err(|e| ("tcp-alive", e.to_string()))?;
            let ttfb_ms = t0.elapsed().as_millis() as u32;
            let status = resp.status().as_u16();
            let body =
                tokio::time::timeout(Duration::from_millis(1500), resp.into_body().collect())
                    .await
                    .map_err(|_| ("tcp-alive", "body timeout".to_string()))?
                    .map_err(|e| ("tcp-alive", e.to_string()))?
                    .to_bytes();
            if body.len() > 64 * 1024 {
                return Err(("tcp-alive", "oversized response".into()));
            }
            Ok::<_, Fail>((status, body, ttfb_ms))
        })
        .await;
        drop(sender);
        driver.abort();
        let (status, body, ttfb_ms) =
            outcome.map_err(|_| ("tcp-alive", "check timeout".to_string()))??;

        let mut r = ProbeResult {
            proxy: String::new(),
            scheme: "",
            input: String::new(),
            status: "dead",
            anonymity: None,
            connect_ms: 0,
            ttfb_ms: Some(ttfb_ms),
            total_ms: 0,
            exit_ip: None,
            slot: -1,
            fail_reason: None,
        };
        match status {
            407 => return Err(("auth-required", "407 from proxy".to_string())),
            200..=299 => {}
            c => return Err(("tcp-alive", format!("target status {c}"))),
        }
        let text = String::from_utf8_lossy(&body).trim().to_string();
        let origin = extract_origin(&text);
        let chain_ips: Vec<IpAddr> = origin
            .as_deref()
            .map(|o| {
                o.split(',')
                    .filter_map(|p| p.trim().parse::<IpAddr>().ok())
                    .collect()
            })
            .unwrap_or_default();
        r.exit_ip = chain_ips.first().copied();
        if let Some(first) = r.exit_ip {
            r.status = "live";
            r.anonymity = Some(classify(&chain_ips, first, proxy_ip, self.own_egress));
        } else if !text.is_empty() {
            r.status = "live"; // target answered but reveals no IP: works, unjudged
        } else {
            return Err(("tcp-alive", "empty body".to_string()));
        }
        Ok(r)
    }

    /// Direct (no-proxy) fetch of a slot, validating BOTH reachability and
    /// body shape; the primary's parsed IP is our own egress (what makes
    /// `transparent` detectable).
    async fn check_shape(&self, slot: &TargetSlot) -> Shape {
        let Some(&ip) = slot.ips.first() else {
            return Shape::Unreachable;
        };
        let start = Instant::now();
        let tcp = match tokio::time::timeout(
            self.cfg.connect_timeout,
            TcpStream::connect((ip, slot.target.port)),
        )
        .await
        {
            Ok(Ok(t)) => t,
            _ => return Shape::Unreachable,
        };
        let _ = tcp.set_nodelay(true);
        let req = match self.request(&slot.target.path, Some(&slot.authority), None) {
            Ok(r) => r,
            Err(_) => return Shape::Unreachable,
        };
        let outcome = if slot.target.tls {
            match self
                .tls_wrap(&self.tls_verified, tcp, start, &slot.target.host)
                .await
            {
                Ok(t) => self.read_once(t, req).await,
                Err(_) => return Shape::Unreachable,
            }
        } else {
            self.read_once(tcp, req).await
        };
        let (_status, body) = match outcome {
            Ok(v) => v,
            Err(_) => return Shape::Unreachable,
        };
        let text = String::from_utf8_lossy(&body).trim().to_string();
        match extract_origin(&text) {
            Some(o) => match o
                .split(',')
                .next()
                .map(str::trim)
                .and_then(|s| s.parse::<IpAddr>().ok())
            {
                Some(ip) => Shape::Ok(ip),
                None => Shape::Wrong(format!("no address in: {o}")),
            },
            None if text.is_empty() => Shape::Unreachable,
            None => Shape::Wrong(format!("body starts {:?}", &text[..text.len().min(24)])),
        }
    }

    async fn read_once<I>(
        &self,
        io: I,
        req: http::Request<Empty<Bytes>>,
    ) -> Result<(u16, Bytes), Fail>
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(io))
                .await
                .map_err(|e| ("tcp-alive", e.to_string()))?;
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| ("tcp-alive", e.to_string()))?;
        let status = resp.status().as_u16();
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| ("tcp-alive", e.to_string()))?
            .to_bytes();
        drop(sender);
        driver.abort();
        Ok((status, body))
    }
}

async fn resolve(t: &CheckTarget) -> Result<Vec<IpAddr>, String> {
    let addrs = tokio::net::lookup_host((t.host.as_str(), t.port))
        .await
        .map_err(|e| format!("resolve {}: {e}", t.host))?;
    let mut ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
    ips.sort_by_key(|a| if a.is_ipv4() { 0 } else { 1 });
    ips.dedup();
    if ips.is_empty() {
        return Err(format!("{} has no addresses", t.host));
    }
    Ok(ips)
}

fn authority_of(t: &CheckTarget) -> String {
    if t.port == 80 || t.port == 443 {
        t.host.clone()
    } else {
        format!("{}:{}", t.host, t.port)
    }
}

/// Whole-body IP ("1.2.3.4") or JSON shapes: {"origin": "1.2.3.4[, x]"} or
/// {"ip": "1.2.3.4"} — tolerant to echo content-negotiation defaults.
fn extract_origin(text: &str) -> Option<String> {
    let text = text.trim();
    if text.parse::<IpAddr>().is_ok() {
        return Some(text.to_string());
    }
    let json_start = text.find('{')?;
    let val: Value = serde_json::from_str(&text[json_start..]).ok()?;
    let o = val
        .get("origin")
        .or_else(|| val.get("ip"))
        .and_then(Value::as_str)?
        .trim()
        .to_string();
    if o.is_empty() { None } else { Some(o) }
}

/// Output identity: user:pass@ip:port when the entry carried credentials.
fn proxy_label(c: &Candidate) -> String {
    match &c.auth {
        Some(a) => format!("{a}@{}", c.addr),
        None => c.addr.to_string(),
    }
}

/// Startup echo health: reachable + parseable body, reachable + wrong
/// shape, or unreachable.
enum Shape {
    Ok(IpAddr),
    Wrong(String),
    Unreachable,
}

/// Round-robin pick; SOCKS4 candidates may only use slots whose resolved
/// addresses include an IPv4 (socks4 has no proxy-side DNS). Returns None
/// only when needs_v4 and no slot can serve v4.
fn pick_slot(slots: &[TargetSlot], rr: usize, needs_v4: bool) -> Option<usize> {
    if slots.is_empty() {
        return None;
    }
    if needs_v4 {
        let ok: Vec<usize> = (0..slots.len())
            .filter(|&i| slots[i].ips.iter().any(|a| a.is_ipv4()))
            .collect();
        if ok.is_empty() {
            return None;
        }
        return Some(ok[rr % ok.len()]);
    }
    Some(rr % slots.len())
}

fn bump_tls(f: Fail) -> Fail {
    if f.0 == "tcp-alive" {
        ("tls-fail", f.1)
    } else {
        f
    }
}

/// elite: exit IP equals the proxy itself | anonymous: a single unrelated NAT
/// address | transparent: our own egress leaked into the chain (or multi-hop)
fn classify(chain: &[IpAddr], exit: IpAddr, proxy_ip: IpAddr, own: Option<IpAddr>) -> &'static str {
    if let Some(own) = own
        && chain.contains(&own)
    {
        return "transparent";
    }
    if chain.len() == 1 {
        return if exit == proxy_ip {
            "elite"
        } else {
            "anonymous"
        };
    }
    "transparent"
}

fn parse_status_line(buf: &[u8]) -> Option<u16> {
    let line = buf.split(|&b| b == b'\n').next()?;
    let mut parts = line.split(|&b| b == b' ');
    parts.next()?; // version token
    let digits: Vec<u8> = parts
        .next()?
        .iter()
        .copied()
        .take_while(u8::is_ascii_digit)
        .collect();
    std::str::from_utf8(&digits).ok()?.parse().ok()
}

fn socks_error_status(display: &str) -> &'static str {
    let d = display.to_ascii_lowercase();
    if d.contains("auth") {
        "auth-required"
    } else if d.contains("unreachable")
        || d.contains("denied")
        || d.contains("expired")
        || d.contains("not supported")
    {
        "socks-rejected"
    } else if d.contains("malformed") || d.contains("version") {
        "tcp-alive"
    } else {
        "dead"
    }
}

/// Minimal standard-base64 encoder (Proxy-Authorization only; no dep).
fn b64(input: &str) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(4) * 4);
    for chunk in input.as_bytes().chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// rustls config: verified = webpki roots (tunnel to the target — the proxy
/// cannot fake the answer); unverified = TLS-terminating proxies whose
/// endpoints are routinely self-signed.
fn tls_config(verify: bool) -> Result<rustls::ClientConfig, String> {
    use rustls::SignatureScheme;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, UnixTime};

    #[derive(Debug)]
    struct AcceptAll;
    impl ServerCertVerifier for AcceptAll {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _m: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _m: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            use rustls::SignatureScheme::*;
            vec![
                RSA_PKCS1_SHA256,
                RSA_PKCS1_SHA384,
                RSA_PKCS1_SHA512,
                ECDSA_NISTP256_SHA256,
                ECDSA_NISTP384_SHA384,
                ED25519,
                RSA_PSS_SHA256,
                RSA_PSS_SHA384,
                RSA_PSS_SHA512,
            ]
        }
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .map_err(|e| e.to_string())?;
    let mut cfg = if verify {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAll))
            .with_no_client_auth()
    };
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn classify_uses_proxy_ip() {
        let own = ip("1.1.1.1");
        let proxy = ip("2.2.2.2");
        assert_eq!(classify(&[proxy], proxy, proxy, Some(own)), "elite");
        assert_eq!(
            classify(&[ip("3.3.3.3")], ip("3.3.3.3"), proxy, Some(own)),
            "anonymous"
        );
        assert_eq!(
            classify(&[own, proxy], proxy, proxy, Some(own)),
            "transparent"
        );
    }

    #[test]
    fn origins_all_body_shapes() {
        assert_eq!(extract_origin("9.9.9.9\n").as_deref(), Some("9.9.9.9"));
        assert_eq!(
            extract_origin("{\"origin\": \"9.9.9.9, x\"}").as_deref(),
            Some("9.9.9.9, x")
        );
        assert_eq!(
            extract_origin("{\"ip\":\"9.9.9.9\"}").as_deref(),
            Some("9.9.9.9")
        ); // ipify JSON form
        assert_eq!(extract_origin("garbage"), None);
    }

    #[test]
    fn socks4_only_picks_v4_capable_slots() {
        fn slot(host: &str, ips: Vec<IpAddr>) -> TargetSlot {
            TargetSlot {
                target: CheckTarget {
                    tls: false,
                    host: host.into(),
                    port: 80,
                    path: "/".into(),
                    url: format!("http://{host}/"),
                },
                ips,
                authority: host.into(),
                sem: Arc::new(Semaphore::new(1)),
            }
        }
        let v4 = IpAddr::from([1, 2, 3, 4]);
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        let slots = vec![slot("v6only", vec![v6]), slot("dual", vec![v4, v6])];
        for rr in 0..8 {
            assert_eq!(
                pick_slot(&slots, rr, true),
                Some(1),
                "socks4 must skip the v6-only slot"
            );
        }
        let mut seen = [false; 2];
        for rr in 0..8 {
            seen[pick_slot(&slots, rr, false).unwrap()] = true;
        }
        assert!(seen[0] && seen[1]);
        assert_eq!(pick_slot(&[slot("v6only", vec![v6])], 0, true), None);
    }

    #[test]
    fn authority_omits_default_ports() {
        let t = CheckTarget {
            tls: true,
            host: "h.example".into(),
            port: 443,
            path: "/".into(),
            url: "https://h.example/".into(),
        };
        assert_eq!(authority_of(&t), "h.example");
        let t2 = CheckTarget { port: 8443, ..t };
        assert_eq!(authority_of(&t2), "h.example:8443");
    }

    #[test]
    fn status_and_socks_buckets() {
        assert_eq!(parse_status_line(b"HTTP/1.1 407 Proxy Auth\r\n"), Some(407));
        assert_eq!(
            socks_error_status("AuthenticationRequiredNeeded"),
            "auth-required"
        );
        assert_eq!(socks_error_status("host unreachable"), "socks-rejected");
    }

    #[test]
    fn base64_matches_std() {
        assert_eq!(b64("bob:s3cret-9"), "Ym9iOnMzY3JldC05");
        assert_eq!(b64("ab"), "YWI=");
        assert_eq!(b64("abc"), "YWJj");
    }
}
