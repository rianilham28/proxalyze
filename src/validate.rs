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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt;
use rustls::pki_types::ServerName;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;

use crate::config::{CheckTarget, Validate};
use crate::model::{Auth, Candidate, ProbeResult, Scheme};

const MAX_BODY: usize = 64 * 1024;
const OVERSIZED_RESPONSE: &str = "oversized response";

/// Throughput sample cap. Separate from MAX_BODY on purpose: the echo body
/// is just an IP, while a speed sample wants as much as the budget allows.
/// Reaching the cap is success, not an error.
const THROUGHPUT_MAX: usize = 256 * 1024;

/// Speed tier from a measured kbps figure. Boundaries are exact.
pub fn speed_tier_of(kbps: u32) -> &'static str {
    match kbps {
        2048.. => "fast",
        512.. => "mid",
        _ => "slow",
    }
}

/// The throughput sample target, resolved once (DNS is not a per-check cost).
pub struct ResolvedTarget {
    pub check: CheckTarget,
    /// resolved addresses, IPv4 first (SOCKS4 needs a v4 literal)
    pub ips: Vec<IpAddr>,
    pub authority: String,
}

/// What a capability follow-up needs to replay the primary request on the
/// same connection. Borrowed from the flow that opened it, so the follow-up
/// cannot drift from the request it is measuring support for.
pub struct ConnExtras<'a> {
    /// exactly the URI the primary request used
    pub target_url: &'a str,
    pub origin_host: Option<&'a str>,
    pub auth: Option<&'a Auth>,
}

/// The body of any request this lane sends. `Empty` has an exact zero
/// length so a plain GET is byte-identical to today's `Empty<Bytes>` wire
/// shape; `Chunked` deliberately has an unknown length, which is what makes
/// hyper emit `Transfer-Encoding: chunked` on http1.
enum ProbeBody {
    Empty,
    /// `None` once the single frame has been handed over: the second poll
    /// must report end-of-stream, not an empty frame forever.
    Chunked(Option<&'static [u8]>),
}

impl hyper::body::Body for ProbeBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            ProbeBody::Empty => std::task::Poll::Ready(None),
            ProbeBody::Chunked(chunk) => match chunk.take() {
                Some(bytes) => std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(
                    Bytes::from_static(bytes),
                )))),
                None => std::task::Poll::Ready(None),
            },
        }
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        match self {
            ProbeBody::Empty => hyper::body::SizeHint::with_exact(0),
            ProbeBody::Chunked(_) => hyper::body::SizeHint::default(),
        }
    }
}

/// A dialed proxy connection in whatever layering the scheme ended up with,
/// erased to one type so the throughput pass can build all six shapes.
type BoxedIo = Box<dyn Duplex>;

/// The read/write surface a tunneled transport exposes; naming it lets every
/// layering branch box into the same `BoxedIo`.
trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

/// Saturating whole-millisecond elapsed — the shape every ms field uses.
fn ms_since(t0: Instant) -> u32 {
    u32::try_from(t0.elapsed().as_millis()).unwrap_or(u32::MAX)
}

/// One body type for the whole lane: the primary GET and both capability
/// follow-ups then share a single `SendRequest`, i.e. one connection.
type BoxedBody = http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>;

/// Payload of the chunked-POST capability probe.
const CHUNKED_POST_BODY: &[u8] = b"proxalyze-capability-probe";

/// stderr write that never panics when the display pipe is closed.
macro_rules! qeprintln {
    ($($a:tt)*) => {{
        use std::io::Write;
        let _ = writeln!(std::io::stderr(), $($a)*);
    }};
}

#[derive(Clone)]
pub struct CheckCfg {
    pub concurrency: usize,
    pub connect_timeout: Duration,
    pub total_timeout: Duration,
    pub debug: bool,
    pub probe_capabilities: bool,
    pub probe_throughput: bool,
    /// Parsed sample target; `None` when no --throughput-url was given.
    pub throughput: Option<CheckTarget>,
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
        let tp = v.throughput_url.trim();
        Ok(Self {
            concurrency: want.min(cap).max(1),
            connect_timeout: Duration::from_secs_f64(v.connect_timeout),
            total_timeout: Duration::from_secs_f64(v.timeout),
            debug,
            probe_capabilities: v.probe_capabilities,
            probe_throughput: v.probe_throughput,
            throughput: if tp.is_empty() {
                None
            } else {
                Some(crate::config::parse_target(tp)?)
            },
        })
    }
}

/// One echo endpoint with its own in-flight budget.
pub struct TargetSlot {
    pub target: CheckTarget,
    /// resolved addresses, IPv4 first (SOCKS4 needs a v4 literal)
    pub ips: Vec<IpAddr>,
    pub authority: String,
    pub cap: usize,
    sem: Arc<Semaphore>,
    errors: Arc<AtomicU64>,
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
    throughput: Option<ResolvedTarget>,
}

/// Progress redraw on stderr. Returns false once the sink is gone
/// (`| head`, `| grep -m1`): the caller stops redrawing but the run
/// finishes and still writes its report files — closing a pipe kills the
/// display, never the work. (Before this guard an `eprint!` panic on EPIPE
/// aborted minutes-long runs outright; process::exit on error was also wrong
/// for the same reason.)
fn progress(msg: &str) -> bool {
    use std::io::Write;
    let stderr = std::io::stderr();
    let mut h = stderr.lock();
    h.write_all(msg.as_bytes()).and_then(|()| h.flush()).is_ok()
}

impl Validator {
    /// targets[0] is the primary; unresolvable backups are dropped with a
    /// warning, an unresolvable primary is fatal.
    pub async fn new(cfg: CheckCfg, targets: Vec<CheckTarget>) -> Result<Self, String> {
        if targets.is_empty() {
            return Err("no check targets configured".into());
        }
        let tls_verify_off = Arc::new(tls_config(false)?);
        let tls_verified = Arc::new(tls_config(true)?);
        // An explicitly requested throughput URL must resolve: a typo'd
        // --throughput-url would otherwise silently zero every kbps.
        let throughput = match cfg.throughput.clone() {
            None => None,
            Some(check) => {
                let ips = resolve(&check).await?;
                let authority = authority_of(&check);
                Some(ResolvedTarget {
                    check,
                    ips,
                    authority,
                })
            }
        };
        let mut me = Self {
            cfg,
            slots: Vec::new(),
            rr: AtomicUsize::new(0),
            own_egress: None,
            tls_verify_off,
            tls_verified,
            done: Arc::new(AtomicUsize::new(0)),
            throughput,
        };

        // Resolve every target first, preserving primary-fatal and
        // backup-drop behavior. Shape checks do not need slot permits.
        let mut resolved = Vec::new();
        for (i, target) in targets.into_iter().enumerate() {
            match resolve(&target).await {
                Ok(ips) => resolved.push((target, ips)),
                Err(e) if i == 0 => return Err(e),
                Err(e) => qeprintln!("[validate] backup target {} dropped: {e}", target.url),
            }
        }

        // Health-check each echo's BODY SHAPE at startup: an echo that
        // answers but whose body we cannot read as an IP would silently
        // null out exit_ip/anonymity for every proxy assigned to it — a
        // wrong verdict, so drop it loudly instead.
        let mut healthy = Vec::new();
        for (i, (target, ips)) in resolved.into_iter().enumerate() {
            let url = target.url.clone();
            let shape = me.check_shape(&target, &ips, &authority_of(&target)).await;
            match shape {
                Shape::Ok(ip) => {
                    if i == 0 {
                        me.own_egress = Some(ip);
                    }
                    healthy.push((target, ips));
                }
                Shape::Unreachable if i == 0 => {
                    qeprintln!(
                        "[validate] primary {url} unreachable now; transparent-detection degraded, liveness still runs"
                    );
                    healthy.push((target, ips));
                }
                Shape::Unreachable => {
                    qeprintln!("[validate] backup {url} unreachable at startup, dropped");
                }
                Shape::Wrong(detail) if i == 0 => {
                    return Err(format!(
                        "primary check_url {url} body is not an exit IP: {detail}"
                    ));
                }
                Shape::Wrong(detail) => {
                    qeprintln!("[validate] backup {url} wrong body shape ({detail}), dropped");
                }
            }
        }

        // Allocate permits only after startup drops, so -j 4 stays -j 4.
        let slot_cap = slot_cap(me.cfg.concurrency, healthy.len());
        me.slots = healthy
            .into_iter()
            .map(|(target, ips)| {
                let authority = authority_of(&target);
                TargetSlot {
                    target,
                    ips,
                    authority,
                    cap: slot_cap,
                    sem: Arc::new(Semaphore::new(slot_cap)),
                    errors: Arc::new(AtomicU64::new(0)),
                }
            })
            .collect();
        if me.slots.first().is_some_and(|slot| !slot.target.tls) {
            qeprintln!(
                "[validate] WARNING: --check-url is http:// — a lying proxy can forge the exit-IP body; https targets are certificate-verified"
            );
        }
        Ok(me)
    }

    /// echo endpoints still active after startup shape verification, in slot order
    pub fn active_targets(&self) -> Vec<String> {
        self.slots.iter().map(|s| s.target.url.clone()).collect()
    }

    pub fn slot_caps(&self) -> Vec<usize> {
        self.slots.iter().map(|slot| slot.cap).collect()
    }

    pub fn slot_errors(&self) -> Vec<u64> {
        self.slots
            .iter()
            .map(|slot| slot.errors.load(Ordering::Relaxed))
            .collect()
    }

    pub async fn run(self: &Arc<Self>, candidates: Vec<Candidate>, tx: mpsc::Sender<ProbeResult>) {
        let total = candidates.len();
        let done = self.done.clone();
        let progress = tokio::spawn(async move {
            use std::io::IsTerminal;
            let tty = std::io::stderr().is_terminal();
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
                let eta_s = if d >= 512 {
                    format!("eta {eta:>4.0}s")
                } else {
                    "eta   ---".into()
                }; // first batches all land at the connect-timeout mark:
                // eta computed off them thrashes 2600s->700s and reads broken
                if !tty {
                    continue;
                }
                if !progress(&format!(
                    "\r[check ] {d:>7}/{total:<7} {:>3}%  {rate:>5.0}/s  {eta_s} ",
                    d * 100 / total
                )) {
                    break; // display gone; finish the run silently
                }
            }
            let final_line = if tty {
                format!(
                    "\r[check ] {total:>7}/{total:<7} 100%  {:>5.1}/s  done in {:>5.1}s",
                    total as f64 / t0.elapsed().as_secs_f64().max(0.001),
                    t0.elapsed().as_secs_f64()
                )
            } else {
                format!(
                    "[check ] {total:>7}/{total:<7} 100%  {:>5.1}/s  done in {:>5.1}s",
                    total as f64 / t0.elapsed().as_secs_f64().max(0.001),
                    t0.elapsed().as_secs_f64()
                )
            };
            progress(&format!("{final_line}\n"));
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
                r.input_row = c.input_row.unwrap_or(usize::MAX);
                if let Some((_, reason)) = fail {
                    if me.cfg.debug {
                        qeprintln!("\n[{}] {} {reason}", r.status, r.proxy);
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
        let granted = Instant::now();
        let plain_target = !slot.target.tls;
        let out = match (c.scheme, slot.target.tls) {
            (Scheme::Http, false) => self.forward_get(tcp, connected, c, slot).await,
            (Scheme::Https, false) => self.tls_proxy_get(tcp, connected, c, slot).await,
            (Scheme::Http, true) => self.connect_tls_get(tcp, connected, c, slot).await,
            (Scheme::Https, true) => self.tls_connect_tls_get(tcp, connected, c, slot).await,
            (Scheme::Socks5, _) => self.socks5_get(tcp, connected, plain_target, c, slot).await,
            (Scheme::Socks4, _) => self.socks4_get(tcp, connected, plain_target, c, slot).await,
        };
        match out {
            Ok(mut r) => {
                r.proxy = proxy_label(c);
                r.scheme = c.scheme.as_str();
                r.slot = slot_idx as i16;
                r.connect_ms = connected.duration_since(start).as_millis() as u32;
                // speed_ms = dial + request; echo-permit queue wait is not
                // proxy slowness, and capability follow-ups are decoration —
                // subtracted so a flag-on pool sorts like a flag-off one.
                r.total_ms = r
                    .connect_ms
                    .saturating_add(ms_since(granted).saturating_sub(r.decor_ms));
                // Throughput rides the SAME permit as the echo exchange
                // (advisory: extra probes are charged against one slot
                // budget) and only runs once the verdict is settled: a
                // failed sample leaves a live proxy live, without a tier.
                if r.status == "live" && self.cfg.probe_throughput && self.throughput.is_some() {
                    r.kbps = self.throughput_probe(c).await;
                    r.speed_tier = r.kbps.map(speed_tier_of);
                }
                drop(permit);
                (r, None)
            }
            Err(fail) => {
                let mut r = self.blank(c, fail.0, start, connected, slot_idx as i16);
                r.proxy = proxy_label(c);
                if fail.1.starts_with("target status") || fail.1 == OVERSIZED_RESPONSE {
                    slot.errors.fetch_add(1, Ordering::Relaxed);
                }
                r.connect_ms = connected.duration_since(start).as_millis() as u32;
                // speed_ms = dial + request; echo-permit queue wait is not proxy slowness
                r.total_ms = r
                    .connect_ms
                    .saturating_add(granted.elapsed().as_millis() as u32);
                drop(permit);
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
            input_row: c.input_row.unwrap_or(usize::MAX),
            status,
            anonymity: None,
            connect_ms: connected.duration_since(start).as_millis() as u32,
            ttfb_ms: None,
            total_ms: start.elapsed().as_millis() as u32,
            exit_ip: None,
            slot,
            fail_reason: None,
            kbps: None,
            speed_tier: None,
            caps: Vec::new(),
            decor_ms: 0,
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
        let extras = self.extras(&slot.target.url, None, c.auth.as_ref());
        self.run_conn(tcp, req, connected, c.addr.ip(), extras.as_ref())
            .await
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
        let extras = self.extras(&slot.target.url, None, c.auth.as_ref());
        self.run_conn(tls, req, connected, c.addr.ip(), extras.as_ref())
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
        let extras = self.extras(&slot.target.path, Some(&slot.authority), c.auth.as_ref());
        self.run_conn(tls, req, connected, c.addr.ip(), extras.as_ref())
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
        let extras = self.extras(&slot.target.path, Some(&slot.authority), c.auth.as_ref());
        self.run_conn(inner, req, connected, c.addr.ip(), extras.as_ref())
            .await
            .map_err(bump_tls)
    }

    /// socks5 domain-form handshake only (proxy-side DNS; username/password
    /// sub-negotiation when the entry carried credentials). Shared with the
    /// throughput pass, which needs the same tunnel over a fresh dial.
    async fn socks5_handshake(
        &self,
        tcp: TcpStream,
        c: &Candidate,
        host: &str,
        port: u16,
        connected: Instant,
    ) -> Result<TcpStream, Fail> {
        let target = (host, port);
        let handshake = async {
            match &c.auth {
                Some(a) if !a.user.is_empty() => match &a.password {
                    Some(p) => {
                        tokio_socks::tcp::Socks5Stream::connect_with_password_and_socket(
                            tcp, target, &a.user, p,
                        )
                        .await
                    }
                    None => {
                        tokio_socks::tcp::Socks5Stream::connect_with_password_and_socket(
                            tcp, target, &a.user, "",
                        )
                        .await
                    }
                },
                _ => tokio_socks::tcp::Socks5Stream::connect_with_socket(tcp, target).await,
            }
        };
        let tunnel = tokio::time::timeout(self.remaining(connected), handshake)
            .await
            .map_err(|_| ("dead", "socks5 timeout".to_string()))?
            .map_err(|e| (socks_error_status(&format!("{e:?}")), format!("{e:?}")))?;
        Ok(tunnel.into_inner())
    }

    /// socks5: handshake, then the shared post-tunnel shape.
    async fn socks5_get(
        &self,
        tcp: TcpStream,
        connected: Instant,
        plain_target: bool,
        c: &Candidate,
        slot: &TargetSlot,
    ) -> Result<ProbeResult, Fail> {
        let inner = self
            .socks5_handshake(tcp, c, &slot.target.host, slot.target.port, connected)
            .await?;
        self.tunneled_get(inner, connected, plain_target, c.addr.ip(), slot)
            .await
    }

    /// socks4 handshake only: v4-literal CONNECT (no proxy-side DNS).
    async fn socks4_handshake(
        &self,
        mut tcp: TcpStream,
        c: &Candidate,
        ip: std::net::Ipv4Addr,
        port: u16,
        connected: Instant,
    ) -> Result<TcpStream, Fail> {
        let userid = match &c.auth {
            Some(a) => format!("{}\0", a.user),
            None => "proxalyze\0".to_string(),
        };
        let pkt: Vec<u8> = [
            &[0x04u8, 0x01u8][..],
            &port.to_be_bytes(),
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
        interpret_socks4_reply(reply)?;
        Ok(tcp)
    }

    /// socks4: v4-literal handshake (no proxy-side DNS), optional TLS, GET.
    async fn socks4_get(
        &self,
        tcp: TcpStream,
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
        let inner = self
            .socks4_handshake(tcp, c, ip, slot.target.port, connected)
            .await?;
        self.tunneled_get(inner, connected, plain_target, c.addr.ip(), slot)
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
            // SOCKS credentials rode the handshake, so the follow-ups must
            // not repeat them as Proxy-Authorization.
            let extras = self.extras(&uri, Some(&slot.authority), None);
            return self
                .run_conn(io, req, connected, proxy_ip, extras.as_ref())
                .await;
        }
        let tls = self
            .tls_wrap(&self.tls_verified, io, connected, &slot.target.host)
            .await?;
        let req = self.request(&slot.target.path, Some(&slot.authority), None)?;
        let extras = self.extras(&slot.target.path, Some(&slot.authority), None);
        self.run_conn(tls, req, connected, proxy_ip, extras.as_ref())
            .await
            .map_err(bump_tls)
    }

    /// Capability follow-up context for a flow, or `None` when the probe is
    /// off — which is what keeps the default run's wire shape untouched.
    fn extras<'a>(
        &self,
        target_url: &'a str,
        origin_host: Option<&'a str>,
        auth: Option<&'a Auth>,
    ) -> Option<ConnExtras<'a>> {
        if !self.cfg.probe_capabilities {
            return None;
        }
        Some(ConnExtras {
            target_url,
            origin_host,
            auth,
        })
    }

    // ---- shared pieces ------------------------------------------------

    fn remaining(&self, connected: Instant) -> Duration {
        self.cfg.total_timeout.saturating_sub(connected.elapsed())
    }

    /// Shared header assembly for both request builders, so the primary GET
    /// and the chunked POST cannot drift. `keep_alive` = omit
    /// `Connection: close` (HTTP/1.1 then keeps the socket open, which the
    /// capability follow-ups need); the default run keeps the header exactly
    /// as it always was.
    fn request_builder(
        &self,
        method: http::Method,
        uri: &str,
        origin_host: Option<&str>,
        auth: Option<&Auth>,
        keep_alive: bool,
    ) -> http::request::Builder {
        let mut b = http::Request::builder().method(method).uri(uri);
        if let Some(h) = origin_host {
            b = b.header(http::header::HOST, h);
        }
        b = b
            .header(http::header::ACCEPT, "*/*")
            .header(http::header::USER_AGENT, user_agent());
        if !keep_alive {
            b = b.header(http::header::CONNECTION, "close");
        }
        if let Some(a) = auth {
            let pass = a.password.clone().unwrap_or_default();
            let value = format!("Basic {}", b64(&format!("{}:{}", a.user, pass)));
            b = b.header(http::header::PROXY_AUTHORIZATION, value);
        }
        b
    }

    /// Build the check request. `origin_host` = Some ⇒ origin-form GET with
    /// that Host header; None ⇒ absolute-form (hyper serializes the URI
    /// verbatim). Credentials ⇒ Proxy-Authorization: Basic.
    fn request(
        &self,
        uri: &str,
        origin_host: Option<&str>,
        auth: Option<&Auth>,
    ) -> Result<http::Request<BoxedBody>, Fail> {
        self.request_keep_alive(uri, origin_host, auth, self.cfg.probe_capabilities)
    }

    fn request_keep_alive(
        &self,
        uri: &str,
        origin_host: Option<&str>,
        auth: Option<&Auth>,
        keep_alive: bool,
    ) -> Result<http::Request<BoxedBody>, Fail> {
        self.request_builder(http::Method::GET, uri, origin_host, auth, keep_alive)
            .body(ProbeBody::Empty)
            .map(|req| req.map(http_body_util::combinators::BoxBody::new))
            .map_err(|e| ("tcp-alive", e.to_string()))
    }

    /// POST with a length-less body ⇒ `Transfer-Encoding: chunked` on the wire.
    fn request_chunked_post(
        &self,
        uri: &str,
        origin_host: Option<&str>,
        auth: Option<&Auth>,
    ) -> Result<http::Request<BoxedBody>, Fail> {
        self.request_builder(http::Method::POST, uri, origin_host, auth, true)
            .header(http::header::CONTENT_TYPE, "application/octet-stream")
            .body(ProbeBody::Chunked(Some(CHUNKED_POST_BODY)))
            .map(|req| req.map(http_body_util::combinators::BoxBody::new))
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

    /// Drive one hyper HTTP/1 connection, read the body, classify, and — when
    /// `extras` is present — probe the connection's protocol capabilities
    /// before it closes. Capability outcomes are decoration only: they can
    /// add or omit `caps` entries, never change the verdict.
    async fn run_conn<I>(
        &self,
        io: I,
        req: http::Request<BoxedBody>,
        connected: Instant,
        proxy_ip: IpAddr,
        extras: Option<&ConnExtras<'_>>,
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
            let body = tokio::time::timeout(Duration::from_millis(1500), async {
                let mut body = resp.into_body();
                let mut buf = BytesMut::new();
                while let Some(item) = body.frame().await {
                    let frame = item.map_err(|e| ("tcp-alive", e.to_string()))?;
                    if let Ok(data) = frame.into_data() {
                        if buf.len() + data.len() > MAX_BODY {
                            return Err::<_, Fail>(("tcp-alive", "oversized response".into()));
                        }
                        buf.extend_from_slice(&data);
                    }
                }
                Ok::<_, Fail>(buf.freeze())
            })
            .await
            .map_err(|_| ("tcp-alive", "body timeout".into()))??;
            Ok::<_, Fail>((status, body, ttfb_ms))
        })
        .await;
        // A live connection is the only place keep-alive / chunked-POST can
        // be observed, so the follow-ups ride it — while `sender` and the
        // connection driver are still alive. Their cost is decoration: it is
        // subtracted from total_ms, and a failure only omits caps entries.
        let mut caps: Vec<&'static str> = Vec::new();
        let mut decor_ms = 0u32;
        if let Some(x) = extras
            && outcome
                .as_ref()
                .is_ok_and(|o| matches!(o, Ok((200..=299, _, _))))
        {
            let probed = tokio::time::timeout(
                self.remaining(connected),
                self.capability_probes(&mut sender, x),
            )
            .await
            .unwrap_or_else(|_| {
                if self.cfg.debug {
                    qeprintln!("[capability] follow-up budget exhausted");
                }
                (Vec::new(), 0)
            });
            caps = probed.0;
            decor_ms = probed.1;
        }
        drop(sender);
        driver.abort();
        let (status, body, ttfb_ms) =
            outcome.map_err(|_| ("tcp-alive", "check timeout".to_string()))??;

        let mut r = ProbeResult {
            proxy: String::new(),
            scheme: "",
            input: String::new(),
            input_row: usize::MAX,
            status: "dead",
            anonymity: None,
            connect_ms: 0,
            ttfb_ms: Some(ttfb_ms),
            total_ms: 0,
            exit_ip: None,
            slot: -1,
            fail_reason: None,
            kbps: None,
            speed_tier: None,
            caps,
            decor_ms,
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
    async fn check_shape(&self, target: &CheckTarget, ips: &[IpAddr], authority: &str) -> Shape {
        let Some(&ip) = ips.first() else {
            return Shape::Unreachable;
        };
        let start = Instant::now();
        let tcp = match tokio::time::timeout(
            self.cfg.connect_timeout,
            TcpStream::connect((ip, target.port)),
        )
        .await
        {
            Ok(Ok(t)) => t,
            _ => return Shape::Unreachable,
        };
        let _ = tcp.set_nodelay(true);
        let req = match self.request(&target.path, Some(authority), None) {
            Ok(r) => r,
            Err(_) => return Shape::Unreachable,
        };
        let budget = self.remaining(start);
        let outcome = if target.tls {
            match self
                .tls_wrap(&self.tls_verified, tcp, start, &target.host)
                .await
            {
                Ok(t) => self.read_once(t, req, budget).await,
                Err(_) => return Shape::Unreachable,
            }
        } else {
            self.read_once(tcp, req, budget).await
        };
        let (_status, body) = match outcome {
            Ok(v) => v,
            Err(fail) => return shape_from_read_error(fail),
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
            None => Shape::Wrong(format!("body starts {:?}", body_preview(&text))),
        }
    }

    async fn read_once<I>(
        &self,
        io: I,
        req: http::Request<BoxedBody>,
        budget: Duration,
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
        let outcome = tokio::time::timeout(budget, async {
            let resp = sender
                .send_request(req)
                .await
                .map_err(|e| ("tcp-alive", e.to_string()))?;
            let status = resp.status().as_u16();
            let mut body = resp.into_body();
            let mut buf = BytesMut::new();
            while let Some(item) = body.frame().await {
                let frame = item.map_err(|e| ("tcp-alive", e.to_string()))?;
                if let Ok(data) = frame.into_data() {
                    if buf.len() + data.len() > MAX_BODY {
                        return Err::<_, Fail>(("tcp-alive", OVERSIZED_RESPONSE.into()));
                    }
                    buf.extend_from_slice(&data);
                }
            }
            Ok((status, buf.freeze()))
        })
        .await;
        drop(sender);
        driver.abort();
        outcome.map_err(|_| ("tcp-alive", "shape-check timeout".into()))?
    }

    /// Two follow-ups on an already-open connection: a plain second GET
    /// (any response ⇒ keep-alive worked) and a chunked POST (a status that
    /// is not 400/411/501 ⇒ the origin accepted a chunked body). Every error
    /// is swallowed: the caller decorates `caps`, never the verdict.
    /// Returns the tag list plus the summed elapsed wall time.
    async fn capability_probes(
        &self,
        sender: &mut hyper::client::conn::http1::SendRequest<BoxedBody>,
        x: &ConnExtras<'_>,
    ) -> (Vec<&'static str>, u32) {
        let mut caps = Vec::new();
        let mut decor_ms = 0u32;

        let t0 = Instant::now();
        let keep_alive: Result<u16, String> =
            match self.request_keep_alive(x.target_url, x.origin_host, x.auth, true) {
                Ok(req) => match sender.send_request(req).await {
                    // Drain before the next request: hyper will not write it
                    // while this response is unread.
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let _ = resp.into_body().collect().await;
                        Ok(status)
                    }
                    Err(e) => Err(e.to_string()),
                },
                Err((_, e)) => Err(e),
            };
        decor_ms = decor_ms.saturating_add(ms_since(t0));
        match keep_alive {
            Ok(status) => {
                if self.cfg.debug {
                    qeprintln!("[capability] keep-alive probe answered {status}");
                }
                caps.push("keep-alive");
            }
            Err(e) => {
                if self.cfg.debug {
                    qeprintln!("[capability] keep-alive probe failed: {e}");
                }
            }
        }

        let t0 = Instant::now();
        let chunked: Result<u16, String> =
            match self.request_chunked_post(x.target_url, x.origin_host, x.auth) {
                Ok(req) => match sender.send_request(req).await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let _ = resp.into_body().collect().await;
                        Ok(status)
                    }
                    Err(e) => Err(e.to_string()),
                },
                Err((_, e)) => Err(e),
            };
        decor_ms = decor_ms.saturating_add(ms_since(t0));
        match chunked {
            Ok(status) if !matches!(status, 400 | 411 | 501) => {
                if self.cfg.debug {
                    qeprintln!("[capability] chunked POST answered {status}");
                }
                caps.push("chunked-post");
            }
            Ok(status) => {
                if self.cfg.debug {
                    qeprintln!("[capability] chunked POST refused with {status}");
                }
            }
            Err(e) => {
                if self.cfg.debug {
                    qeprintln!("[capability] chunked POST failed: {e}");
                }
            }
        }
        (caps, decor_ms)
    }

    /// Time a download through an open tunneled connection. Reads body
    /// frames until the response ends or the sample cap is reached — hitting
    /// the cap is the normal success path, not an error, and a body that
    /// ends early still yields the bytes it delivered.
    async fn timed_download<I>(
        &self,
        io: I,
        req: http::Request<BoxedBody>,
        budget: Duration,
    ) -> Result<(u64, u32), Fail>
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if budget.is_zero() {
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
        let outcome = tokio::time::timeout(budget, async {
            let t0 = Instant::now();
            let resp = sender
                .send_request(req)
                .await
                .map_err(|e| ("tcp-alive", e.to_string()))?;
            let status = resp.status().as_u16();
            if !(200..=299).contains(&status) {
                return Err::<_, Fail>(("tcp-alive", format!("target status {status}")));
            }
            let mut body = resp.into_body();
            let mut bytes = 0u64;
            while let Some(item) = body.frame().await {
                let frame = item.map_err(|e| ("tcp-alive", e.to_string()))?;
                if let Ok(data) = frame.into_data() {
                    // Clamp inside the frame: a peer that coalesces 300 KiB
                    // into one frame must still sample exactly the cap, so
                    // the throughput figure reflects a fixed sample size.
                    let take = data
                        .len()
                        .min(THROUGHPUT_MAX.saturating_sub(bytes as usize));
                    bytes += take as u64;
                    if bytes as usize >= THROUGHPUT_MAX {
                        break;
                    }
                }
            }
            Ok((
                bytes,
                u32::try_from(t0.elapsed().as_millis()).unwrap_or(u32::MAX),
            ))
        })
        .await;
        drop(sender);
        driver.abort();
        outcome.map_err(|_| ("tcp-alive", "throughput timeout".to_string()))?
    }

    /// Second dial through the same proxy, download the sample, and report
    /// kbps. `None` on any failure — a missing speed figure is decoration, so
    /// a proxy that cannot serve the sample stays live.
    async fn throughput_probe(&self, c: &Candidate) -> Option<u32> {
        let t = self.throughput.as_ref()?;
        // Fresh budget: the echo's dial-anchored remainder is ~0 by now, and
        // a ~0 budget would starve every slow-but-live proxy of a speed tier.
        let start = Instant::now();
        let tcp = tokio::time::timeout(self.cfg.connect_timeout, TcpStream::connect(c.addr))
            .await
            .ok()?
            .ok()?;
        let _ = tcp.set_nodelay(true);

        // Layering mirrors the check flows exactly: proxy-facing TLS is
        // verification-off (self-signed proxy endpoints), origin-facing TLS
        // is verified (the sample host must not be forgeable).
        let (io, uri, origin_host): (BoxedIo, String, Option<String>) = match c.scheme {
            Scheme::Http | Scheme::Https => {
                let io: BoxedIo = if t.check.tls {
                    let mut tcp = tcp;
                    self.connect_phase(&mut tcp, start, &t.authority, c.auth.as_ref())
                        .await
                        .ok()?;
                    let tls = self
                        .tls_wrap(&self.tls_verified, tcp, start, &t.check.host)
                        .await
                        .ok()?;
                    Box::new(tls)
                } else if matches!(c.scheme, Scheme::Https) {
                    let tls = self
                        .tls_wrap(&self.tls_verify_off, tcp, start, &t.check.host)
                        .await
                        .ok()?;
                    Box::new(tls)
                } else {
                    Box::new(tcp)
                };
                if t.check.tls {
                    (io, t.check.path.clone(), Some(t.authority.clone()))
                } else {
                    (io, t.check.url.clone(), None)
                }
            }
            Scheme::Socks5 | Scheme::Socks4 => {
                let inner = match c.scheme {
                    Scheme::Socks5 => self
                        .socks5_handshake(tcp, c, &t.check.host, t.check.port, start)
                        .await
                        .ok()?,
                    _ => {
                        let Some(&IpAddr::V4(ip)) = t.ips.iter().find(|a| a.is_ipv4()) else {
                            return None; // socks4 has no proxy-side DNS
                        };
                        self.socks4_handshake(tcp, c, ip, t.check.port, start)
                            .await
                            .ok()?
                    }
                };
                if t.check.tls {
                    let tls = self
                        .tls_wrap(&self.tls_verified, inner, start, &t.check.host)
                        .await
                        .ok()?;
                    (
                        Box::new(tls),
                        t.check.path.clone(),
                        Some(t.authority.clone()),
                    )
                } else {
                    let uri = format!("http://{}{}", t.authority, t.check.path);
                    (Box::new(inner), uri, Some(t.authority.clone()))
                }
            }
        };

        let req = self
            .request_keep_alive(&uri, origin_host.as_deref(), c.auth.as_ref(), true)
            .ok()?;
        let budget = self.cfg.total_timeout.saturating_sub(start.elapsed());
        let (bytes, elapsed_ms) = self.timed_download(io, req, budget).await.ok()?;
        if bytes == 0 {
            return None;
        }
        if self.cfg.debug {
            qeprintln!("[throughput] {bytes} bytes in {elapsed_ms} ms");
        }
        // u64 intermediates: at the 256 KiB cap and a 1 ms floor this is
        // 2_097_152_000, which fits u32 only because of that floor.
        Some(u32::try_from(bytes * 8 * 1000 / elapsed_ms.max(1) as u64).unwrap_or(u32::MAX))
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

fn body_preview(text: &str) -> String {
    text.chars().take(24).collect()
}

fn shape_from_read_error(fail: Fail) -> Shape {
    if fail.1 == OVERSIZED_RESPONSE {
        Shape::Wrong(OVERSIZED_RESPONSE.into())
    } else {
        Shape::Unreachable
    }
}

fn user_agent() -> &'static str {
    concat!("proxalyze/", env!("CARGO_PKG_VERSION"))
}

fn slot_cap(concurrency: usize, slots: usize) -> usize {
    let floor = if concurrency >= 16 { 16 } else { 1 };
    concurrency
        .div_ceil(slots.max(1))
        .max(floor)
        .min(concurrency)
}

fn interpret_socks4_reply(reply: [u8; 8]) -> Result<(), Fail> {
    if reply[0] != 0 {
        return Err(("socks-rejected", format!("socks4 reply VN={}", reply[0])));
    }
    match reply[1] {
        90 => Ok(()),
        92 => Err(("auth-required", "socks4 identd refusal".into())),
        code => Err(("socks-rejected", format!("socks4 reply code {code}"))),
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

    fn validator() -> Validator {
        Validator {
            cfg: CheckCfg {
                concurrency: 1,
                connect_timeout: Duration::from_secs(1),
                total_timeout: Duration::from_secs(1),
                debug: false,
                probe_capabilities: false,
                probe_throughput: false,
                throughput: None,
            },
            slots: Vec::new(),
            rr: AtomicUsize::new(0),
            own_egress: None,
            tls_verify_off: Arc::new(tls_config(false).unwrap()),
            tls_verified: Arc::new(tls_config(true).unwrap()),
            done: Arc::new(AtomicUsize::new(0)),
            throughput: None,
        }
    }

    /// Scripted HTTP/1.1 peer: reads a whole request (head plus any
    /// chunked body), answers with the next scripted response, and returns
    /// every request head it saw.
    async fn serve(mut client: tokio::io::DuplexStream, responses: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let mut seen = Vec::new();
        // One buffer across the whole script: hyper pipelines, so a later
        // request can arrive in the same read as an earlier one's head.
        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 512];
        for response in responses {
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = client.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    return seen;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            // A chunked request's body trails its head; consume the terminal
            // chunk so the client's next write cannot deadlock on it.
            let head = String::from_utf8_lossy(&buf).to_ascii_lowercase();
            let chunked = head.contains("transfer-encoding: chunked");
            if chunked {
                while !buf.windows(5).any(|w| w == b"0\r\n\r\n") {
                    let n = client.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return seen;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
            }
            let end = if chunked {
                buf.windows(5)
                    .position(|w| w == b"0\r\n\r\n")
                    .map(|p| p + 5)
                    .unwrap_or(buf.len())
            } else {
                buf.windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map(|p| p + 4)
                    .unwrap_or(buf.len())
            };
            seen.push(buf[..end].to_vec());
            buf.drain(..end);
            if client.write_all(&response).await.is_err() {
                return seen;
            }
            let _ = client.flush().await;
        }
        seen
    }

    fn ok_body() -> Vec<u8> {
        let body = b"{\"origin\":\"127.0.0.1\"}";
        let mut out = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: keep-alive\r\n\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        out
    }

    fn check_uri() -> String {
        "http://echo.test/ip".into()
    }

    async fn respond_to_connect(mut client: tokio::io::DuplexStream, response: &'static [u8]) {
        let mut request = Vec::new();
        let mut chunk = [0u8; 128];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let n = client.read(&mut chunk).await.unwrap();
            assert_ne!(n, 0, "validator closed CONNECT before sending its request");
            request.extend_from_slice(&chunk[..n]);
        }
        client.write_all(response).await.unwrap();
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
                cap: 1,
                errors: Arc::new(AtomicU64::new(0)),
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
    fn user_agent_is_present() {
        assert_eq!(
            user_agent(),
            concat!("proxalyze/", env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn slot_cap_respects_low_concurrency() {
        assert_eq!(slot_cap(4, 3), 2);
        assert_eq!(slot_cap(1024, 3), 342);
        assert_eq!(slot_cap(1024, 1), 1024);
        assert_eq!(slot_cap(4, 1), 4);
    }

    #[tokio::test]
    async fn connect_phase_accepts_successful_connect_reply() {
        let (mut client, peer) = tokio::io::duplex(1024);
        let server = tokio::spawn(respond_to_connect(peer, b"HTTP/1.1 200 OK\r\n\r\n"));

        let result = validator()
            .connect_phase(&mut client, Instant::now(), "example.com:443", None)
            .await;

        server.await.unwrap();
        assert!(result.is_ok(), "HTTP 200 CONNECT reply should succeed");
    }

    #[tokio::test]
    async fn connect_phase_maps_407_to_auth_required() {
        let (mut client, peer) = tokio::io::duplex(1024);
        let server = tokio::spawn(respond_to_connect(peer, b"HTTP/1.1 407 Proxy Auth\r\n\r\n"));

        let result = validator()
            .connect_phase(&mut client, Instant::now(), "example.com:443", None)
            .await;

        server.await.unwrap();
        assert_eq!(
            result.expect_err("HTTP 407 CONNECT reply should fail").0,
            "auth-required"
        );
    }

    #[test]
    fn interpret_socks4_reply_maps_reply_codes() {
        assert!(interpret_socks4_reply([0, 90, 0, 0, 0, 0, 0, 0]).is_ok());
        assert_eq!(
            interpret_socks4_reply([0, 91, 0, 0, 0, 0, 0, 0])
                .expect_err("SOCKS4 request rejected")
                .0,
            "socks-rejected"
        );
        assert_eq!(
            interpret_socks4_reply([0, 92, 0, 0, 0, 0, 0, 0])
                .expect_err("SOCKS4 identd required")
                .0,
            "auth-required"
        );
        assert_eq!(
            interpret_socks4_reply([4, 90, 0, 0, 0, 0, 0, 0])
                .expect_err("SOCKS4 reply with bad version must fail")
                .0,
            "socks-rejected"
        );
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

    #[test]
    fn body_preview_counts_chars_at_multibyte_boundary() {
        let body = format!("{}☃{}", "é".repeat(12), "x".repeat(20));
        let expected = format!("{}☃{}", "é".repeat(12), "x".repeat(11));

        assert_eq!(body_preview(&body), expected);
    }

    #[test]
    fn oversized_read_once_response_has_wrong_shape() {
        let shape = shape_from_read_error(("tcp-alive", "oversized response".into()));

        assert!(
            matches!(shape, Shape::Wrong(detail) if detail == "oversized response"),
            "an oversized reachable response is a wrong body shape, not unreachable"
        );
    }

    #[test]
    fn speed_tier_thresholds_are_exact() {
        assert_eq!(speed_tier_of(2048), "fast");
        assert_eq!(speed_tier_of(2047), "mid");
        assert_eq!(speed_tier_of(512), "mid");
        assert_eq!(speed_tier_of(511), "slow");
    }

    #[tokio::test]
    async fn timed_download_caps_at_256k_without_touching_echo_cap() {
        let (client, mut peer) = tokio::io::duplex(1024 * 1024);
        let body = vec![b'x'; 300 * 1024];
        let head_out = {
            let mut all =
                format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", body.len()).into_bytes();
            all.extend_from_slice(&body);
            all
        };
        let server = tokio::spawn(async move {
            // Read the request head first: hyper writes nothing until the
            // peer is listening.
            let mut chunk = [0u8; 512];
            let mut head = Vec::new();
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = peer.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                head.extend_from_slice(&chunk[..n]);
            }
            let _ = peer.write_all(&head_out).await;
            let _ = peer.flush().await;
            // hold the stream open past the cap so the reader stops on it
            tokio::time::sleep(Duration::from_millis(500)).await;
        });

        let v = validator();
        let req = v
            .request_keep_alive("http://x.test/big", Some("x.test"), None, true)
            .unwrap();
        let (bytes, _elapsed) = v
            .timed_download(client, req, Duration::from_secs(5))
            .await
            .expect("hitting the throughput cap is success, not an oversized error");
        server.abort();

        assert!(
            (1..=(THROUGHPUT_MAX as u64)).contains(&bytes),
            "sample must stop at the 256 KiB cap, got {bytes}"
        );
    }

    #[tokio::test]
    async fn capability_probe_failure_keeps_live_verdict() {
        let (client, peer) = tokio::io::duplex(8192);
        // Answers the primary GET, then hangs up: both follow-ups fail.
        let server = tokio::spawn(async move {
            let _ = serve(peer, vec![ok_body()]).await;
        });

        let mut v = validator();
        v.cfg.probe_capabilities = true;
        let uri = check_uri();
        let req = v.request(&uri, None, None).unwrap();
        let extras = v.extras(&uri, None, None).unwrap();
        let r = v
            .run_conn(client, req, Instant::now(), ip("127.0.0.1"), Some(&extras))
            .await
            .expect("a broken follow-up must not fail the check");
        let _ = server.await;

        assert_eq!(r.status, "live");
        assert_eq!(r.anonymity, Some("elite"));
        assert_eq!(r.fail_reason, None);
        assert!(
            r.caps.is_empty(),
            "a peer that hangs up supports neither capability: {:?}",
            r.caps
        );
    }

    #[tokio::test]
    async fn keep_alive_and_chunked_tags_on_successful_followups() {
        let (client, peer) = tokio::io::duplex(64 * 1024);
        let post_ok = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok".to_vec();
        let server =
            tokio::spawn(async move { serve(peer, vec![ok_body(), ok_body(), post_ok]).await });

        let mut v = validator();
        v.cfg.probe_capabilities = true;
        let uri = check_uri();
        let req = v.request(&uri, None, None).unwrap();
        let extras = v.extras(&uri, None, None).unwrap();
        let r = v
            .run_conn(client, req, Instant::now(), ip("127.0.0.1"), Some(&extras))
            .await
            .expect("three answered requests are a live proxy");
        let seen = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("peer should have served all three requests")
            .unwrap();

        let head = String::from_utf8_lossy(&seen[0]).to_ascii_lowercase();
        assert!(
            !head.contains("connection: close"),
            "the primary request must stay open for the follow-ups: {head}"
        );
        let chunked = String::from_utf8_lossy(&seen[2]).to_ascii_lowercase();
        assert!(
            chunked.contains("transfer-encoding: chunked"),
            "the POST body has no length, so it must be chunked: {chunked}"
        );
        let mut caps = r.caps.clone();
        caps.sort_unstable();
        assert_eq!(caps, ["chunked-post", "keep-alive"]);
    }
}
