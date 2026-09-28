#![allow(dead_code)]

use std::borrow::Cow;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
pub enum EchoMode {
    Elite,
    Anonymous,
    Transparent,
}

/// Explicitly make an accepted stream blocking. BSD/macOS inherit O_NONBLOCK
/// from the nonblocking listener (Linux does not), which defeats the
/// handlers' blocking reads with SO_RCVTIMEO: they fail instantly with
/// WouldBlock instead of waiting for the peer's next segment.
fn make_blocking(stream: &TcpStream) {
    stream.set_nonblocking(false).unwrap();
}

impl EchoMode {
    fn body(self) -> &'static str {
        match self {
            Self::Elite => "127.0.0.1",
            Self::Anonymous => "203.0.113.7",
            Self::Transparent => "198.51.100.9",
        }
    }
}

pub struct EchoServer {
    pub addr: SocketAddr,
    accepts: Arc<AtomicUsize>,
    targets: Arc<Mutex<Vec<String>>>,
    /// Connections that presented a second request head — PER-CONNECTION
    /// reuse, not a global request count: one connection serving four
    /// requests is one hit.
    keepalive: Arc<AtomicUsize>,
    /// `Transfer-Encoding` values observed, recorded alongside `targets` so
    /// a chunked-POST probe can be identified after the fact.
    transfer_encodings: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

/// Everything one `EchoServer` instance shares with its per-connection
/// threads, and the static facts about what it serves.
#[derive(Clone)]
struct EchoFixture {
    mode: EchoMode,
    status: u16,
    /// Bytes served on any `/big` path; `None` disables the endpoint.
    big_body: Option<usize>,
    accepts: Arc<AtomicUsize>,
    targets: Arc<Mutex<Vec<String>>>,
    keepalive: Arc<AtomicUsize>,
    transfer_encodings: Arc<Mutex<Vec<String>>>,
    /// GET-only: the first GET the server ever sees is the startup
    /// shape-check and must consume the own-egress response. POSTs never
    /// take an ordinal.
    get_ordinal: Arc<AtomicUsize>,
}

/// A chunked-POST capability probe is a POST, never a check: dispatching on
/// method first keeps the ordinal reserved for the GET shape-check.
const POST_ACK: &str = "ok";

/// Bodies larger than a one-liner can't live in `EchoMode::body`'s
/// `&'static str`, so the throughput sample is served from a path instead.
const BIG_PATH: &str = "/big";

/// Requests served per accepted stream before the mock closes. Bounded so a
/// client that never goes away cannot pin a mock thread.
const MAX_REQUESTS_PER_CONNECTION: usize = 4;

/// How long a mock waits for the NEXT request head on a connection it has
/// already answered. Generous enough for a real follow-up (the client sends
/// it immediately on the same stream) but short enough that a client which
/// sent `Connection: close` does not pin the handler thread while the suite's
/// `Drop` joins it.
const IDLE_READ_TIMEOUT: Duration = Duration::from_millis(250);

/// The startup shape-check must consume the own-egress response; a static
/// server otherwise cannot tell elite from anonymous.
const OWN_EGRESS: &str = "198.51.100.9";

impl EchoServer {
    pub fn start(mode: EchoMode, status: u16) -> Self {
        Self::build(mode, status, None)
    }

    /// Also serve `size` bytes on any path ending in `/big`, for
    /// `--probe-throughput` (whose sample cap is 256 KiB — far past what an
    /// `EchoMode` body can hold).
    pub fn start_with_big_body(mode: EchoMode, size: usize) -> Self {
        Self::build(mode, 200, Some(size))
    }

    fn build(mode: EchoMode, status: u16, big_body: Option<usize>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let targets = Arc::new(Mutex::new(Vec::new()));
        let keepalive = Arc::new(AtomicUsize::new(0));
        let transfer_encodings = Arc::new(Mutex::new(Vec::new()));
        let fixture = EchoFixture {
            mode,
            status,
            big_body,
            accepts: accepts.clone(),
            targets: targets.clone(),
            keepalive: keepalive.clone(),
            transfer_encodings: transfer_encodings.clone(),
            get_ordinal: Arc::new(AtomicUsize::new(0)),
        };
        let stop = Arc::new(AtomicBool::new(false));
        let thread_fixture = fixture.clone();
        let thread_stop = stop.clone();
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        thread_fixture.accepts.fetch_add(1, Ordering::SeqCst);
                        let fixture = thread_fixture.clone();
                        let _ = thread::spawn(move || handle_echo(stream, &fixture));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            addr,
            accepts,
            targets,
            keepalive,
            transfer_encodings,
            stop,
            thread: Some(thread),
        }
    }

    pub fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    /// Connections that served a second request head on the same stream.
    pub fn keepalive_hits(&self) -> usize {
        self.keepalive.load(Ordering::SeqCst)
    }

    pub fn targets(&self) -> Vec<String> {
        self.targets.lock().unwrap().clone()
    }

    /// `targets()` after the detached per-connection threads have had a
    /// chance to record, or a panic once `timeout` elapses. A connection
    /// handler records from its own thread, so an immediate read after the
    /// child exits can otherwise miss a request that DID arrive.
    pub fn wait_for_targets(&self, min: usize, timeout: Duration) -> Vec<String> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let targets = self.targets();
            if targets.len() >= min || std::time::Instant::now() >= deadline {
                return targets;
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}

/// Requests on one connection: method first (a chunked-POST capability
/// probe is a POST and is acknowledged, never answered with an IP body),
/// then path, and only then the global GET ordinal.
fn handle_echo(mut stream: TcpStream, fixture: &EchoFixture) {
    make_blocking(&stream);
    stream.set_read_timeout(Some(IDLE_READ_TIMEOUT)).unwrap();
    let mut served = 0usize;
    while served < MAX_REQUESTS_PER_CONNECTION {
        let Some(head) = read_http_head(&mut stream) else {
            return;
        };
        served += 1;
        if served == 2 {
            // A second head on the SAME stream is per-connection reuse.
            fixture.keepalive.fetch_add(1, Ordering::SeqCst);
        }
        let request_line = head.lines().next().unwrap_or_default();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default();
        let target = parts.next().unwrap_or_default().to_owned();
        fixture.targets.lock().unwrap().push(target.clone());
        if let Some(encoding) = header_value(&head, "transfer-encoding") {
            fixture
                .transfer_encodings
                .lock()
                .unwrap()
                .push(encoding.to_owned());
        }
        // Owned because the big-body arm sizes itself in bytes rather than
        // borrowing a `&'static str`.
        let body: Cow<'_, str> = if method.eq_ignore_ascii_case("POST") {
            Cow::Borrowed(POST_ACK)
        } else if fixture.big_body.is_some_and(|_| target.ends_with(BIG_PATH)) {
            Cow::Owned("x".repeat(fixture.big_body.unwrap_or_default()))
        } else if fixture.get_ordinal.fetch_add(1, Ordering::SeqCst) == 0 {
            Cow::Borrowed(OWN_EGRESS)
        } else {
            Cow::Borrowed(fixture.mode.body())
        };
        if write_http_response(&mut stream, fixture.status, &body, head_wants_close(&head)) {
            return;
        }
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        shutdown_server(self.addr, &self.stop, self.thread.take());
    }
}

fn shutdown_server(addr: SocketAddr, stop: &Arc<AtomicBool>, handle: Option<JoinHandle<()>>) {
    stop.store(true, Ordering::Relaxed);
    let _ = TcpStream::connect(addr);
    if let Some(handle) = handle {
        let _ = handle.join();
    }
}

pub struct HttpProxyMock {
    pub addr: SocketAddr,
    accepts: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    /// Connections that presented a second request head — per-connection
    /// reuse, so one connection serving several requests is one hit.
    keepalive: Arc<AtomicUsize>,
    /// Per-request capture of the forward path, where the capability
    /// follow-ups actually land: an HTTP proxy answers them itself, so the
    /// echo never sees them.
    requests: Arc<Mutex<Vec<RequestCapture>>>,
    /// Forward absolute-form requests to the real target instead of
    /// answering them from `body`.
    relay: bool,
    thread: Option<JoinHandle<()>>,
}

/// One forwarded request, as the proxy received it.
#[derive(Clone, Debug)]
pub struct RequestCapture {
    pub method: String,
    pub target: String,
    pub transfer_encoding: Option<String>,
}

impl HttpProxyMock {
    pub fn open(body: &str) -> Self {
        Self::build(None, body.into(), 200, false)
    }

    /// Forwards absolute-form requests to the real target, relaying the
    /// response verbatim, so a `--throughput-url` sample flows from the
    /// origin rather than from this mock's own body. Origin-form requests
    /// (the check and its capability follow-ups) are still answered from
    /// `body`.
    pub fn open_relaying(body: &str) -> Self {
        Self::build(None, body.into(), 200, true)
    }

    pub fn requiring_auth(user: &str, password: &str, body: &str) -> Self {
        Self::build(
            Some((user.into(), password.into())),
            body.into(),
            200,
            false,
        )
    }

    pub fn unauthorized() -> Self {
        Self::build(
            Some(("required".into(), "secret".into())),
            String::new(),
            407,
            false,
        )
    }

    pub fn unavailable() -> Self {
        Self::build(None, "unavailable".into(), 503, false)
    }

    fn build(
        required_auth: Option<(String, String)>,
        body: String,
        status: u16,
        relay: bool,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let thread_accepts = accepts.clone();
        let keepalive = Arc::new(AtomicUsize::new(0));
        let thread_keepalive = keepalive.clone();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let thread_requests = requests.clone();
        let thread_auth = Arc::new(required_auth);
        let shared_body = Arc::new(body);
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        thread_accepts.fetch_add(1, Ordering::SeqCst);
                        let auth = thread_auth.clone();
                        let keepalive = thread_keepalive.clone();
                        let requests = thread_requests.clone();
                        let body = shared_body.clone();
                        let _ = thread::Builder::new().spawn(move || {
                            handle_http_proxy(
                                stream,
                                auth.as_ref().as_ref(),
                                &body,
                                status,
                                keepalive,
                                requests,
                                relay,
                            )
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1))
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            addr,
            accepts,
            keepalive,
            requests,
            relay,
            stop,
            thread: Some(thread),
        }
    }

    pub fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    /// Connections that served more than one request head.
    pub fn keepalive_hits(&self) -> usize {
        self.keepalive.load(Ordering::SeqCst)
    }

    /// Wait until the forward path has recorded `min` requests, so a caller
    /// that reads immediately after the child exits cannot race the
    /// per-connection threads.
    pub fn wait_for_requests(&self, min: usize, timeout: Duration) -> Vec<RequestCapture> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let captured = self.requests.lock().unwrap().clone();
            if captured.len() >= min || std::time::Instant::now() >= deadline {
                return captured;
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for HttpProxyMock {
    fn drop(&mut self) {
        shutdown_server(self.addr, &self.stop, self.thread.take());
    }
}

fn handle_http_proxy(
    mut stream: TcpStream,
    auth: Option<&(String, String)>,
    body: &str,
    status: u16,
    keepalive: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<RequestCapture>>>,
    relay: bool,
) {
    make_blocking(&stream);
    let _ = stream.set_read_timeout(Some(IDLE_READ_TIMEOUT));
    // Bounded loop: a capability probe rides the SAME connection for a
    // keep-alive GET and a chunked POST, so a mock that answered once and
    // dropped the stream could never earn either tag. Closing after a
    // response happens only when the CLIENT asked for it, or the request
    // budget is spent.
    let mut served = 0usize;
    while served < MAX_REQUESTS_PER_CONNECTION {
        let Some(head) = read_http_head(&mut stream) else {
            return;
        };
        served += 1;
        if served == 2 {
            // A second head on the SAME stream is per-connection reuse.
            keepalive.fetch_add(1, Ordering::SeqCst);
        }
        let first = head.lines().next().unwrap_or_default();
        let mut parts = first.split_whitespace();
        requests.lock().unwrap().push(RequestCapture {
            method: parts.next().unwrap_or_default().to_owned(),
            target: parts.next().unwrap_or_default().to_owned(),
            transfer_encoding: header_value(&head, "transfer-encoding").map(str::to_owned),
        });
        if connect_authority(first).is_some() {
            // A tunnel consumes the connection outright.
            serve_connect(&mut stream, &head, auth);
            return;
        }
        if relay && let Some(authority) = absolute_form_authority(first) {
            // Absolute-form request in pass-through mode: the body must come
            // from the real origin, not from this mock.
            if let Ok(mut target) = TcpStream::connect(authority) {
                let _ = target.set_read_timeout(Some(Duration::from_secs(1)));
                if target.write_all(head.as_bytes()).is_ok() {
                    relay_bidirectional(stream.try_clone().unwrap(), target);
                    return;
                }
            }
            let _ = write_http_response(&mut stream, 502, "pass-through failed", true);
            return;
        }
        if auth.is_some_and(|(u, p)| !has_basic_auth(&head, u, p)) {
            if write_http_response(&mut stream, 407, "proxy authentication required", true) {
                return;
            }
            continue;
        }
        if write_http_response(&mut stream, status, body, head_wants_close(&head)) {
            return;
        }
    }
}

/// CONNECT is terminal: once the tunnel is up the socket belongs to the
/// relay, not to the request loop.
fn serve_connect(stream: &mut TcpStream, head: &str, auth: Option<&(String, String)>) {
    let authority = match connect_authority(head.lines().next().unwrap_or_default()) {
        Some(authority) => authority,
        None => return,
    };
    if auth.is_some_and(|(u, p)| !has_basic_auth(head, u, p)) {
        let _ = write_http_response(stream, 407, "proxy authentication required", true);
        return;
    }
    match TcpStream::connect(authority) {
        Ok(target) => {
            target
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            if stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .is_ok()
            {
                relay_bidirectional(stream.try_clone().unwrap(), target);
            }
        }
        Err(_) => {
            let _ = write_http_response(stream, 502, "connect failed", true);
        }
    }
}

pub struct SilentProxy {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl SilentProxy {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let thread = thread::spawn(move || {
            let mut held = Vec::new();
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => held.push(stream),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1))
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            addr,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for SilentProxy {
    fn drop(&mut self) {
        shutdown_server(self.addr, &self.stop, self.thread.take());
    }
}

pub struct Socks5Mock {
    pub addr: SocketAddr,
    accepts: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Socks5Mock {
    pub fn no_auth() -> Self {
        Self::build(None)
    }

    pub fn requiring(user: &str, password: &str) -> Self {
        Self::build(Some((user.into(), password.into())))
    }

    fn build(credentials: Option<(String, String)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let thread_accepts = accepts.clone();
        let thread_credentials = Arc::new(credentials);
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        thread_accepts.fetch_add(1, Ordering::SeqCst);
                        let credentials = thread_credentials.clone();
                        let _ = thread::Builder::new().spawn(move || {
                            handle_socks_client(stream, credentials.as_ref().as_ref())
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1))
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            addr,
            accepts,
            stop,
            thread: Some(thread),
        }
    }

    pub fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }
}

impl Drop for Socks5Mock {
    fn drop(&mut self) {
        shutdown_server(self.addr, &self.stop, self.thread.take());
    }
}

fn handle_socks_client(mut stream: TcpStream, credentials: Option<&(String, String)>) {
    make_blocking(&stream);
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    if !socks_handshake(&mut stream, credentials) {
        return;
    }
    let Some(target) = read_socks_connect(&mut stream) else {
        let _ = stream.write_all(&[5, 1, 0]);
        return;
    };
    match TcpStream::connect(target) {
        Ok(upstream) => {
            upstream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            if stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).is_ok() {
                relay_bidirectional(stream.try_clone().unwrap(), upstream);
            }
        }
        Err(_) => {
            let _ = stream.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
        }
    }
}

pub fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

pub struct TestDir(PathBuf);

impl TestDir {
    pub fn new(test_name: &str) -> Self {
        let clean: String = test_name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        let path =
            std::env::temp_dir().join(format!("proxalyze-e2e-{}-{clean}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `command(&dir)` plus the caller's flags, in one spawn. `command` already
/// supplies `--backup-url ""`, so no caller ever re-spells the network-free
/// boilerplate.
pub fn run_with(test_dir: &TestDir, args: &[&str]) -> Output {
    let mut cmd = command(test_dir);
    cmd.args(args);
    run(&mut cmd)
}

pub fn command(test_dir: &TestDir) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_proxalyze"));
    cmd.arg("--backup-url").arg("");
    cmd.arg("--connect-timeout").arg("0.25");
    cmd.arg("--timeout").arg("1.0");
    cmd.arg("--workers").arg("2");
    cmd.arg("--out").arg(test_dir.path());
    cmd
}

pub fn run(cmd: &mut Command) -> Output {
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}

fn read_http_head(stream: &mut TcpStream) -> Option<String> {
    let mut bytes = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }

        bytes.extend_from_slice(&buf[..n]);
        if bytes.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if bytes.len() > 64 * 1024 {
            return None;
        }
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Write one response. Returns `true` when the caller must close the
/// connection: either the client asked for it, or the write failed. A
/// `Content-Length`-delimited body lets a keep-alive client read to
/// completion and reuse the stream, which is what the capability follow-ups
/// need.
fn write_http_response(stream: &mut TcpStream, status: u16, body: &str, close: bool) -> bool {
    let reason = if status == 200 { "OK" } else { "Error" };
    let connection = if close { "close" } else { "keep-alive" };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: {connection}\r\n\r\n{body}",
        body.len()
    );
    // The write MUST happen regardless of `close`: `close || write` would
    // short-circuit and answer `Connection: close` clients with silence.
    stream.write_all(response.as_bytes()).is_err() || close
}

/// The client's own `Connection: close` — the only thing that may close a
/// response-delivering connection before its request budget is spent.
fn head_wants_close(head: &str) -> bool {
    header_value(head, "connection")
        .is_some_and(|value| value.to_ascii_lowercase().contains("close"))
}

/// Case-insensitive header lookup in a raw request head.
fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        line.split_once(':')
            .filter(|(key, _)| key.trim().eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim())
    })
}

fn has_basic_auth(head: &str, user: &str, password: &str) -> bool {
    let expected = format!("Basic {}", base64(format!("{user}:{password}").as_bytes()));
    head.lines().any(|line| {
        line.to_ascii_lowercase()
            .starts_with("proxy-authorization:")
            && line
                .split_once(':')
                .is_some_and(|(_, value)| value.trim() == expected)
    })
}

fn socks_handshake(stream: &mut TcpStream, credentials: Option<&(String, String)>) -> bool {
    let mut greeting = [0u8; 2];
    if stream.read_exact(&mut greeting).is_err() || greeting[0] != 5 {
        return false;
    }
    let mut methods = vec![0u8; greeting[1] as usize];
    if stream.read_exact(&mut methods).is_err() {
        return false;
    }
    if credentials.is_none() {
        if !methods.contains(&0) {
            return false;
        }
        return stream.write_all(&[5, 0]).is_ok();
    }
    if !methods.contains(&2) {
        return false;
    }
    if stream.write_all(&[5, 2]).is_err() {
        return false;
    }
    let mut auth = [0u8; 2];
    if stream.read_exact(&mut auth).is_err() || auth[0] != 1 {
        return false;
    }
    let mut user = vec![0u8; auth[1] as usize];
    if stream.read_exact(&mut user).is_err() {
        return false;
    }
    let mut pass_len = [0u8; 1];
    if stream.read_exact(&mut pass_len).is_err() {
        return false;
    }
    let mut pass = vec![0u8; pass_len[0] as usize];
    if stream.read_exact(&mut pass).is_err() {
        return false;
    }
    let expected = credentials.unwrap();
    if user == expected.0.as_bytes() && pass == expected.1.as_bytes() {
        stream.write_all(&[1, 0]).is_ok()
    } else {
        let _ = stream.write_all(&[1, 1]);
        false
    }
}

fn read_socks_connect(stream: &mut TcpStream) -> Option<SocketAddr> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).ok()?;
    if header[0] != 5 || header[1] != 1 {
        return None;
    }
    let host = match header[3] {
        1 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).ok()?;
            IpAddr::V4(Ipv4Addr::from(ip))
        }
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).ok()?;
            let mut name = vec![0u8; len[0] as usize];
            stream.read_exact(&mut name).ok()?;
            String::from_utf8(name).ok()?.parse().ok()?
        }
        4 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).ok()?;
            IpAddr::from(ip)
        }
        _ => return None,
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).ok()?;
    Some(SocketAddr::new(host, u16::from_be_bytes(port)))
}

/// Host:port of an absolute-form forward request (`GET http://h:port/p HTTP/1.1`).
/// The scheme is stripped, so a `https://` target would still be forwarded in
/// the clear — the mocks here only ever carry plain-HTTP targets.
fn absolute_form_authority(request_line: &str) -> Option<&str> {
    let target = request_line.split_ascii_whitespace().nth(1)?;
    if !target.contains("://") {
        return None;
    }
    let authority = target.split_once("://")?.1;
    let tail = authority
        .split_once('/')
        .map_or(authority, |(host, _)| host);
    (!tail.is_empty()).then_some(tail)
}

pub(crate) fn connect_authority(request_line: &str) -> Option<&str> {
    request_line
        .strip_prefix("CONNECT ")?
        .split_ascii_whitespace()
        .next()
}

fn relay_bidirectional(left: TcpStream, right: TcpStream) {
    let right_for_left = right.try_clone().unwrap();
    let left_for_right = left.try_clone().unwrap();
    let forward = thread::spawn(move || copy_stream(left, right_for_left));
    copy_stream(right, left_for_right);
    let _ = forward.join();
}

fn copy_stream(mut source: TcpStream, mut sink: TcpStream) {
    let mut buf = [0u8; 8192];
    while let Ok(n) = source.read(&mut buf) {
        if n == 0 || sink.write_all(&buf[..n]).is_err() {
            break;
        }
    }
    let _ = sink.shutdown(Shutdown::Write);
}

fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let a = chunk[0] as u32;
        let b = *chunk.get(1).unwrap_or(&0) as u32;
        let c = *chunk.get(2).unwrap_or(&0) as u32;
        let n = a << 16 | b << 8 | c;
        out.push(ALPHABET[(n >> 18 & 63) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::connect_authority;

    #[test]
    fn connect_authority_extracts_the_request_target() {
        for (line, expected) in [
            ("CONNECT 127.0.0.1:443 HTTP/1.1", Some("127.0.0.1:443")),
            ("CONNECT example.test HTTP/1.1", Some("example.test")),
            ("GET http://example.test/ HTTP/1.1", None),
        ] {
            assert_eq!(connect_authority(line), expected, "line: {line}");
        }
    }
}
