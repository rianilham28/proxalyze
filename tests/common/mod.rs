#![allow(dead_code)]

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
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl EchoServer {
    pub fn start(mode: EchoMode, status: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let targets = Arc::new(Mutex::new(Vec::new()));
        let thread_accepts = accepts.clone();
        let thread_targets = targets.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let request_number = Arc::new(AtomicUsize::new(0));
        let thread_request_number = request_number.clone();
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        thread_accepts.fetch_add(1, Ordering::SeqCst);
                        let targets = thread_targets.clone();
                        let request_number = thread_request_number.clone();
                        let _ = thread::spawn(move || {
                            let mut stream = stream;
                            stream
                                .set_read_timeout(Some(Duration::from_secs(1)))
                                .unwrap();
                            let Some(request) = read_http_head(&mut stream) else {
                                return;
                            };
                            let request_line = request.lines().next().unwrap_or_default();
                            let target = request_line
                                .split_whitespace()
                                .nth(1)
                                .unwrap_or_default()
                                .to_owned();
                            targets.lock().unwrap().push(target);
                            let ordinal = request_number.fetch_add(1, Ordering::SeqCst);
                            // classify captures own egress before judging candidates.
                            // A static server therefore cannot distinguish elite and
                            // anonymous: the startup request must consume the own-IP
                            // response, and candidate requests receive the mode body.
                            let body = if ordinal == 0 {
                                "198.51.100.9"
                            } else {
                                mode.body()
                            };
                            write_http_response(&mut stream, status, body);
                        });
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
            stop,
            thread: Some(thread),
        }
    }

    pub fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    pub fn targets(&self) -> Vec<String> {
        self.targets.lock().unwrap().clone()
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
    thread: Option<JoinHandle<()>>,
}

impl HttpProxyMock {
    pub fn open(body: &str) -> Self {
        Self::build(None, body.into(), 200)
    }

    pub fn requiring_auth(user: &str, password: &str, body: &str) -> Self {
        Self::build(Some((user.into(), password.into())), body.into(), 200)
    }

    pub fn unauthorized() -> Self {
        Self::build(
            Some(("required".into(), "secret".into())),
            String::new(),
            407,
        )
    }

    pub fn unavailable() -> Self {
        Self::build(None, "unavailable".into(), 503)
    }

    fn build(required_auth: Option<(String, String)>, body: String, status: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let thread_accepts = accepts.clone();
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
                        let body = shared_body.clone();
                        let _ = thread::Builder::new().spawn(move || {
                            handle_http_proxy(stream, auth.as_ref().as_ref(), &body, status)
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
) {
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let Some(head) = read_http_head(&mut stream) else {
        return;
    };
    let first = head.lines().next().unwrap_or_default();
    if let Some(authority) = connect_authority(first) {
        if auth.is_some_and(|(u, p)| !has_basic_auth(&head, u, p)) {
            write_http_response(&mut stream, 407, "proxy authentication required");
        } else if let Ok(target) = TcpStream::connect(authority) {
            target
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            relay_bidirectional(stream.try_clone().unwrap(), target);
        } else {
            write_http_response(&mut stream, 502, "connect failed");
        }
    } else if auth.is_some_and(|(u, p)| !has_basic_auth(&head, u, p)) {
        write_http_response(&mut stream, 407, "proxy authentication required");
    } else {
        write_http_response(&mut stream, status, body);
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

fn write_http_response(stream: &mut TcpStream, status: u16, body: &str) {
    let reason = if status == 200 { "OK" } else { "Error" };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
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
