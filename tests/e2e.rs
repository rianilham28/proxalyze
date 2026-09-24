//! Public-binary regression coverage for the gap sweep.
//!
//! Every network peer is a hermetic `127.0.0.1` mock. CONNECT and SOCKS4
//! remain covered by the lower-level duplex unit tests: an HTTPS inner-TLS
//! end-to-end flow would require a certificate trusted by webpki, which this
//! network-free harness deliberately does not introduce.

mod common;

use std::io::Read;
use std::net::TcpStream;
use std::path::Path;
use std::process::{Command, Stdio};

use common::{EchoMode, EchoServer, HttpProxyMock, SilentProxy, Socks5Mock, TestDir};

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn records(path: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn run_http(mode: EchoMode) -> (TestDir, std::process::Output, &'static str) {
    let echo = EchoServer::start(mode, 200);
    let proxy_body = match mode {
        EchoMode::Elite => "127.0.0.1",
        EchoMode::Anonymous => "203.0.113.7",
        EchoMode::Transparent => "198.51.100.9",
    };
    let proxy = HttpProxyMock::open(proxy_body);
    let dir = TestDir::new(&format!("http_{mode:?}"));
    let input = dir.path().join("input.txt");
    std::fs::write(&input, format!("127.0.0.1:{}\n", proxy.addr.port())).unwrap();
    let output = common::run(
        common::command(&dir)
            .arg("-i")
            .arg(&input)
            .arg("--check-url")
            .arg(format!("http://{}/ip", echo.addr)),
    );
    let expected = match mode {
        EchoMode::Elite => "elite",
        EchoMode::Anonymous => "anonymous",
        EchoMode::Transparent => "transparent",
    };
    (dir, output, expected)
}

#[test]
fn http_forward_classifies_elite() {
    let (dir, output, expected) = run_http(EchoMode::Elite);
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        stdout(&output),
        stderr(&output)
    );
    let rows = records(&dir.path().join("proxies.jsonl"));
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["anonymity"], expected);
}

#[test]
fn http_forward_classifies_anonymous() {
    let (dir, output, expected) = run_http(EchoMode::Anonymous);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        records(&dir.path().join("proxies.jsonl"))[0]["anonymity"],
        expected
    );
}

#[test]
fn http_forward_classifies_transparent() {
    let (dir, output, expected) = run_http(EchoMode::Transparent);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        records(&dir.path().join("proxies.jsonl"))[0]["anonymity"],
        expected
    );
}

#[test]
fn socks5_without_auth_reaches_echo_and_is_live() {
    let echo = EchoServer::start(EchoMode::Elite, 200);
    let socks = Socks5Mock::no_auth();
    let dir = TestDir::new("socks5_no_auth");
    let input = dir.path().join("input.txt");
    std::fs::write(
        &input,
        format!("socks5://127.0.0.1:{}\n", socks.addr.port()),
    )
    .unwrap();
    let output = common::run(
        common::command(&dir)
            .arg("-i")
            .arg(&input)
            .arg("--check-url")
            .arg(format!("http://{}/ip", echo.addr)),
    );
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        stdout(&output),
        stderr(&output)
    );
    let rows = records(&dir.path().join("proxies.jsonl"));
    assert_eq!(
        rows.len(),
        1,
        "stdout:\n{}\nstderr:\n{}",
        stdout(&output),
        stderr(&output)
    );
    assert_eq!(rows[0]["anonymity"], "elite");
    assert!(echo.targets().iter().any(|target| target.ends_with("/ip")));
}

#[test]
fn socks5_with_correct_credentials_is_live() {
    let echo = EchoServer::start(EchoMode::Elite, 200);
    let socks = Socks5Mock::requiring("Admin", "p+ss");
    let dir = TestDir::new("socks5_correct_credentials");
    let input = dir.path().join("input.txt");
    std::fs::write(
        &input,
        format!("socks5://Admin:p+ss@127.0.0.1:{}\n", socks.addr.port()),
    )
    .unwrap();
    let output = common::run(
        common::command(&dir)
            .arg("-i")
            .arg(&input)
            .arg("--check-url")
            .arg(format!("http://{}/ip", echo.addr)),
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        records(&dir.path().join("proxies.jsonl"))[0]["anonymity"],
        "elite"
    );
}

#[test]
fn socks5_wrong_credentials_produces_auth_required_row() {
    let echo = EchoServer::start(EchoMode::Elite, 200);
    let socks = Socks5Mock::requiring("Admin", "p+ss");
    let dir = TestDir::new("socks5_wrong_credentials");
    let input = dir.path().join("input.txt");
    std::fs::write(
        &input,
        format!("socks5://Admin:wrong@127.0.0.1:{}\n", socks.addr.port()),
    )
    .unwrap();
    let output = common::run(
        common::command(&dir)
            .arg("-i")
            .arg(&input)
            .arg("--check-url")
            .arg(format!("http://{}/ip", echo.addr)),
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let rows = records(&dir.path().join("proxies.jsonl"));
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0]["tags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tag| tag == "auth-required")
    );
    assert!(stdout(&output).contains("auth 1"));
}

#[test]
fn http_407_produces_auth_required_row() {
    let echo = EchoServer::start(EchoMode::Elite, 200);
    let proxy = HttpProxyMock::unauthorized();
    let dir = TestDir::new("http_407");
    let input = dir.path().join("input.txt");
    std::fs::write(&input, format!("127.0.0.1:{}\n", proxy.addr.port())).unwrap();
    let output = common::run(
        common::command(&dir)
            .arg("-i")
            .arg(&input)
            .arg("--check-url")
            .arg(format!("http://{}/ip", echo.addr)),
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let rows = records(&dir.path().join("proxies.jsonl"));
    assert!(
        rows[0]["tags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tag| tag == "auth-required")
    );
}

#[test]
fn dead_port_has_dead_summary_and_no_jsonl_row() {
    assert!(
        TcpStream::connect(("127.0.0.1", 1)).is_err(),
        "port 1 unexpectedly has a listener — dead-port contract not testable in this environment"
    );
    let echo = EchoServer::start(EchoMode::Elite, 200);
    // No mock binds below 1024, so this port cannot be stolen between an
    // ephemeral-port allocation and the child dial.
    let port = 1;
    let dir = TestDir::new("dead_port");
    let input = dir.path().join("input.txt");
    std::fs::write(&input, format!("127.0.0.1:{port}\n")).unwrap();
    let output = common::run(
        common::command(&dir)
            .arg("-i")
            .arg(&input)
            .arg("--check-url")
            .arg(format!("http://{}/ip", echo.addr)),
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("dead 1"), "{}", stdout(&output));
    assert!(records(&dir.path().join("proxies.jsonl")).is_empty());
    assert_eq!(echo.accepts(), 1); // only the startup shape-check
}

#[test]
fn comment_line_is_not_dialed() {
    let echo = EchoServer::start(EchoMode::Elite, 200);
    let proxy = HttpProxyMock::open("127.0.0.1");
    let dir = TestDir::new("comment_not_dialed");
    let input = dir.path().join("input.txt");
    std::fs::write(
        &input,
        format!(
            "# 127.0.0.1:{}\n127.0.0.1:{}\n",
            proxy.addr.port(),
            proxy.addr.port()
        ),
    )
    .unwrap();
    let output = common::run(
        common::command(&dir)
            .arg("-i")
            .arg(&input)
            .arg("--check-url")
            .arg(format!("http://{}/ip", echo.addr)),
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(proxy.accepts(), 1);
    assert!(stdout(&output).contains("1 kept"));
}

#[test]
fn hostname_only_input_is_parsed_but_never_dialed() {
    let echo = EchoServer::start(EchoMode::Elite, 200);
    let proxy = HttpProxyMock::open("127.0.0.1");
    let dir = TestDir::new("hostname_not_dialed");
    let input = dir.path().join("input.txt");
    std::fs::write(&input, format!("localhost:{}\n", proxy.addr.port())).unwrap();
    let output = common::run(
        common::command(&dir)
            .arg("-i")
            .arg(&input)
            .arg("--check-url")
            .arg(format!("http://{}/ip", echo.addr)),
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("0 kept"), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("1 hostname lines"),
        "{}",
        stdout(&output)
    );
    assert_eq!(proxy.accepts(), 0);
    assert_eq!(echo.accepts(), 1);
}

#[test]
fn nan_timeout_is_clean_cli_error_not_panic() {
    let dir = TestDir::new("nan_timeout");
    let input = dir.path().join("input.txt");
    std::fs::write(&input, b"127.0.0.1:1\n").unwrap();
    let output = common::run(
        Command::new(env!("CARGO_BIN_EXE_proxalyze"))
            .arg("--backup-url")
            .arg("")
            .arg("-i")
            .arg(&input)
            .arg("--out")
            .arg(dir.path())
            .arg("--timeout=NaN"),
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("--timeout must be a finite"));
    assert!(!stderr(&output).contains("panicked"));
}

#[test]
fn closed_debug_stderr_pipe_still_writes_reports() {
    let echo = EchoServer::start(EchoMode::Elite, 200);
    let live_proxy = HttpProxyMock::open("127.0.0.1");
    let silent_proxy = SilentProxy::start();
    let dir = TestDir::new("closed_debug_stderr");
    let input = dir.path().join("input.txt");
    std::fs::write(
        &input,
        format!(
            "127.0.0.1:{}\n127.0.0.1:{}\n",
            live_proxy.addr.port(),
            silent_proxy.addr.port()
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_proxalyze"))
        .arg("--backup-url")
        .arg("")
        .arg("--workers")
        .arg("2")
        .arg("--out")
        .arg(dir.path())
        .arg("-i")
        .arg(&input)
        .arg("--check-url")
        .arg(format!("http://{}/ip", echo.addr))
        .arg("--debug")
        .arg("--timeout")
        .arg("2.0")
        .arg("--connect-timeout")
        .arg("0.5")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout_pipe = child.stdout.take().unwrap();
    let mut stderr_pipe = child.stderr.take().unwrap();
    let mut startup = [0u8; 5];
    stderr_pipe.read_exact(&mut startup).unwrap();
    // With a two-second total timeout, the parent must be descheduled for
    // roughly 1.9s between this read and the adjacent drop for ordering to
    // invert. That accepted residual can only make the test vacuous: the late
    // guarded write would find an already-closed pipe either way, while a raw
    // eprintln! panic would lose the result and trip the 2/2 integrity gate.
    drop(stderr_pipe);
    let mut stdout_bytes = Vec::new();
    stdout_pipe.read_to_end(&mut stdout_bytes).unwrap();
    let status = child.wait().unwrap();
    let summary = String::from_utf8_lossy(&stdout_bytes);
    assert!(
        status.success(),
        "child failed after stderr was closed: {status}; summary:\n{summary}"
    );
    assert!(summary.contains("integrity 2/2"), "{summary}");
    assert!(dir.path().join("proxies.txt").exists());
    let rows = records(&dir.path().join("proxies.jsonl"));
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["anonymity"], "elite");
}

#[test]
fn zero_candidates_leave_sentinel_output_untouched() {
    let echo = EchoServer::start(EchoMode::Elite, 200);
    let dir = TestDir::new("zero_candidate_sentinel");
    let input = dir.path().join("input.txt");
    let sentinel = dir.path().join("proxies.txt");
    std::fs::write(&input, b"proxy.invalid:8080\n").unwrap();
    std::fs::write(&sentinel, b"operator sentinel\n").unwrap();
    let output = common::run(
        common::command(&dir)
            .arg("-i")
            .arg(&input)
            .arg("--check-url")
            .arg(format!("http://{}/ip", echo.addr)),
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"operator sentinel\n");
    assert!(
        stdout(&output)
            .lines()
            .any(|line| { line == "[write ] 0 candidates · existing outputs left untouched" })
    );
}

#[test]
fn http_credentials_preserve_case_and_symbols_on_the_wire() {
    let echo = EchoServer::start(EchoMode::Elite, 200);
    let proxy = HttpProxyMock::requiring_auth("Admin", "p+ss", "127.0.0.1");
    let dir = TestDir::new("http_credentials_wire");
    let input = dir.path().join("input.txt");
    std::fs::write(
        &input,
        format!("http://Admin:p+ss@127.0.0.1:{}\n", proxy.addr.port()),
    )
    .unwrap();
    let output = common::run(
        common::command(&dir)
            .arg("-i")
            .arg(&input)
            .arg("--check-url")
            .arg(format!("http://{}/ip", echo.addr)),
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let rows = records(&dir.path().join("proxies.jsonl"));
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["anonymity"], "elite");
}

#[test]
fn live_output_files_are_owner_only() {
    let echo = EchoServer::start(EchoMode::Elite, 200);
    let proxy = HttpProxyMock::open("127.0.0.1");
    let dir = TestDir::new("output_permissions");
    let input = dir.path().join("input.txt");
    std::fs::write(&input, format!("127.0.0.1:{}\n", proxy.addr.port())).unwrap();
    let output = common::run(
        common::command(&dir)
            .arg("-i")
            .arg(&input)
            .arg("--check-url")
            .arg(format!("http://{}/ip", echo.addr)),
    );
    assert!(output.status.success(), "{}", stderr(&output));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for name in ["proxies.txt", "proxies.jsonl"] {
            let mode = std::fs::metadata(dir.path().join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{name} mode {mode:o}");
        }
    }
}

#[test]
fn min_live_five_returns_three_when_only_one_lives() {
    let echo = EchoServer::start(EchoMode::Elite, 200);
    let proxy = HttpProxyMock::open("127.0.0.1");
    let dir = TestDir::new("min_live_five");
    let input = dir.path().join("input.txt");
    std::fs::write(&input, format!("127.0.0.1:{}\n", proxy.addr.port())).unwrap();
    let output = common::run(
        common::command(&dir)
            .arg("-i")
            .arg(&input)
            .arg("--check-url")
            .arg(format!("http://{}/ip", echo.addr))
            .arg("--min-live")
            .arg("5"),
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(stderr(&output).contains("min-live: 1 live < required 5"));
}

#[test]
fn query_string_survives_socks5_tunnel() {
    let echo = EchoServer::start(EchoMode::Elite, 200);
    let socks = Socks5Mock::no_auth();
    let dir = TestDir::new("socks_query_retention");
    let input = dir.path().join("input.txt");
    std::fs::write(
        &input,
        format!("socks5://127.0.0.1:{}\n", socks.addr.port()),
    )
    .unwrap();
    let output = common::run(
        common::command(&dir)
            .arg("-i")
            .arg(&input)
            .arg("--check-url")
            .arg(format!("http://{}/ip?probe=1", echo.addr)),
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        records(&dir.path().join("proxies.jsonl"))[0]["anonymity"],
        "elite"
    );
    assert!(
        echo.targets()
            .iter()
            .any(|target| target.ends_with("/ip?probe=1")),
        "recorded targets: {:?}",
        echo.targets()
    );
}

#[test]
fn target_503_increments_slot_error_summary() {
    let echo = EchoServer::start(EchoMode::Elite, 200);
    let proxy = HttpProxyMock::unavailable();
    let dir = TestDir::new("target_error_503");
    let input = dir.path().join("input.txt");
    std::fs::write(&input, format!("127.0.0.1:{}\n", proxy.addr.port())).unwrap();
    let output = common::run(
        common::command(&dir)
            .arg("-i")
            .arg(&input)
            .arg("--check-url")
            .arg(format!("http://{}/ip", echo.addr)),
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("target-err 1"),
        "{}",
        stdout(&output)
    );
    assert!(records(&dir.path().join("proxies.jsonl")).is_empty());
}

#[test]
fn dropping_a_mock_releases_its_listener() {
    let addr = {
        let proxy = HttpProxyMock::open("127.0.0.1");
        proxy.addr
    };
    let mut released = false;
    for _ in 0..20 {
        if TcpStream::connect(addr).is_err() {
            released = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(released, "mock listener still owns {addr}");
}
