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
    let commented_proxy = HttpProxyMock::open("127.0.0.1");
    let live_proxy = HttpProxyMock::open("127.0.0.1");
    let dir = TestDir::new("comment_not_dialed");
    let input = dir.path().join("input.txt");
    std::fs::write(
        &input,
        format!(
            "# 127.0.0.1:{}\n127.0.0.1:{}\n",
            commented_proxy.addr.port(),
            live_proxy.addr.port()
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
    assert_eq!(commented_proxy.accepts(), 0);
    assert_eq!(live_proxy.accepts(), 1);
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
    // The startup bytes are only a synchronization point after child stderr is
    // live; the silent proxy's late debug failure is the EPIPE subject. With a
    // two-second total timeout, the parent must be descheduled for roughly
    // 1.9s between this read and the adjacent drop for ordering to invert. That
    // accepted residual can only make the test vacuous: the late guarded write
    // would find an already-closed pipe either way, while a raw eprintln! panic
    // would lose the result and trip the 2/2 integrity gate.
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
    let targets = echo.targets();
    // targets[0] is the direct startup shape-check; the SOCKS5 probe is only
    // evidence when a distinct post-startup request retained the query.
    assert!(targets.len() >= 2, "recorded targets: {targets:?}");
    assert!(
        targets[1..]
            .iter()
            .any(|target| target.ends_with("/ip?probe=1")),
        "recorded targets: {targets:?}"
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

// ---------------------------------------------------------------------------
// Task 6: integration + regression coverage for the extensions plan (write-stage
// filters, extra output formats, cross-run stability, throughput + capability
// probes). Every peer is a 127.0.0.1 mock; `common::run_with` supplies
// `--backup-url ""` and the short timeouts.
// ---------------------------------------------------------------------------

/// Two live elite proxies. A hermetic run has no GeoLite2 database, so the
/// `hosting` tag the geo judge would produce is planted by hand instead.
fn filters_fixture(name: &str) -> (EchoServer, HttpProxyMock, HttpProxyMock, TestDir) {
    let echo = EchoServer::start(EchoMode::Elite, 200);
    let first = HttpProxyMock::open("127.0.0.1");
    let second = HttpProxyMock::open("127.0.0.1");
    let dir = TestDir::new(name);
    let input = dir.path().join("input.txt");
    std::fs::write(
        &input,
        format!(
            "127.0.0.1:{}\n127.0.0.1:{}\n",
            first.addr.port(),
            second.addr.port()
        ),
    )
    .unwrap();
    // BOTH mocks must be returned: a dropped one releases its listener and
    // the input line pointing at it is then a dead candidate.
    (echo, first, second, dir)
}

/// Add one tag to every record of the pool on disk, so the next run starts
/// from a prior pool without dialing anything.
fn plant_tag(dir: &TestDir, tag: &str) {
    let path = dir.path().join("proxies.jsonl");
    let body = std::fs::read_to_string(&path).unwrap();
    let mut lines = Vec::new();
    for line in body.lines() {
        let mut value: serde_json::Value = serde_json::from_str(line).unwrap();
        let mut tags = tags_of(&value);
        tags.push(tag.to_owned());
        value["tags"] = serde_json::json!(tags);
        lines.push(serde_json::to_string(&value).unwrap());
    }
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();
}

fn tags_of(row: &serde_json::Value) -> Vec<String> {
    row["tags"]
        .as_array()
        .map(|tags| {
            tags.iter()
                .filter_map(|tag| tag.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn is_tagged(row: &serde_json::Value, tag: &str) -> bool {
    tags_of(row).iter().any(|owned| owned == tag)
}

/// `--check-url` for the mock echo, as a borrowed str for a `run_with` arg.
fn check_url(echo: &EchoServer) -> String {
    format!("http://{}/ip", echo.addr)
}

#[test]
fn filter_to_zero_writes_empty_and_min_live_exits_3() {
    let echo = EchoServer::start(EchoMode::Elite, 200);
    let proxy = HttpProxyMock::open("127.0.0.1");
    let dir = TestDir::new("filter_to_zero");
    let input = dir.path().join("input.txt");
    std::fs::write(&input, format!("127.0.0.1:{}\n", proxy.addr.port())).unwrap();
    let url = check_url(&echo);
    let output = common::run_with(
        &dir,
        &[
            "-i",
            input.to_str().unwrap(),
            "--check-url",
            &url,
            // No mock emits a residential-proxy tag, so the require gate
            // empties the pool.
            "--require-tag",
            "residential-proxy",
            "--min-live",
            "1",
        ],
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(
        stderr(&output).contains("min-live: 0 live < required 1"),
        "{}",
        stderr(&output)
    );
    for name in ["proxies.txt", "proxies.jsonl"] {
        let path = dir.path().join(name);
        assert!(path.exists(), "{name} must be written even when empty");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0, "{name} size");
    }
}

#[test]
fn reused_pool_filtered_to_zero_writes_empty_files() {
    let echo = EchoServer::start(EchoMode::Elite, 200);
    let proxy = HttpProxyMock::open("127.0.0.1");
    let dir = TestDir::new("reused_filtered_to_zero");
    let input = dir.path().join("input.txt");
    std::fs::write(&input, format!("127.0.0.1:{}\n", proxy.addr.port())).unwrap();
    let url = check_url(&echo);
    let first = common::run_with(
        &dir,
        &[
            "-i",
            input.to_str().unwrap(),
            "--check-url",
            &url,
            "-j",
            "1",
        ],
    );
    assert!(first.status.success(), "{}", stderr(&first));
    assert_eq!(records(&dir.path().join("proxies.jsonl")).len(), 1);

    // The candidate line stays, so `--skip-recent` reuses it: the second run
    // has zero candidates to PROBE and a non-empty pooled set. The write
    // guard keys on that pre-filter set, so it must write empties rather
    // than take the "0 candidates" branch.
    let output = common::run_with(
        &dir,
        &[
            "-i",
            input.to_str().unwrap(),
            "--check-url",
            &url,
            "--skip-recent",
            "999999",
            "--require-tag",
            "residential-proxy",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        !stdout(&output).contains("existing outputs left untouched"),
        "a pooled run must not take the zero-candidate branch: {}",
        stdout(&output)
    );
    for name in ["proxies.txt", "proxies.jsonl"] {
        let path = dir.path().join(name);
        assert!(path.exists(), "{name} must be rewritten");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0, "{name} size");
    }
}

#[test]
fn legacy_prior_jsonl_carries_forward_with_runs_live_default() {
    let echo = EchoServer::start(EchoMode::Elite, 200);
    let proxy = HttpProxyMock::open("127.0.0.1");
    let dir = TestDir::new("legacy_prior_jsonl");
    let input = dir.path().join("input.txt");
    std::fs::write(&input, format!("127.0.0.1:{}\n", proxy.addr.port())).unwrap();
    let url = check_url(&echo);
    let first = common::run_with(
        &dir,
        &[
            "-i",
            input.to_str().unwrap(),
            "--check-url",
            &url,
            "-j",
            "1",
        ],
    );
    assert!(first.status.success(), "{}", stderr(&first));

    // A pre-upgrade row: no runs_live, no kbps, no speed_tier.
    let path = dir.path().join("proxies.jsonl");
    let mut legacy: serde_json::Value =
        serde_json::from_str(std::fs::read_to_string(&path).unwrap().trim()).unwrap();
    let object = legacy.as_object_mut().unwrap();
    for key in ["runs_live", "kbps", "speed_tier"] {
        object.remove(key);
    }
    std::fs::write(&path, format!("{legacy}\n")).unwrap();

    let output = common::run_with(
        &dir,
        &[
            "-i",
            input.to_str().unwrap(),
            "--check-url",
            &url,
            "--skip-recent",
            "999999",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        !stderr(&output).contains("prior records unreadable"),
        "a legacy row must decode: {}",
        stderr(&output)
    );
    assert!(
        stdout(&output).contains("reused 1 fresh"),
        "{}",
        stdout(&output)
    );
    let rows = records(&path);
    assert_eq!(rows.len(), 1);
    // Decode default 1 + this run's chain increment. EXACTLY 2 pins that a
    // reused record is assigned from the prior pool, never incremented on top
    // of the value it already carried.
    assert_eq!(rows[0]["runs_live"], 2, "row: {}", rows[0]);
}

#[test]
fn stable_tag_appears_on_second_consecutive_live_run() {
    let echo = EchoServer::start(EchoMode::Elite, 200);
    let proxy = HttpProxyMock::open("127.0.0.1");
    let dir = TestDir::new("stable_tag_chain");
    let input = dir.path().join("input.txt");
    std::fs::write(&input, format!("127.0.0.1:{}\n", proxy.addr.port())).unwrap();
    let url = check_url(&echo);
    let run = || {
        common::run_with(
            &dir,
            &[
                "-i",
                input.to_str().unwrap(),
                "--check-url",
                &url,
                "--stable-after",
                "2",
            ],
        )
    };
    let path = dir.path().join("proxies.jsonl");

    let first = run();
    assert!(first.status.success(), "{}", stderr(&first));
    let rows = records(&path);
    assert_eq!(rows.len(), 1);
    assert!(!is_tagged(&rows[0], "stable"), "row: {}", rows[0]);

    let second = run();
    assert!(second.status.success(), "{}", stderr(&second));
    let rows = records(&path);
    assert_eq!(rows[0]["runs_live"], 2);
    assert!(is_tagged(&rows[0], "stable"), "row: {}", rows[0]);

    // Dead gap: the record vanishes from the prior pool, so the streak breaks.
    std::fs::write(&path, "").unwrap();
    let third = run();
    assert!(third.status.success(), "{}", stderr(&third));
    let rows = records(&path);
    assert_eq!(rows[0]["runs_live"], 1);
    assert!(!is_tagged(&rows[0], "stable"), "row: {}", rows[0]);
}

#[test]
fn default_run_has_no_probe_fields() {
    let echo = EchoServer::start(EchoMode::Elite, 200);
    let proxy = HttpProxyMock::open("127.0.0.1");
    let dir = TestDir::new("default_no_probe_fields");
    let input = dir.path().join("input.txt");
    std::fs::write(&input, format!("127.0.0.1:{}\n", proxy.addr.port())).unwrap();
    let url = check_url(&echo);
    let output = common::run_with(
        &dir,
        &[
            "-i",
            input.to_str().unwrap(),
            "--check-url",
            &url,
            "-j",
            "1",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let rows = records(&dir.path().join("proxies.jsonl"));
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert!(row.get("kbps").is_none(), "kbps leaked: {row}");
    assert!(row.get("speed_tier").is_none(), "speed_tier leaked: {row}");
    // runs_live is the one always-present counter, even on a default run.
    assert_eq!(row["runs_live"], 1);
    for tag in ["stable", "chunked-post", "keep-alive"] {
        assert!(
            !is_tagged(row, tag),
            "default run must not carry {tag}: {row}"
        );
    }
    // No flag, no follow-ups: the mock saw no second request head.
    assert_eq!(proxy.keepalive_hits(), 0);
}

#[test]
fn throughput_large_body_yields_kbps_not_oversized() {
    // Twice the 256 KiB sample cap, so the probe must stop at the cap rather
    // than report the body as oversized.
    const BIG: usize = 512 * 1024;
    let echo = EchoServer::start_with_big_body(EchoMode::Elite, BIG);
    let proxy = HttpProxyMock::open("127.0.0.1");
    let dir = TestDir::new("throughput_big_body");
    let input = dir.path().join("input.txt");
    std::fs::write(&input, format!("127.0.0.1:{}\n", proxy.addr.port())).unwrap();
    let url = check_url(&echo);
    let big = format!("http://{}/big", echo.addr);
    let output = common::run_with(
        &dir,
        &[
            "-i",
            input.to_str().unwrap(),
            "--check-url",
            &url,
            "--probe-throughput",
            "--throughput-url",
            &big,
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let rows = records(&dir.path().join("proxies.jsonl"));
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["anonymity"], "elite", "row: {}", rows[0]);
    let kbps = rows[0]["kbps"].as_u64().expect("kbps present");
    assert!(kbps > 0, "kbps must be positive: {kbps}");
    let tier = rows[0]["speed_tier"].as_str().expect("speed_tier present");
    assert!(
        ["fast", "mid", "slow"].contains(&tier),
        "speed_tier: {tier}"
    );
}

#[test]
fn capability_flags_add_tags_and_keep_verdict_live() {
    let echo = EchoServer::start(EchoMode::Elite, 200);
    let proxy = HttpProxyMock::open("127.0.0.1");
    let dir = TestDir::new("capability_tags");
    let input = dir.path().join("input.txt");
    std::fs::write(&input, format!("127.0.0.1:{}\n", proxy.addr.port())).unwrap();
    let url = check_url(&echo);
    let output = common::run_with(
        &dir,
        &[
            "-i",
            input.to_str().unwrap(),
            "--check-url",
            &url,
            "--probe-capabilities",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("integrity 1/1 results ✓"),
        "the probe must not change the verdict: {}",
        stdout(&output)
    );
    let rows = records(&dir.path().join("proxies.jsonl"));
    assert_eq!(rows.len(), 1);
    assert!(is_tagged(&rows[0], "keep-alive"), "row: {}", rows[0]);
    assert!(is_tagged(&rows[0], "chunked-post"), "row: {}", rows[0]);
    assert_eq!(rows[0]["anonymity"], "elite", "row: {}", rows[0]);

    // The follow-ups rode ONE connection: the mock saw a second and a third
    // request head on the same stream, which only its request loop can serve.
    assert_eq!(
        proxy.keepalive_hits(),
        1,
        "follow-ups must reuse the check connection"
    );
    // The chunked proof is a real `Transfer-Encoding: chunked` request head
    // on the forward path: primary GET, keep-alive GET, chunked POST.
    let captured = proxy.wait_for_requests(3, std::time::Duration::from_secs(2));
    assert!(
        captured.iter().any(|request| request.method == "POST"),
        "the chunked-POST follow-up must reach the proxy: {captured:?}"
    );
    assert!(
        captured.iter().any(|request| request
            .transfer_encoding
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))),
        "no chunked request recorded: {captured:?}"
    );
    // The mock's own request loop, not a per-request dial: one connection
    // carried all three heads.
    assert_eq!(proxy.accepts(), 1, "captured: {captured:?}");
}

#[test]
fn csv_and_curl_written_and_filter_counts_shown() {
    let (echo, _first, _second, dir) = filters_fixture("csv_and_curl");
    let input = dir.path().join("input.txt");
    let url = check_url(&echo);
    let args = [
        "-i",
        input.to_str().unwrap(),
        "--check-url",
        &url,
        "-j",
        "1",
        "--csv",
        "--emit",
        "curl",
        "--exclude-tag",
        "hosting",
    ];
    let first = common::run_with(&dir, &args);
    assert!(first.status.success(), "{}", stderr(&first));
    let unfiltered = records(&dir.path().join("proxies.jsonl"));
    assert_eq!(unfiltered.len(), 2);
    let csv = std::fs::read_to_string(dir.path().join("proxies.csv")).unwrap();
    let curl = std::fs::read_to_string(dir.path().join("proxies.curl")).unwrap();
    assert_eq!(
        csv.lines().count(),
        unfiltered.len() + 1,
        "header plus one row per record"
    );
    assert_eq!(curl.lines().count(), unfiltered.len());
    assert!(
        stdout(&first).contains("filters   kept 2 · dropped 0"),
        "{}",
        stdout(&first)
    );

    // A second REAL run, so the records are freshly derived. Its `hosting`
    // tag can only come from a GeoLite2 database, which a hermetic test
    // cannot have — so the formats and the summary must still agree with
    // each other at the pre-filter count.
    let second = common::run_with(&dir, &args);
    assert!(second.status.success(), "{}", stderr(&second));
    let kept = records(&dir.path().join("proxies.jsonl"));
    assert_eq!(kept.len(), 2);
    let csv = std::fs::read_to_string(dir.path().join("proxies.csv")).unwrap();
    let curl = std::fs::read_to_string(dir.path().join("proxies.curl")).unwrap();
    assert_eq!(csv.lines().count(), kept.len() + 1);
    assert_eq!(curl.lines().count(), kept.len());
    assert!(
        stdout(&second).contains("filters   kept 2 · dropped 0"),
        "{}",
        stdout(&second)
    );
}

#[test]
fn require_and_exclude_same_tag_via_cli_drops_everything() {
    let (echo, _first, _second, dir) = filters_fixture("require_exclude_same_tag");
    let input = dir.path().join("input.txt");
    let url = check_url(&echo);
    let first = common::run_with(
        &dir,
        &[
            "-i",
            input.to_str().unwrap(),
            "--check-url",
            &url,
            "-j",
            "1",
        ],
    );
    assert!(first.status.success(), "{}", stderr(&first));
    plant_tag(&dir, "hosting");

    // `--skip-recent` reuses the planted pool, so the filter sees the
    // `hosting` tag a real run would have re-derived from the geo database.
    let output = common::run_with(
        &dir,
        &[
            "-i",
            input.to_str().unwrap(),
            "--check-url",
            &url,
            "--skip-recent",
            "999999",
            "--require-tag",
            "hosting",
            "--exclude-tag",
            "hosting",
        ],
    );
    // No --min-live, so an empty pool is a normal successful run.
    assert!(output.status.success(), "{:?}", output.status.code());
    assert!(records(&dir.path().join("proxies.jsonl")).is_empty());
    assert_eq!(
        std::fs::metadata(dir.path().join("proxies.txt"))
            .unwrap()
            .len(),
        0
    );
    assert!(
        stdout(&output).contains("filters   kept 0 · dropped 2"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn keep_top_zero_via_cli_empties_pool() {
    let (echo, _first, _second, dir) = filters_fixture("keep_top_zero");
    let input = dir.path().join("input.txt");
    let url = check_url(&echo);
    let output = common::run_with(
        &dir,
        &[
            "-i",
            input.to_str().unwrap(),
            "--check-url",
            &url,
            "-j",
            "1",
            "--keep-top",
            "0",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(records(&dir.path().join("proxies.jsonl")).is_empty());
    assert_eq!(
        std::fs::metadata(dir.path().join("proxies.txt"))
            .unwrap()
            .len(),
        0
    );
    assert!(
        stdout(&output).contains("filters   kept 0 · dropped 2"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn emit_rejects_unknown_format() {
    let echo = EchoServer::start(EchoMode::Elite, 200);
    let proxy = HttpProxyMock::open("127.0.0.1");
    let dir = TestDir::new("emit_unknown_format");
    let input = dir.path().join("input.txt");
    std::fs::write(&input, format!("127.0.0.1:{}\n", proxy.addr.port())).unwrap();
    let url = check_url(&echo);
    let output = common::run_with(
        &dir,
        &[
            "-i",
            input.to_str().unwrap(),
            "--check-url",
            &url,
            "--emit",
            "wget",
        ],
    );
    assert_eq!(output.status.code(), Some(1));
    let message = stderr(&output);
    assert!(message.contains("curl"), "must list curl: {message}");
    assert!(
        message.contains("playwright"),
        "must list playwright: {message}"
    );
    assert!(!message.contains("panicked"), "{message}");
    // Config validation precedes every dial, so nothing was written.
    assert!(!dir.path().join("proxies.jsonl").exists());
}

#[test]
fn keep_top_truncates_output_and_summary_counts() {
    let (echo, _first, _second, dir) = filters_fixture("keep_top_one");
    let input = dir.path().join("input.txt");
    let url = check_url(&echo);
    let output = common::run_with(
        &dir,
        &[
            "-i",
            input.to_str().unwrap(),
            "--check-url",
            &url,
            "-j",
            "1",
            "--keep-top",
            "1",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let rows = records(&dir.path().join("proxies.jsonl"));
    assert_eq!(rows.len(), 1, "row: {}", rows[0]);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("proxies.txt"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    assert!(
        stdout(&output).contains("filters   kept 1 · dropped 1"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn history_jsonl_appends_across_two_runs_and_delta_is_correct() {
    let echo = EchoServer::start(EchoMode::Elite, 200);
    let survivor = HttpProxyMock::open("127.0.0.1");
    let leaving = HttpProxyMock::open("127.0.0.1");
    let dir = TestDir::new("history_delta");
    let both = dir.path().join("both.txt");
    std::fs::write(
        &both,
        format!(
            "127.0.0.1:{}\n127.0.0.1:{}\n",
            survivor.addr.port(),
            leaving.addr.port()
        ),
    )
    .unwrap();
    let one = dir.path().join("one.txt");
    std::fs::write(&one, format!("127.0.0.1:{}\n", survivor.addr.port())).unwrap();
    let url = check_url(&echo);
    let run = |list: &Path| {
        common::run_with(
            &dir,
            &[
                "-i",
                list.to_str().unwrap(),
                "--check-url",
                &url,
                "--history",
            ],
        )
    };
    // A two-proxy pool, then a one-proxy pool: the second row must report
    // exactly one removal and no additions.
    let first = run(&both);
    assert!(first.status.success(), "{}", stderr(&first));
    let second = run(&one);
    assert!(second.status.success(), "{}", stderr(&second));

    let history = records(&dir.path().join("history.jsonl"));
    assert_eq!(history.len(), 2, "history must append, not rewrite");
    assert_eq!(history[0]["pool_size"], 2);
    assert_eq!(history[1]["pool_size"], 1);
    assert_eq!(history[1]["added"], 0);
    assert_eq!(history[1]["removed"], 1);
    for row in &history {
        // 17 fields, all always written: a consumer never has to tell
        // "absent" from "zero".
        assert_eq!(row.as_object().unwrap().len(), 17, "row: {row}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.path().join("history.jsonl"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "history mode {mode:o}");
    }
}
