# Proxalyze Gap-Sweep Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all verified bugs and implement all agreed gap/improvement items from the 2026-09-24 audit of proxalyze (commit 29d1ba1), preserving the project's existing design philosophy (declared schemes, raw output, no derived grades, measurement-honesty).

**Architecture:** Single-crate Rust binary (edition 2024). No new runtime dependencies; only std + existing deps (http-body-util::Limited for bounded reads). Changes span parse → config → validate → model/geo → output → main layers plus a new `tests/` integration suite (binary is bin-only; tests spawn the compiled binary, no lib target added).

**Tech stack:** Rust 1.98, tokio, hyper, clap 4, serde_json, maxminddb. Verification: `cargo test --locked`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo fmt --all -- --check`.

**License decision (user-confirmed):** MIT.

**Branch:** `fix/proxalyze-gap-sweep` (controller-owned; implementers never commit).

**Line references** below are as-of base commit 29d1ba1; re-locate by symbol if drift occurs.

---

## Batch Map (file-isolation enforced; max 3 parallel)

| Batch | Tasks | Files owned |
|---|---|---|
| 1 | A, B, C | A: parse.rs + main.rs(load/summary/flag) · B: config.rs · C: output.rs |
| 2 | E, F, G1 | E: validate.rs · F: LICENSE+Cargo.toml+.github · G1: model.rs+geo.rs+config.rs+main.rs(build/summary)+output tests+examples |
| 3 | G2 | main.rs (+ small log extraction touching validate.rs — sequential after E) |
| 4 | J, K | J: main.rs+output.rs · K (Tester agent): tests/ only |
| 5 | L | README.md |
| final | — | whole-branch review, then finishing-a-development-branch |

Cross-task contracts (stable interfaces tasks share):
- `parse::parse_proxies_stats(body, claim) -> Parsed` where `Parsed { entries: Vec<Entry>, malformed: usize, hosts: Vec<HostEntry> }`; `HostEntry { host: String, port: u16, scheme: Scheme, auth: Option<Auth> }` — defined by A, consumed by G2 (summary) and main load path.
- `Validator::slot_caps(&self) -> Vec<usize>` and per-slot target-error counters (`AtomicU64` per slot, incremented in `probe()` when fail reason starts with `"target status"`) — defined by E, printed by G2 summary.
- `output::read_records(path) -> Result<Vec<LiveRecord>, String>` (jsonl → records via value-interning) — defined by J, reused conceptually by existing output tests.
- `LiveRecord` gains `source: String` and `country: Option<String>` (`skip_serializing_if = "Option::is_none"`) — added by G1; C already merged output.rs so G1 edits its tests sequentially.

---

### Task A: Parse/input layer — credential case, comments, formats, hostname reporting, stdin, dir extensions

**Files:**
- Modify: `src/parse.rs` (scan_prefixed ~:75-101, scan_bare/extend_token ~:140-195, parse_proxies_stats ~:44-63, tests ~:258-386)
- Modify: `src/main.rs` (Cli struct ~:33-76, build_config ~:89-127, load_candidates ~:135-159, expand_inputs ~:162-174, summary inputs loop ~:339-352)

**Verified defects this task fixes:** `Admin:Secret@ip` probed as `admin:secret` (whole-token lowercase at parse.rs:78); `# ip:port` commented lines still probed (f3: 1 kept); `user:p+ss@ip` rewritten to wrong auth `ss@` (keep-set split at `+`); `ip:port:user:pass` → 0 kept (f1); `ip,port` → 0 kept (f2); bare `host:port` lines invisible (0 kept, 0 malformed); `-i -` unsupported; missing-file error lacks filename; dir scan only case-sensitive `.txt`.

- [ ] **Step 1: Define new parse API (failing shape)**

In `src/parse.rs`, add and switch signature (callers updated in Step 6):

```rust
#[derive(Debug, PartialEq, Eq)]
pub struct HostEntry {
    pub host: String,
    pub port: u16,
    pub scheme: Scheme,
    pub auth: Option<Auth>,
}

#[derive(Debug)]
pub struct Parsed {
    pub entries: Vec<Entry>,
    /// declared-but-unparsable garbage (non-host, e.g. octet > 255)
    pub malformed: usize,
    /// proxy-shaped lines whose host is a DNS name (out of contract unless --resolve-hostnames)
    pub hosts: Vec<HostEntry>,
}

pub fn parse_proxies_stats(body: &[u8], claim: Scheme) -> Parsed { ... }
```

- [ ] **Step 2: Write failing tests** (in `src/parse.rs` `mod tests`)

```rust
#[test]
fn credentials_keep_their_case() {
    let out = parse_proxies(b"http://Admin:Secret@1.2.3.4:80\n", Scheme::Http);
    let a = out[0].auth.as_ref().unwrap();
    assert_eq!((a.user.as_str(), a.password.as_deref()), ("Admin", Some("Secret")));
}

#[test]
fn comment_lines_are_never_probed() {
    let body = b"# 9.9.9.9:3128\n; socks5://1.2.3.4:1080\n1.2.3.4:8080\n";
    let p = parse_proxies_stats(body, Scheme::Http);
    assert_eq!(p.entries.len(), 1);
    assert_eq!(p.malformed, 0);
    assert!(p.hosts.is_empty());
}

#[test]
fn symbol_passwords_are_preserved_not_rewritten() {
    let out = parse_proxies(b"user:p+ss#1@1.2.3.4:80\n", Scheme::Http);
    let a = out[0].auth.as_ref().unwrap();
    assert_eq!((a.user.as_str(), a.password.as_deref()), ("user", Some("p+ss#1")));
}

#[test]
fn colon_quad_and_csv_formats_parse() {
    let p = parse_proxies_stats(b"1.2.3.4:8080:root:sec:ret\n5.6.7.8,8080\n", Scheme::Http);
    assert_eq!(p.entries.len(), 2);
    let a = p.entries[0].auth.as_ref().unwrap();
    assert_eq!((a.user.as_str(), a.password.as_deref()), ("root", Some("sec:ret")));
}

#[test]
fn bare_hostnames_are_reported_not_swallowed() {
    let p = parse_proxies_stats(b"proxy.provider-a.net:4145\n", Scheme::Socks5);
    assert!(p.entries.is_empty());
    assert_eq!(p.malformed, 0);
    assert_eq!(p.hosts.len(), 1);
    assert_eq!(p.hosts[0].host, "proxy.provider-a.net");
    assert_eq!(p.hosts[0].scheme, Scheme::Socks5);
}
```

Run: `cargo test --locked parse::` → expect FAIL (no `Parsed`, no behavior).

- [ ] **Step 3: Stop lowercasing tokens** — `src/parse.rs:78`: replace `let tok = String::from_utf8_lossy(&body[s..e]).to_ascii_lowercase();` with `let tok = String::from_utf8_lossy(&body[s..e]);`. `Scheme::from_claim` already lowercases internally (model.rs) — verify `://` split still matches upper-case `HTTP://` (split is on the literal `://`, case-insensitive scheme via from_claim). Keep `extend_token`'s lowercasing or drop it (bare lines carry no auth; `Ipv4Addr`/`IpAddr` parse accepts any case) — dropping is preferred for symmetry.

- [ ] **Step 4: Comment prefilter** — new helper, applied at top of `parse_proxies_stats` to both passes:

```rust
/// Drop lines whose first non-whitespace byte is '#' or ';' (disabled entries).
fn strip_comments(body: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    if !body.iter().any(|&b| b == b'#' || b == b';') {
        return std::borrow::Cow::Borrowed(body);
    }
    let mut out = Vec::with_capacity(body.len());
    let mut line_start = true;
    let mut skip = false;
    for &b in body {
        if line_start && !b.is_ascii_whitespace() {
            skip = b == b'#' || b == b';';
            line_start = false;
        }
        if b == b'\n' { line_start = true; skip = false; }
        if !skip { out.push(b); }
    }
    std::borrow::Cow::Owned(out)
}
```

Wire: `let body_ref: &[u8] = &strip_comments(body);` then run scan_prefixed/scan_bare/host-scan on it. Comment chars are stripped ONLY at line start — `#` inside a kept line survives (needed for Step 5 passwords).

- [ ] **Step 5: Formats** — (a) `scan_prefixed` keep-set: extend to
`b.is_ascii_alphanumeric() || matches!(b, b'.' | b':' | b'/' | b'@' | b'-' | b'_' | b'[' | b']' | b'+' | b'=' | b'%' | b'!' | b'#' | b'$' | b'&' | b'*' | b'(' | b')' | b'~' | b',' | b';')`
(quote chars deliberately excluded; space-separated passwords remain documented-out-of-contract, README updated in L). (b) `scan_bare` keep-set: add `b','` and full `b'a'..=b'z' | b'A'..=b'Z'` so quad/csv/host tokens arrive intact. (c) `extend_token(tok, claim, out, hosts)` logic order: try `parse_addr_str` (unchanged) → try CIDR (unchanged) → try quad: `t.splitn(4, ':')` with 4 parts, `parse_v4_lenient(parts[0])` + `parts[1].parse::<u16>()` → push `Entry { addr, scheme: claim, auth: if parts[2].is_empty() { None } else { Some(Auth { user: parts[2].into(), password: (!parts[3].is_empty()).then(|| parts[3].into()) }) } }` → try csv: `t.split_once(',')` with lenient-v4 + u16 → plain `Entry` → if none, host-shape fallback (Step 6's host scan handles bare host lines separately; extend_token itself just returns). (d) `scan_prefixed` `://` and `@` branches: on `parse_addr_str` failure, if `proxy_ish(hostport)` AND host part contains an ASCII letter → push `HostEntry` (lowercase the DNS name: `host.to_ascii_lowercase()` — hostnames are case-insensitive; creds NOT lowercased) instead of `*mal += 1`; if host part is all-numeric → `*mal += 1` (keeps `999.1.1.1` malformed test green).

- [ ] **Step 6: Bare hostname pass + main wiring** — new line-wise scan in `parse_proxies_stats` over `strip_comments` output: per line, `trim()`, split once on whitespace — if no whitespace, match `host:port` where `port` parses u16 ∈ 1..=65535 and `host` contains a letter and `host.parse::<IpAddr>()` fails and not bracketed-v6 → push `HostEntry { host: host.to_ascii_lowercase(), port, scheme: claim, auth: None }`. Exact-line-only keeps prose (`see example.com:80 docs`) out of the count. Then `src/main.rs`: `load_candidates` destructures `Parsed`; `per_file` tuples become `(label, kept, malformed, hosts_len)` (type annotation updated); summary inputs loop prints host count. `parse_proxies` test wrapper returns `parse_proxies_stats(...).entries`. **Update** existing `declared_malformed_lines_are_counted_once` (parse.rs:324): hostname line moves to `hosts` → `assert_eq!(mal, 2)` + `assert_eq!(p.hosts.len(), 1)`.

- [ ] **Step 7: stdin + dir extensions + error context (main.rs)** — in `load_candidates`: `let body: Vec<u8> = if file.path == "-" { use std::io::Read; let mut b = Vec::new(); std::io::stdin().read_to_end(&mut b)?; b } else { std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))? };` with `expand_inputs` short-circuiting `"-"` → `vec![PathBuf::from("-")]`; label for stdin is `"-"`. `expand_inputs` extension filter: `f.extension().and_then(|x| x.to_str()).is_some_and(|x| matches!(x.to_ascii_lowercase().as_str(), "txt" | "lst" | "csv"))` and error message generalized to `"{path}: directory has no list files (.txt/.lst/.csv)"`.

- [ ] **Step 8: `--resolve-hostnames` flag** — Cli: `/// Resolve hostname:port candidates via DNS at load (one lookup per unique host)\n    #[arg(long)] resolve_hostnames: bool`. In `load_candidates` (async, after entries merged): if flag, for each `HostEntry` (dedup key `host:port:scheme:auth-string` via a local HashSet) run `tokio::net::lookup_host((host.as_str(), port))`, push each resolved addr as `Candidate`; count resolved vs failed. If flag off, hosts are counted-only. Summary line gets: ` · {hosts} hostname lines (skipped: no DNS — pass --resolve-hostnames)` or ` · {resolved} resolved / {failed} unresolved`.

- [ ] **Step 9: Verify** — Run: `cargo test --locked` → all pass; `cargo clippy --all-targets --locked -- -D warnings` → clean; manual: `cargo run --quiet -- -i examples/sample.txt --out /tmp/a-out` still parses 3 kept / 3 malformed(hosts) per new accounting (sample's `x.x.x.x` comment forms are comment lines now — expect them NOT counted: recheck sample counts and update README example in Task L accordingly; sample.txt comments start with `#` so entries stay 3, malformed becomes 0 — record actual numbers for L).

---

### Task B: Config validation — timeout panics + query-string path

**Files:**
- Modify: `src/config.rs` (`Config::check` ~:91-107, `parse_target` ~:129-152, tests ~:164-201)

**Verified defects this task fixes:** `--timeout=NaN` / `--timeout=-5` / `--timeout=1e30` panic inside `Duration::from_secs_f64` (validate.rs:62-63) with rc=101 (134 under release `panic=abort`) instead of a clean CLI error; `--timeout 0` accepted and silently fails every probe; `--check-url 'https://h/p?format=json'` drops `?format=json` on origin-form paths (`config.rs:141-144` takes only `u.path()`) while absolute-form (forward_get) keeps the full raw URL — same flag, different wire bytes per code path.

- [ ] **Step 1: Failing tests** (append to `config.rs` tests mod)

```rust
#[test]
fn timeouts_must_be_finite_and_positive() {
    let mk = |t: f64, ct: f64| {
        let mut c = Config {
            inputs: vec![InputFile { path: "x".into(), scheme: "http".into() }],
            ..Config::default()
        };
        c.validate.timeout = t;
        c.validate.connect_timeout = ct;
        c.check()
    };
    assert!(mk(f64::NAN, 1.0).is_err());
    assert!(mk(f64::INFINITY, 1.0).is_err());
    assert!(mk(-5.0, 1.0).is_err());
    assert!(mk(10.0, f64::NEG_INFINITY).is_err());
    assert!(mk(0.0, 0.0).is_err());
    assert!(mk(10.0, 0.0).is_err());
    assert!(mk(10.0, 2.0).is_ok());
}

#[test]
fn target_path_keeps_query_string() {
    let t = parse_target("https://echo.example/ip?format=json").unwrap();
    assert_eq!(t.path, "/ip?format=json");
    assert_eq!(t.url, "https://echo.example/ip?format=json");
    let t2 = parse_target("https://echo.example").unwrap();
    assert_eq!(t2.path, "/");
}
```

Run: `cargo test --locked config::` → expect FAIL (no validation; path drops query).

- [ ] **Step 2: Implement validation** in `Config::check` (after the concurrency check):

```rust
for (name, v) in [
    ("--timeout", self.validate.timeout),
    ("--connect-timeout", self.validate.connect_timeout),
] {
    if !v.is_finite() || v <= 0.0 {
        return Err(format!("{name} must be a finite number > 0 (got {v})"));
    }
}
if self.validate.connect_timeout > self.validate.timeout {
    return Err(format!(
        "--connect-timeout ({}) must not exceed --timeout ({})",
        self.validate.connect_timeout, self.validate.timeout
    ));
}
```

- [ ] **Step 3: Fix path** in `parse_target`:

```rust
let path = {
    let mut p = u.path().to_string();
    if p.is_empty() {
        p = '/'.into();
    }
    if let Some(q) = u.query() {
        p.push('?');
        p.push_str(q);
    }
    p
};
```

Verify consumers: `forward_get` uses `slot.target.url` (raw, unchanged); `tunneled_get`/`check_shape` use `target.path` (now carries query) — the two paths become byte-identical for the same target. `authority_of` (validate.rs) must NOT include the query — it builds from `t.host`/`t.port`, unaffected.

- [ ] **Step 4: Verify** — `cargo test --locked` all green; manual: `./target/debug/proxalyze -i examples/sample.txt --timeout=NaN --out /tmp/b` → prints `Error: --timeout must be a finite number > 0 (got NaN)`, rc=1 (not 101/134); `--timeout 0` → same style error.

---

### Task C: Output safety — credentials 0600, atomic writes, no unrelated-dir deletion

**Files:**
- Modify: `src/output.rs` (`write_out` ~:62-90, tests ~:95-285)

**Verified defects this task fixes:** outputs containing `user:pass@` credentials written mode 644 (reproduced via `stat`); `File::create` truncates the live output before new content is written (crash mid-write = torn file, and a downstream consumer reading during write sees a partial file); `output.rs:68-71` unconditionally `remove_dir_all("<out>/proxies")` — any unrelated directory named `proxies` under `--out` is destroyed without prompting.

- [ ] **Step 1: Failing tests** (in `output.rs` tests)

```rust
#[test]
fn output_files_are_owner_only() {
    let dir = std::env::temp_dir().join(format!("pxz-perm-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let r = rec("http", "1.2.3.4:80"); // existing test helper builds LiveRecord
    write_out(&dir, &crate::config::Output::default(), std::slice::from_ref(&r)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for f in ["proxies.txt", "proxies.jsonl"] {
            let mode = std::fs::metadata(dir.join(f)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{f} mode {:o}", mode & 0o777);
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unrelated_proxies_dir_is_left_alone() {
    let dir = std::env::temp_dir().join(format!("pxz-stale-{}", std::process::id()));
    let nested = dir.join("proxies");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(nested.join("keep.txt"), b"mine").unwrap();
    write_out(&dir, &crate::config::Output::default(), &[]).unwrap();
    assert!(nested.join("keep.txt").exists(), "unrelated dir was deleted");
    let _ = std::fs::remove_dir_all(&dir);
}
```

Run: `cargo test --locked output::` → expect FAIL (644; nested dir deleted).

- [ ] **Step 2: Implement** — delete the legacy `proxies/` `remove_dir_all` block entirely, replacing with comment: `// Legacy proxies/ dir (pre-two-file format) is intentionally left in place: deleting an operator-named directory is not our call.` Introduce a helper in output.rs:

```rust
fn write_atomic(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::io::BufWriter::new(
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?,
        );
        f.write_all(contents)?;
        f.flush()?;
        f.get_ref().sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}
```

(`#[cfg(not(unix))]` variant without `.mode()` — the crate's release targets are linux/macos but keep it compiling everywhere: gate the `use OpenOptionsExt` + `.mode(0o600)` behind `#[cfg(unix)]` via a tiny `open_opts()` fn returning `std::fs::OpenOptions`.) `write_out` then builds both files into `Vec<u8>` (txt: one proxy per line; jsonl: `serde_json::to_vec(r)` + `\n` per record) and calls `write_atomic` twice; return paths as today.

- [ ] **Step 3: Verify** — `cargo test --locked` all green; `cargo clippy --all-targets --locked -- -D warnings` clean; manual: run against sample, `stat -c %a out/proxies.txt out/proxies.jsonl` → `600 600`.

---

### Task E: Check-lane hardening (validate.rs)

**Files:**
- Modify: `src/validate.rs` (`CheckCfg::from_validate` ~:53-66, `Validator::new` ~:117-176, `run` ~:186-227, `probe` ~:253-345, `request` ~:566-592, `run_conn` ~:674-750, `read_once` ~:813-840, `progress` ~:94-101, tests ~:1085-1175)

**Verified defects this task fixes:** `--debug` + closed stderr pipe kills the whole run — unguarded `eprintln!` at validate.rs:243 (also :130, :158, :164, :173) panics on EPIPE; the panic fires inside the spawned probe task **before** `tx.send`/`done++` (:243-248) so the integrity gate (main.rs:430) then fails the run — rc=1 with outputs MISSING (release: rc=134 via `panic=abort`), vs plain run rc=0 with outputs written; body collected unbounded then size-checked after the fact (validate.rs:704 collect vs :709 `> 64*1024`) — a hostile/enthusiastic target can buffer arbitrarily before rejection; `read_once` has **no timeout at all** (:813-840) — a stalled echo response hangs startup shape-checks forever; `speed_ms` (primary sort key) includes echo-permit queue wait (permit acquired :300-326, `total_ms = start.elapsed()` :333); no `User-Agent` header on probe requests; progress writes `\r` frames into non-TTY stderr; per-slot `Semaphore` sized from pre-drop target count (`targets_len` captured :120 before unhealthy backups are removed) so surviving echoes get under-budgeted permits while summary (main.rs:322-325) recomputes from the raw flag — two sources of truth that both can disagree with reality; mid-run target-side 4xx/5xx land in `tcp-alive` with no per-echo visibility; `-j` floor of 16 silently overrides smaller explicit values (:61).

- [ ] **Step 1: Guarded stderr logging** — add near `progress`:

```rust
/// stderr write that never panics: a closed pipe (`| head`) is a display
/// choice, not a reason to kill a minutes-long run — same contract as qprintln.
macro_rules! qeprintln {
    ($($a:tt)*) => {{
        use std::io::Write;
        let _ = writeln!(std::io::stderr(), $($a)*);
    }};
}
```

Replace all five `eprintln!` sites (:130, :158, :164, :173, :243) with `qeprintln!`. Belt-and-suspenders: in the probe task, move the debug print **after** `tx.send(r).await` + `done.fetch_add` (reorder so even a hypothetical panic in formatting can never cost a result).

- [ ] **Step 2: Failing unit tests** (validate.rs tests mod)

```rust
#[test]
fn user_agent_is_present() {
    assert_eq!(&*user_agent(), concat!("proxalyze/", env!("CARGO_PKG_VERSION")));
}

#[test]
fn slot_cap_respects_low_concurrency() {
    assert_eq!(slot_cap(4, 3), 4.floor_div(3).max(4.min(16))); // see impl note
}
```

Implement `fn user_agent() -> &'static str` used by `request()` as `.header(http::header::USER_AGENT, user_agent())`, and pure `fn slot_cap(concurrency: usize, slots: usize) -> usize` = `concurrency.div_ceil(slots.max(1)).clamp(1, concurrency.max(1))` with the **16 floor applied only when `concurrency >= 16`**: `let floor = if concurrency >= 16 { 16 } else { 1 }; concurrency.div_ceil(slots.max(1)).max(floor).min(concurrency)` — so `-j 4` truly means 4 total (JoinSet gate already caps global in-flight; per-slot caps just must not exceed it). Simplify the test to exact expected values from this formula: `slot_cap(4, 3) == 2` (ceil 4/3=2, floor suppressed), `slot_cap(1024, 3) == 342`, `slot_cap(1024, 1) == 1024`, `slot_cap(4, 1) == 4`. Drop `.max(16)` from `CheckCfg::from_validate` except keep the rlimit-derived `cap` clamp (`want.min(cap).max(1)`); keep a minimum of 1 only. Update the `defaults_are_the_shipped_sweet_spot`-style expectations if any assert the 16 floor (config.rs test asserts `max_concurrent_checks == 512` default — leave that Task-G2's default reconciliation; do not touch config.rs here).

Run: `cargo test --locked validate::` → expect FAIL for new tests.

- [ ] **Step 3: Timeout + limit on `read_once`** — signature gains `budget: Duration`; wrap the whole send+collect in `tokio::time::timeout(budget, …)`; body via `http_body_util::Limited::new(resp.into_body(), 64 * 1024 + 1)` before `.collect()`; map timeout → `("tcp-alive", "shape-check timeout")`, size overflow → `("tcp-alive", "oversized response")`. `check_shape` passes `self.remaining(start)` (it has `start: Instant`).

- [ ] **Step 4: Bounded body in `run_conn`** — replace raw `resp.into_body().collect()` with `http_body_util::Limited::new(resp.into_body(), 64 * 1024 + 1).collect()` inside the existing 1500ms timeout; keep the belt-and-suspenders `body.len() > 64 * 1024` check OR delete it (Limited subsumes it) — delete, with the limit as a named const `const MAX_BODY: usize = 64 * 1024;` used by both sites.

- [ ] **Step 5: speed_ms excludes queue wait** — in `probe()`, capture `let granted = Instant::now();` immediately after permit acquisition succeeds; in the `Ok(mut r)` arm: `r.total_ms = r.connect_ms.saturating_add(granted.elapsed().as_millis() as u32);` (connect + work, no queue). Comment: `// speed_ms = dial + request; echo-permit queue wait is not proxy slowness`.

- [ ] **Step 6: Per-slot counters, caps after health-check, exposure** — restructure `Validator::new`: run `resolve` for all targets (primary-fatal rule unchanged), then shape-check **before** building semaphores (shape-check needs no permit), then build `TargetSlot`s for survivors with `Semaphore::new(slot_cap(cfg.concurrency, survivor_count))`. Add to `TargetSlot`: `pub cap: usize` (the value used) and `errors: Arc<AtomicU64>`. In `probe()`'s `Err(fail)` arm: `if fail.1.starts_with("target status") { slot.errors.fetch_add(1, Ordering::Relaxed); }`. Expose on Validator: `pub fn slot_caps(&self) -> Vec<usize>` and `pub fn slot_errors(&self) -> Vec<u64>`. Keep the degraded-primary path (primary unreachable at startup → warn + continue, no removal) — primary still gets a slot and semaphore; `own_egress` stays `None` as today.

- [ ] **Step 7: Non-TTY progress** — in `run()`'s progress task: `use std::io::IsTerminal; let tty = std::io::stderr().is_terminal();` — if `!tty`, skip every `\r` frame and print only the final completion line (plain, newline-terminated). EPIPE guard stays (covers TTY-redirected-to-closed-pipe).

- [ ] **Step 8: HTTP-target warning** — in `Validator::new` after slots built: `if !targets_have_tls { qeprintln!("[validate] WARNING: --check-url is http:// — a lying proxy can forge the exit-IP body; https targets are certificate-verified"); }` (only when primary slot `target.tls == false`).

- [ ] **Step 9: Verify** — `cargo test --locked` green; clippy clean; **EPIPE repro now passes**: `./target/debug/proxalyze -i examples/sample.txt --debug --connect-timeout 0.05 --timeout 1 --out /tmp/e-out 2>&1 | head -c 5 >/dev/null; echo rc=$?` → `rc=0` AND `/tmp/e-out/proxies.jsonl` exists (previously rc=1, missing); release build same probe → rc=0 (not 134): `cargo build --release --quiet` first.

---

### Task F: License + Cargo metadata + CI

**Files:**
- Create: `LICENSE`
- Modify: `Cargo.toml` ([package] ~:1-6)
- Modify: `.github/workflows/ci.yml`

**Gaps this fixes:** no LICENSE anywhere (public repo, published releases, legally all-rights-reserved; `cargo publish` impossible); Cargo.toml missing `license`/`repository`/`readme`; CI never verifies declared `rust-version = "1.98"` (toolchain is rolling `@stable` only) and only discovers aarch64 breakage at tag time.

- [ ] **Step 1: LICENSE** — standard MIT text, `Copyright (c) 2026 proxalyze contributors`.

- [ ] **Step 2: Cargo.toml [package]** — add:

```toml
license = "MIT"
repository = "https://github.com/rianilham28/proxalyze"
readme = "README.md"
keywords = ["proxy", "validator", "socks", "http", "cli"]
categories = ["command-line-utilities", "network-programming"]
```

- [ ] **Step 3: CI jobs** — append to `ci.yml`:

```yaml
  msrv:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@1.98.0
      - uses: Swatinem/rust-cache@v2
      - run: cargo check --locked --all-targets

  cross-target:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: aarch64-unknown-linux-gnu
      - uses: Swatinem/rust-cache@v2
      - if: ${{ true }}
        run: sudo apt-get update && sudo apt-get install -y gcc-aarch64-linux-gnu
      - env:
          CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER: aarch64-linux-gnu-gcc
        run: cargo check --locked --target aarch64-unknown-linux-gnu
```

(Skip the pointless `if: ${{ true }}` — plain `run:` is fine.) Scope release.yml top-level `permissions: contents: write` down to the `release` job only (move the block under `jobs.release`), least privilege.

- [ ] **Step 4: Verify** — `cargo check --locked` locally; YAML validated by `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml'))"` (or visual review if pyyaml absent); LICENSE present; `cargo package --list --allow-dirty` shows LICENSE + README (metadata sanity).

---

### Task G1: Schema/provenance/stats/geo (LiveRecord.source + country, unjudged bucket)

**Files:**
- Modify: `src/model.rs` (`LiveRecord` ~:99-119, `Stats` ~:121-170)
- Modify: `src/geo.rs` (`Judge` ~:20-80)
- Modify: `src/config.rs` (add `detect_city_db` beside `detect_asn_db` ~:33-49; `Config` gains `city_db: Option<String>`)
- Modify: `src/main.rs` (`build_config` sets `city_db`, `check_all` record construction ~:235-262, `summary` verdict line ~:301-316, `async_main` `Judge::open` call)
- Modify: `src/output.rs` tests (`checked_in_samples_stay_self_consistent` expected-key set ~:215-230, `rec` helper ~:104-120, jsonl-rebuild closure ~:145-165)
- Modify: `examples/out/proxies.jsonl` (regenerate rows with `source`)

**Gaps this fixes:** JSONL has no input provenance — with multiple `-i` files a survivor can't be traced to its source list (`ProbeResult.input` exists but is dropped at record build, main.rs:250); summary verdict folds live-unjudged (anonymity `null`) into the `transparent` count (`model.rs:155-158` `("live", _)`) while output rank treats them as a separate class (`output.rs:41-50` rank 3) — summary and files disagree; `geo/GeoLite2-City.mmdb` sits unused — exit-IP country is the single most-requested proxy filter and emitting it as a *raw fact* (not a judgment) matches the README philosophy.

**Contract with Task A:** uses `r.input` (already populated by `Validator::run`) as `source`. **Contract with G2:** field named `live_unjudged` on `Stats`, `live_total()` includes it (keeps integrity math intact); summary line print of the new bucket happens in G2 (main summary edits split to avoid same-batch file clash — G1 only touches the `check_all`/`async_main`/verdict-count regions; G2 the flag/help/cap regions; sequential batches so no clash).

- [ ] **Step 1: Failing tests**

model.rs (new `#[cfg(test)] mod tests`):

```rust
#[test]
fn live_without_exit_ip_counts_unjudged_not_transparent() {
    use crate::model::{ProbeResult, Stats};
    let mut s = Stats::default();
    let mut r = ProbeResult { proxy: "1.2.3.4:80".into(), scheme: "http", input: "f".into(),
        status: "live", anonymity: None, connect_ms: 1, ttfb_ms: Some(2), total_ms: 3,
        exit_ip: None, slot: 0, fail_reason: None };
    s.record(&r);
    assert_eq!(s.live_unjudged, 1);
    assert_eq!(s.live_transparent, 0);
    assert_eq!(s.live_total(), 1);
    r.anonymity = Some("transparent");
    r.exit_ip = "9.9.9.9".parse().ok();
    s.record(&r);
    assert_eq!(s.live_transparent, 1);
    assert_eq!(s.live_unjudged, 1);
    assert_eq!(s.live_total(), 2);
}
```

geo.rs: `#[test] fn country_absent_without_city_db() { let j = Judge::open(None, None).unwrap(); assert!(j.country("9.9.9.9".parse().unwrap()).is_none()); }` — signature change: `Judge::open(asn: Option<&str>, city: Option<&str>)`.

config.rs: `#[test] fn city_db_auto_detect_shape() { let _ = detect_city_db(); }` (path helper returns Option; no panic).

Run: `cargo test --locked` → FAIL (compile errors = the failing shape).

- [ ] **Step 2: model.rs** — `LiveRecord` gains:

```rust
/// input file (or "-") this proxy was parsed from
pub source: String,
/// ISO country of the exit IP when GeoLite2-City is available
#[serde(skip_serializing_if = "Option::is_none")]
pub country: Option<String>,
```

`Stats` gains `pub live_unjudged: usize;` and `record()` match becomes:

```rust
match (r.status, r.anonymity) {
    ("live", Some("elite")) => self.live_elite += 1,
    ("live", Some("anonymous")) => self.live_anonymous += 1,
    ("live", Some("transparent")) => self.live_transparent += 1,
    ("live", _) => self.live_unjudged += 1,
    ...
}
```

and `live_total()` = elite + anonymous + transparent + **unjudged** (integrity gate keeps passing: unjudged rows are still `status == "live"` records).

- [ ] **Step 3: config.rs `detect_city_db`** — mirror `detect_asn_db` over `["geo/GeoLite2-City.mmdb", "~/.local/share/proxalyze/GeoLite2-City.mmdb"]`; `Config` gains `pub city_db: Option<String>;` set in `build_config` (main.rs).

- [ ] **Step 4: geo.rs** — `Judge { asn: Option<Reader>, city: Option<Reader> }`; `open(asn_path, city_path)`: each `Some(p)` that fails to open is a hard error (same message style as ASN via existing `open_db`), `None` is fine; add `pub fn country(&self, ip: IpAddr) -> Option<String>` → city lookup → `["city"]["country"]["iso_code"]` as str, uppercase-preserved. `locate()` unchanged (ASN judgment untouched — location stays out of judgment).

- [ ] **Step 5: main.rs record build** — in `check_all`:

```rust
records.push(model::LiveRecord {
    proxy: format!("{}://{}", r.scheme, r.proxy),
    type_: r.scheme,
    last_checked: checked_at,
    speed_ms: r.total_ms,
    connect_ms: r.connect_ms,
    ttfb_ms: r.ttfb_ms,
    anonymity: r.anonymity,
    exit_ip: r.exit_ip,
    asn,
    org,
    tags,
    source: r.input.clone(),
    country: r.exit_ip.and_then(|ip| judge.country(ip)),
});
```

`async_main`: `let judge = Judge::open(cfg.asn_db.as_deref(), cfg.city_db.as_deref())?;` and the startup banner geo string shows both (`geo asn+city` / `geo asn` / `geo off`).

- [ ] **Step 6: output.rs test updates + examples regen** — `rec()` helper gains `source: "examples/sample.txt".into(), country: None`; expected-key BTreeSet gains `"source"` (keep `country` in the allowed set since skip-if-none may omit it); the jsonl→LiveRecord rebuild closure reads `r["source"].as_str().unwrap_or("examples/sample.txt")` and sets `country: None`. Regenerate `examples/out/proxies.jsonl`: add `"source":"examples/sample.txt"` to every row (position after `tags` to match struct order — easiest: small python/jq one-liner run by the implementer, or hand-edit the 3 rows; verify with `cargo test --locked checked_in_samples`).

- [ ] **Step 7: Verify** — `cargo test --locked` green (including `checked_in_samples_stay_self_consistent`); clippy clean; manual: `cargo run --quiet -- -i examples/sample.txt --out /tmp/g1 && head -1 /tmp/g1/proxies.jsonl` shows `source` field.

---

### Task G2: CLI UX — error Display, zero-candidate write guard, --min-live, backup-url semantics, summary wiring, help honesty

**Files:**
- Modify: `src/main.rs` (Cli struct ~:33-76, `build_config` ~:89-127, `load_candidates` error sites, `async_main` write phase ~:415-460, `summary` ~:281-360, `main()` ~:364-377)

**Verified defects this fixes:** errors print Debug-quoted (`Error: "..."`, and io errors print `Os { code: 2, … }` with no filename — path context added by Task A's read, but main()'s `Box<dyn Error>` Debug formatting remains); a zero-candidate run (e.g. all-hostname input) **overwrites good previous outputs with empty files and exits 0** (reproduced: 32-byte sentinel → 0 bytes); no machine gate for CI (`--min-live`); `--backup-url A --backup-url ""` discards A too (any-empty clears all, main.rs:108-113); summary "cap" recomputes from raw flag ignoring rlimit clamp and slot reality (main.rs:322-325); no per-echo target-error visibility; `-j` floor not documented in `--help`; `Validate::default().max_concurrent_checks == 512` disagrees with clap default 1024 while test `defaults_are_the_shipped_sweet_spot` pins 512 as "shipped".

**Contract with E:** reads `validator.slot_caps()` / `validator.slot_errors()` — obtained by returning them from `check_all` (extend its return tuple). **Contract with A:** `Parsed { entries, malformed, hosts }` + `--resolve-hostnames` + summary host line already present — G2 does NOT redo those; G2 only adds the items below. **Contract with G1:** prints `live_unjudged` bucket.

- [ ] **Step 1: Failing tests** (main.rs has no test mod today — add one for pure helpers)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_urls_only_cleared_by_bare_empty_flag() {
        assert!(resolve_backup_urls(&[]).len() == 2);           // defaults
        assert!(resolve_backup_urls(&["".into()]).is_empty());   // isolate primary
        assert_eq!(
            resolve_backup_urls(&["https://a.example/x".into(), "".into()]),
            vec!["https://a.example/x".to_string()],
            "mixed: empties dropped, real URLs kept"
        );
        assert_eq!(
            resolve_backup_urls(&["https://a.example/x".into(), "https://b.example/".into()]),
            vec!["https://a.example/x".to_string(), "https://b.example/".to_string()]
        );
    }

    #[test]
    fn min_live_flag_defaults_to_zero() {
        let cli = Cli::parse_from(["proxalyze", "-i", "x.txt"]);
        assert_eq!(cli.min_live, 0);
        let cli = Cli::parse_from(["proxalyze", "-i", "x.txt", "--min-live", "50"]);
        assert_eq!(cli.min_live, 50);
    }
}
```

Extract current backup logic into `fn resolve_backup_urls(user: &[String]) -> Vec<String>`: empty input → defaults (`config::Validate::default().backup_urls`); all entries empty → `vec![]`; otherwise filter out empty entries and return the rest. Run: `cargo test --locked main::` → FAIL (fn missing, flag missing).

- [ ] **Step 2: --min-live + help honesty (Cli)** — add:

```rust
/// Exit non-zero (code 3) when fewer than N live survivors are produced;
/// 0 (default) disables the gate. For CI pipelines that must not accept
/// a silently-empty result.
#[arg(long, default_value_t = 0)]
min_live: usize,
```

`--help` additions: `-j` doc gains `(floor: 16 when -j >= 16; smaller values honored exactly)`; `--timeout` doc gains `(must be finite and > 0)`; `--backup-url` doc gains `("" alone = primary only; mixed with real URLs, empties are ignored)`.

- [ ] **Step 3: Error Display** — change `main()` to:

```rust
fn main() {
    if let Err(e) = run_main() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
fn run_main() -> Result<(), Box<dyn Error>> { /* old main body */ }
```

so errors print via Display (no Debug quotes, no `Os { … }` dumps — Task A already attached filenames at the source). Keep `--min-live` failure path separate: after `summary()` prints, `if cfg.min_live > 0 && stats.live_total() < cfg.min_live { eprintln!("min-live: {live} live < required {need}"); std::process::exit(3); }`.

- [ ] **Step 4: Zero-candidate write guard** — in `async_main`, wrap the write phase:

```rust
if total == 0 {
    qprintln!("[write ] 0 candidates · existing outputs left untouched");
} else {
    /* existing sort + create_dir_all + write_out block */
}
```

- [ ] **Step 5: Summary wiring** — `check_all` return tuple extended with `(Vec<usize> /*slot_caps*/, Vec<u64> /*slot_errors*/)`. `summary()` changes: echoes section prints per-slot `cap {n}` from the real `slot_caps[i]` (replacing the raw-flag recompute at :322-325) and appends ` · target-err {n}` when `slot_errors[i] > 0` with hint ` <- echo returned 4xx/5xx mid-run; check --check-url or raise -j`; verdict line gains ` · unjudged {stats.live_unjudged}` inside the live parens: `live {total} (elite {e} · anonymous {a} · transparent {t} · unjudged {u})`; integrity line unchanged (uses `live_total()` which already includes unjudged per G1).

- [ ] **Step 6: Default reconciliation** — `Validate::default().max_concurrent_checks`: set to `1024` to match clap, and update config.rs test `defaults_are_the_shipped_sweet_spot` to assert 1024 (test lives in config.rs — G2 runs after B and G1, sequential, allowed; note it in report). Comment in config.rs: `// must match clap default_value_t in main.rs`.

- [ ] **Step 7: Verify** — `cargo test --locked` green; clippy clean; manual matrix: (a) `--min-live 5 --out /tmp/g2` on sample → `Error`-style message + `rc=3`; (b) hostname-only input into a dir with a sentinel output → sentinel byte-identical, `rc=0`, `[write ] 0 candidates · existing outputs left untouched`; (c) `--timeout NaN` → clean Display error `rc=1`; (d) summary shows `unjudged`, real `cap`, `target-err` columns; (e) `--help` shows the three doc additions.

---

### Task J: `--skip-recent` incremental re-check (resume)

**Files:**
- Modify: `src/main.rs` (Cli, `async_main` before `check_all`)
- Modify: `src/output.rs` (new `read_records`)

**Gap this fixes:** every run re-probes the entire pool from scratch and rewrites both files — for the project's own nightly pool-refresh workflow (git history: `chore(pool): refresh validated proxies`), freshly-checked proxies are re-checked within hours. `last_checked` is already emitted per record but never consumed.

- [ ] **Step 1: Failing tests** (output.rs tests + main tests)

```rust
// output.rs
#[test]
fn read_records_round_trips_written_output() {
    let dir = std::env::temp_dir().join(format!("pxz-read-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut r = rec("http", "9.9.9.9:80");
    r.last_checked = 1_700_000_000;
    r.source = "pool.txt".into();
    write_out(&dir, &crate::config::Output::default(), std::slice::from_ref(&r)).unwrap();
    let back = read_records(&dir.join("proxies.jsonl")).unwrap();
    assert_eq!(back.len(), 1);
    assert_eq!(back[0].proxy, r.proxy);
    assert_eq!(back[0].last_checked, 1_700_000_000);
    assert_eq!(back[0].source, "pool.txt");
    assert_eq!(back[0].type_, "http"); // &'static str interned back
    let _ = std::fs::remove_dir_all(&dir);
}

// main.rs tests
#[test]
fn skip_recent_partitions_by_age() {
    let now = 1_700_000_100u64;
    // pure helper: given records + max_age, return set of proxy labels fresh enough
    let mut r = crate::model::LiveRecord { /* use a builder or reconstruct via json */ };
    // ... implement as: fn fresh_set(records: &[LiveRecord], now: u64, max_age: u64) -> std::collections::HashSet<String>
}
```

(For the main.rs test, construct `LiveRecord` directly — all fields are public — rather than JSON.) Run: `cargo test --locked` → FAIL (`read_records` missing).

- [ ] **Step 2: `output::read_records`** — read file line-by-line, `serde_json::from_str::<serde_json::Value>` per non-empty line, intern back into `LiveRecord` with the same mapping style used by `checked_in_samples_stay_self_consistent` (`type_` via match on the three scheme strings + fallback `"http"`, `anonymity` via the intern closure, tags via intern). Skip malformed lines with a collected warning count returned as `Ok((records, skipped))` — decide: return `Result<(Vec<LiveRecord>, usize), String>`. Truncated final line (torn previous write — now prevented by Task C, but old files exist) must not fail the whole read.

- [ ] **Step 3: Cli flag + partition logic** — `/// Skip candidates whose previous proxies.jsonl record is younger than SECONDS (incremental re-check; 0 = off)\n    #[arg(long, default_value_t = 0)] skip_recent: u64`. In `async_main` after `load_candidates`, before `check_all`: if `cfg.skip_recent > 0`, attempt `read_records(&dir/proxies.jsonl)` (missing file → log `[skip ] no previous output · checking all`, proceed); build `fresh: HashMap<String, &LiveRecord>` keyed by `record.proxy` where `now - last_checked <= skip_recent` (clock: reuse `now_secs()`); partition candidates: candidate's rendered label `format!("{}://{}", scheme, proxy_label)` — rendering lives in validate (private). To avoid cross-layer coupling, key the map on the **address+scheme+auth** identity the same way `Registry` does: helper `fn record_key(scheme: &str, addr: SocketAddr, auth: Option<&Auth>) -> String` living in model.rs (put it in this task; model.rs is fair game after G1 merged — sequential). Fresh candidates' prior records are carried into the final `records` vec (with their original `last_checked`/timings/`source`/`country`), summary gets `reused {n} fresh · probed {m}`; sort_records re-sorts the union. Exit/integrity math: `total` = probed count only; reused records excluded from `stats` (they're not probes) — integrity line reports probed totals, plus `reused {n}` token appended.

- [ ] **Step 4: Verify** — `cargo test --locked` green; manual: run sample twice with `--skip-recent 3600` → second run prints `reused 3 fresh · probed 0`, outputs keep original `last_checked`; with `--skip-recent 0` behavior identical to today.

---

### Task K: Integration + regression test suite (Tester agent — test authoring only)

**Files:**
- Create: `tests/e2e.rs` (spawns the compiled binary via `env!("CARGO_BIN_EXE_proxalyze")`)
- Create: `tests/common/mod.rs` (mock servers)

**Gap this fixes:** zero coverage of the six scheme flows and zero regression tests for every bug fixed in this sweep. Tests must be **network-free** (project convention): mocks bound to `127.0.0.1` ephemeral ports.

- [ ] **Step 1: Mock servers** in `tests/common/mod.rs` using std threads (no extra deps; tokio dev-dependency NOT needed if binary spawn + std TcpListener):
  - `EchoServer` — accepts HTTP, responds `200` with body = configured exit-IP string (plain or `{"origin": …}`), used as `--check-url http://127.0.0.1:PORT/ip`.
  - `HttpProxyMock` — absolute-form GET → fetches from EchoServer (or directly answers with EchoServer's body); CONNECT → 200 then relay; 407 mode when auth expected-but-missing.
  - `Socks5Mock` — greeting/method negotiate (no-auth + user/pass methods), CONNECT command → relay to echo; RFC1929 reject → `0x01`/`0xFF` behavior to drive `auth-required`.
  - Helpers: `free_port()`, `wait_for_listen()`.

- [ ] **Step 2: Scheme-flow e2e tests** (each writes an input file to a temp dir, spawns binary with `-i … --check-url http://127.0.0.1:… --out <tmp>`, asserts on `proxies.jsonl`):
  1. http proxy + http target → `status live`, `anonymity elite` when echo returns the proxy's own 127.0.0.1 (classify: exit == proxy_ip).
  2. http proxy + CONNECT (https target is out of scope without TLS mock — instead cover CONNECT via `--check-url` **http** through a proxy configured to require CONNECT? If too complex, cover CONNECT path at unit level instead: **required minimum**: flows 1 (forward), socks5 no-auth, socks5 user/pass, socks5 wrong-creds → `auth-required`, http 407 → `auth-required`, dead port → `dead`, comment-line input → 0 probed, hostname input without flag → 0 probed + hostname count in stdout.
  3. socks5 with correct creds → live; wrong creds → auth-required (mock rejects).
  4. Anonymity: echo returns `192.0.2.9` (≠ proxy ip) → `anonymous`; echo returns our own egress — mock direct-fetch at startup sees 127.0.0.1 and probe-through-proxy returns 127.0.0.1 → `transparent`.

- [ ] **Step 3: Regression tests for this sweep's bugs** (spawn-binary assertions):
  - `--timeout=NaN` → exit code **1**, stderr contains `--timeout must be a finite`, stderr does NOT contain `panicked` (bug B).
  - `--debug` with stderr piped to a closed reader (`Command` with `Stdio::piped()`, read 5 bytes, drop) → exit 0 AND outputs exist (bug E). Use `std::process` carefully: spawn, read some stderr, drop child stderr, wait → assert success.
  - Zero-candidate run does not clobber sentinel output (bugs G2/A): write sentinel `proxies.txt`, run with hostname-only input, assert bytes unchanged, exit 0.
  - Credentials survive case + symbols: input `http://Admin:p+ss@127.0.0.1:PORT` against mock requiring Basic `Admin:p+ss` → live (bugs A.3/A.4 end-to-end).
  - Commented line not probed: input `# 127.0.0.1:PORT` + one real line → mock's accept counter == 1.
  - Output perms 0600 (bug C) `#[cfg(unix)]`.
  - `--min-live 5` on a mock yielding 1 live → exit 3 (G2).
  - Query-string: `--check-url http://127.0.0.1:PORT/ip?probe=1` → mock records request target `/ip?probe=1` on the **tunneled/origin** path (drive via socks5 flow) (bug B query).

- [ ] **Step 4: Verify** — `cargo test --locked` runs everything (unit + e2e) green; total test count recorded for Task L; tests must be parallel-safe (unique temp dirs via `std::process::id()` + test name, ephemeral ports).

---

### Task L: README refresh

**Files:**
- Modify: `README.md`

**Gaps this fixes:** claims "15 tests" (actual: record from Task K — likely 40+); example output line predates malformed/hostnames accounting and Task A changes comment-line handling (`x.x.x.x` forms now comment-suppressed); `cargo install --path .` lacks `--locked`; no documentation of new flags/fields/semantics from this sweep; "Raw output, two files" section missing `source`/`country`; notes section unchanged despite `-j` floor behavior change (small `-j` now honored exactly).

- [ ] **Step 1: Failing test** — none (docs). Verification = the repo's own `checked_in_samples_stay_self_consistent` test still passes after any example-output edits, plus a fresh-eyes read.

- [ ] **Step 2: Edits (exact)**
  1. `cargo test   # N tests, no network` — N from final run.
  2. `cargo install --path . --locked`.
  3. Example block: rerun `cargo run --quiet -- -i examples/sample.txt` and paste actual `[parse]`/`[write]` lines (comment forms no longer inflate malformed — capture real numbers).
  4. Output docs: add `source` (input file) and `country` (ISO, when GeoLite2-City present; auto-detect paths listed beside ASN) to the `proxies.jsonl` field list; note files are written `0600` atomically (tmp+rename).
  5. New flags section additions in `--check-url`/input prose: `--resolve-hostnames`, `--min-live` (exit 3), `--skip-recent SECONDS`, `-i -` stdin, dir scan picks `.txt/.lst/.csv` case-insensitive, comment lines (`#`/`;`) skipped, supported forms gain `ip:port:user:pass` and `ip,port`, password charset note updated (symbols `+ = % ! # $ & * ( ) ~ , ;` now preserved; whitespace still unsupported).
  6. Notes section: `-j` — "values below 16 are honored exactly; ≥16 unchanged"; timeout must be finite > 0; `speed_ms` now excludes echo-permit queue wait (measurement note stays honest).
  7. Anonymity/sort description: add `unjudged` bucket to summary output example (`live N (elite · anonymous · transparent · unjudged)`).
  8. `--backup-url ""` semantics line updated (mixed = empties ignored).

- [ ] **Step 3: Verify** — `cargo test --locked` still green; `git diff README.md` reviewed for stale claims (`15 tests`, `(0 dupes)` example, `cargo install --path .` bare).

---

## Self-Review (controller runs before Oracle)

- **Spec coverage:** every audit item maps to a task — EPIPE→E; timeout panic→B+K; creds case→A+K; symbol passwords→A+K; zero-write→G2+K; stale-dir delete→C+K; comments→A+K; query drop→B+K; error UX→A(A path ctx)+G2(Display); hostname visibility→A; 4-field/CSV→A; provenance→G1; target-err/UA→E+G2; stdin/dir-ext→A; min-live→G2+K; country→G1; skip-recent→J; speed_ms→E; cap truth→E+G2; http warning→E; backup-url→G2; 0600→C+K; bounded body+read_once timeout→E; LICENSE/metadata/CI→F; README→L; default 512/1024→G2; non-TTY→E; test gaps→K. **Gap check:** mid-run 429 → covered as `target-err` counter + hint (E+G2), no status-vocabulary change (deliberate: statuses are documented contract). Release-profile `panic=abort` untouched (root causes fixed instead).
- **Placeholder scan:** J Step 1 originally shipped a `// ...` test stub. It was NOT fixed in the body text — binding-fixed by Oracle Addendum (round 2, J section: fully compilable test bodies, no ellipses).
- **Type consistency:** `Parsed`/`HostEntry` (A→G2 summary? G2 does NOT print hosts — A owns that line ✓); `slot_caps/slot_errors` (E→G2 ✓); `live_unjudged` (G1→G2 ✓); `read_records` (J only ✓); `Judge::open(asn, city)` (G1→main ✓); `record_key` (J defines in model.rs after G1 ✓ sequential).

## Oracle Review

Oracle (reviewer subagent) reviews this saved plan file against the audit findings — see dispatch in-session. Findings presented to user before execution.

## Execution Handoff

Plan complete at `docs/plans/2026-09-24-proxalyze-gap-fixes.md`. User already selected **Subagent-Driven** execution → proceed directly with subagent-driven-development + dispatching-parallel-agents per Batch Map, controller-only commits after each batch passes two-stage review, final whole-branch review, then finishing-a-development-branch.

---

## Oracle Amendments (BINDING — override any conflicting step text above)

### A (parse/input)
1. Keep-set adds ONLY `+ = % ! # $ & * ( ) ~ ,` — **not `;`** (stays a comment marker; mid-line `;` keeps splitting exactly as today). Password-charset docs in L must match this list.
2. **Comma regression guard:** BOTH passes split each incoming token on `,` and process every cell independently through the existing per-token logic (a prefixed cell may carry its own `scheme://` or `@`; a bare cell runs parse_addr_str → quad → strict csv). This preserves today's multi-entry comma lines (which would otherwise go 2→0 entries) and adds the `ipv4,port` format. Strict csv branch = cell is exactly `v4,port`.
3. After `://`/`@` extraction, trim trailing `,`/`#` from hostport before parse/proxy_ish.
4. Host scan = separate `fn scan_host_lines(body: &[u8], claim: Scheme) -> Vec<HostEntry>`; **skips any line containing `://` or `@`** (prefixed-host handling lives only in scan_prefixed, which gains its own HostEntry branch); exact single-token `host:port` lines only; dedup identical (host,port,claim) triples. NO signature churn on scan_bare/extend_token beyond internal cell-splitting; auth rides the existing `(SocketAddr, Option<Auth>)` tuple (quad → `Some`, others `None`). No unused params (clippy -D).
5. Flags stay on `Cli` (main.rs). `load_candidates` gains a `resolve_hostnames: bool` parameter. **No new Config fields** (avoids cross-task config.rs ownership).
6. Expected sample parse after comment-strip: `3 kept · 0 malformed` — implementer pastes ACTUAL run output into report for Task L.

### B (config)
Manual verify = exit code **1** AND stderr **contains** `--timeout must be a finite` (Debug-quote wrapping only disappears once G2 lands; do not assert exact prefix).

### C (output)
Temp name must be unique per process AND per file: `path.with_file_name(format!("{}.{}.tmp", file_name, std::process::id()))`. `with_extension("tmp")` collides `proxies.txt`↔`proxies.jsonl` on `proxies.tmp` and collides across concurrent runs.

### E (validate)
1. **Drop** the "reorder after tx.send" requirement — `qeprintln!` (never panics) is the complete fix; call sites stay put.
2. Delete the `4.floor_div(3)` sketch. Exact tests: `slot_cap(4,3)==2`, `slot_cap(1024,3)==342`, `slot_cap(1024,1)==1024`, `slot_cap(4,1)==4`.
3. `granted` Instant after permit; `total_ms = connect_ms + granted.elapsed()` applied in the **Err/blank arm too** whenever a permit was acquired (407/auth-required results currently include queue wait — sort key stays polluted otherwise).
4. `Validator::new` internals are free to restructure; outcome = semaphores sized on the **final survivor count**. Mark `slot_caps`/`slot_errors` with `#[allow(dead_code)] // summary wiring lands in a later batch` (G2 removes).
5. Counter consumption is G2's job: G2 clones `validator` Arc before spawn, reads slots **after `runner.await`**. E only guarantees the `&Arc<Validator>` methods exist.
6. **Flow unit tests move here** (K cannot e2e CONNECT/socks4 without a webpki-trusted cert): `#[tokio::test]` + `tokio::io::duplex` peers → `connect_phase` 200→Ok, 407→auth-required; factor socks4 reply interpretation into `fn interpret_socks4_reply([u8;8]) -> Result<(), Fail>` and test grant/reject. Six-flow coverage = CONNECT+socks4 unit (here) + forward/socks5/407/dead e2e (K). https inner-TLS e2e documented out-of-scope (webpki trust).

### F (meta)
Cross-target job uses `cargo build --locked --target aarch64-unknown-linux-gnu` with the apt gcc + `CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER` env (proven by release.yml; `cargo check` doesn't link while ring's target build-script still compiles C). Permissions: top-level `permissions: contents: read`; `release` job gets `permissions: contents: write`.

### G1 (schema/geo)
1. Country path = `v["country"]["iso_code"]` — **top-level** MaxMind City schema, NOT `["city"]["country"]` (else feature silently emits nothing).
2. G1 does **NOT** touch `summary()`/verdict region — G2 owns ALL summary() edits. Remove main.rs:291-302 from G1 scope.
3. Update geo.rs module doc (~line 6) to mention City db; banner covers `geo asn+city` / `geo asn` / `geo city` / `geo off`.

### G2 (CLI UX)
1. Write-guard snippet must keep later prints compiling (avoid E0425): declare `written` as `Option<Vec<String>>` via if/else, do the size-print inside `if let Some(written)`, `t_write`/`dir` scoped before the branch; verify with `cargo check`.
2. Add a **local** `qeprintln!` macro in main.rs (same guarded pattern as validate.rs's; do NOT extract a shared module — YAGNI); use for min-live + all stderr writes.
3. min-live at G2 time = `stats.live_total()` (J amends to add reused-live).
4. Remove E's `#[allow(dead_code)]` when the summary consumes the getters.

### J (skip-recent)
1. J owns **model.rs** too (batch map updated: J = main.rs + output.rs + model.rs; K = tests/ only — still conflict-free).
2. `read_records -> Result<(Vec<LiveRecord>, usize), String>` — this shape in contract, step, AND test (skipped-line count second).
3. Step 1 tests must be **fully compilable** — no `// ...` stubs; LiveRecord construction lists every field including G1's `source`/`country`.
4. type_ interning: match all four schemes explicitly (`http|https|socks4|socks5`), fallback `"http"` unreachable-in-practice (json only ever contains those four — state in comment).
5. `country` preserved via serde directly (`Option<String>` deserializes) — G1's `country: None` is fixture-only, no conflict.
6. `now.saturating_sub(last_checked)` — no underflow.
7. Partition AFTER load_candidates and BEFORE `let total = candidates.len()`; `total` becomes the **probed** count; integrity/progress/gates all use probed. `record_key(scheme, addr, auth) -> String` lives in model.rs.
8. Write guard: J replaces G2's condition with `total == 0 && records.is_empty()` (all-reused → write the union idempotently; parse-empty → skip, reused is necessarily 0 there too).
9. min-live amended to `stats.live_total() + reused_live`.
10. Manual "run sample twice" step **deleted** (doc-range IPs are dead → zero records → meaningless). Verify with a hand-written synthetic `proxies.jsonl` fixture (fresh `last_checked`) + `--backup-url ""` + `--skip-recent 3600` → expect `reused N fresh · probed 0`.

### K (tests)
1. Every binary spawn helper passes `--backup-url ""` (default backups are external HTTPS → DNS/network; repo rule is no-network tests).
2. EchoServer must be **stateful**: first request (startup shape-check = direct fetch) returns the configured own-egress body (e.g. `198.51.100.9`); subsequent requests return the mode body (elite → proxy ip `127.0.0.1`; anonymous → `203.0.113.7`; transparent → `198.51.100.9`). `classify` checks own-egress FIRST — a static server can never produce elite/anonymous.
3. Query assertion: recorded request-target **ends_with** `/ip?probe=1` (socks5+http target uses absolute-form `http://host/ip?probe=1`; origin-form also satisfies ends_with).
4. Six-flow claim → coverage split per E amendment (unit: CONNECT, socks4; e2e: forward, socks5, 407, dead, comments, hostnames).

### L (README)
Releases link → absolute `https://github.com/rianilham28/proxalyze/releases`. Test count and example `[parse]` line taken from the controller's final run + Task A's pasted actual output.

### GLOBAL — validation ownership (applies to every task)
Implementer verify steps shrink to: `cargo fmt` on own files + `cargo check --locked` + **targetified** `cargo test --locked <module>::` — and only while the crate compiles. If compile errors are in files the implementer does NOT own (sibling WIP in the same batch): do NOT fix them, retry once, else report `DONE_WITH_CONCERNS: blocked by sibling WIP`. **The controller runs the full gate** (`cargo fmt --all -- --check`, `cargo clippy --all-targets --locked -- -D warnings`, full `cargo test --locked`) after ALL tasks in a batch land — parallel same-crate edits make per-task full-suite runs unreliable by construction.

---

## Addendum — Oracle round 2 (BINDING; supersedes conflicting text above)

### B — timeout validation MUST reject overflow and zero-duration (supersedes B Step 2 condition)
`is_finite && > 0` still accepts `1e30` → `Duration::from_secs_f64` panics on overflow (the audit's panic bug survives) and `1e-300` rounds to `Duration::ZERO` → instant-fail probes. Use:

```rust
use std::time::Duration; // top of config.rs
for (name, v) in [
    ("--timeout", self.validate.timeout),
    ("--connect-timeout", self.validate.connect_timeout),
] {
    let ok = v.is_finite()
        && v > 0.0
        && Duration::try_from_secs_f64(v).is_ok_and(|d| !d.is_zero());
    if !ok {
        return Err(format!(
            "{name} must be a finite number > 0 that fits a Duration (got {v})"
        ));
    }
}
// then the existing connect_timeout <= timeout check
```

`Duration::try_from_secs_f64` (stable 1.66) folds negative/NaN/overflow into `Err`. Tests ADD: `assert!(mk(1e30, 1.0).is_err());` (overflow), `assert!(mk(1e-300, 1e-300).is_err());` (zero-duration), `assert!(mk(10.0, 1e-300).is_err());`. Manual verify = rc 1 + stderr contains `--timeout must be a finite` (substring; Debug quotes only vanish after G2).

### A — keep-set and comma ordering (SUPERSEDES A1/A2 entirely)
- **Prefixed keep-set adds ONLY** `+ = % ! # $ & * ( ) ~` — **NO comma, NO semicolon.** Comma/semicolon stay natural token breaks → today's multi-entry prefixed lines (`http://a:80,http://b:80`, `ip:port;ip:port`) keep parsing exactly as now (zero regression; the oracle's merge regression is resolved by never merging in the prefixed pass). Comma-in-password remains unsupported → Task L documents it alongside whitespace ("re-encode at the proxy"), same class as today.
- **`ip,port` support lives only in the bare pass**: bare keep-set gains `,` + full `a-z A-Z`. In `extend_token`, order is: (1) `parse_addr_str` (unchanged) → (2) CIDR (unchanged) → (3) **strict csv whole-token**: `split_once(',')` where left is lenient-v4 AND right is u16 → one plain `Entry`; (4) **quad** `splitn(4, ':')` (note: `splitn` keeps the remainder in piece 4, so password `sec:ret` survives — the plan's test must pass as written); (5) **comma cell-split fallback**: token contains `,` but strict csv failed → split on `,`, each cell through parse_addr_str then quad (cells must be self-contained `ip:port`/quad — no cross-cell port pairing; `ip,port,ip,port` on one line stays unsupported, same as today). Order matters: strict csv BEFORE cell-split or `5.6.7.8,8080` loses its port pair.
- Prefixed hostport cleanup: strip from the **first `#`** in hostport only (after `split_auth`, so passwords keep `#`). No comma trim needed (comma never reaches the prefixed hostport now).
- Host scan (`scan_host_lines`) unchanged from amendments (skips `://`/`@` lines, exact single-token `host:port`, dedup triples). Prefixed-host → HostEntry branch: hostname letters → `HostEntry`; all-numeric host → `malformed++` (keeps `999.1.1.1` test green). Update `declared_malformed_lines_are_counted_once`: hostname line moves to hosts → `mal == 2`, `hosts.len() == 1`.

### E — speed_ms rule (sharpens E3)
`granted = Instant::now()` taken right after permit acquisition. **Recompute `r.total_ms = r.connect_ms + granted.elapsed()` in BOTH post-permit arms** (Ok arm AND Err arm after `blank()` — the 407/auth-required path). Pre-permit Err arms (dial-fail, permit-timeout) stay as-is: they never reach output or live-latency stats. Also `slot_errors`/`slot_caps` reads are G2's job via Arc clone after `runner.await` (E5 stands). Socks4/CONNECT unit tests: `connect_phase` is generic over `S: AsyncRead+AsyncWrite` → drive directly with `tokio::io::duplex`; for socks4 factor `interpret_socks4_reply([u8; 8]) -> Result<(), Fail>` (and optionally the request builder) into pure/generic fns testable the same way — do not attempt to call `socks4_get` with a `DuplexStream` (it takes `TcpStream` concretely).

### G2/J — no bare eprintln (sharpens G2.2)
The local `qeprintln!` macro (guarded, never panics) lands in G2 in main.rs; **every** stderr write in G2 and J uses it — min-live message, skip-recent log lines, error path in `run_main`. A raw `eprintln!` in main.rs reintroduces the EPIPE bug class this sweep exists to kill.

### J — read_records completeness (supersedes J2/J4 wording)
1. Shape: `read_records(path) -> Result<(Vec<LiveRecord>, usize), String>` everywhere (contract, step, test).
2. Decode EVERY field from each JSON value: `proxy`, `type_` (4-way intern: http|https|socks4|socks5), `last_checked`, `speed_ms`, `connect_ms`, `ttfb_ms` (absent → None), `anonymity` (3-way intern, absent/unknown → None), `exit_ip`, `asn` (absent → None), `org` (absent → None), `tags` (intern each of hosting|cdn|mobile|vpn|residential-proxy|auth-required), `source` (absent → `"unknown"`), `country` (absent → None). **Do NOT copy the checked-in test decoder** (it zeroes timings and drops asn/org/ttfb/country).
3. Strict-intern rule: a line whose `type_` or any tag is NOT in the known set → count as **skipped**, do not decode (no silent socks4→http corruption; version-skew lines are skipped+counted, never mangled). Unknown-`anonymity` values → None is fine (it's semantically Option).
4. Placement: partition after `load_candidates`, before `let total = candidates.len()`; `total` becomes probed count; integrity gates + progress operate on probed; the reused union is merged into `records` **after both integrity gates pass**, before `sort_records`; `min_live` = `stats.live_total() + reused_live`; write guard = `total == 0 && records.is_empty()` (supersedes G2 guard when J lands; all-reused → union written idempotently). `now.saturating_sub(last_checked)`.
5. `record_key` in model.rs (J owns model.rs — batch map amended).

### K — hermetic spawns (restates + sharpens K1-K3)
Every binary spawn helper passes `--backup-url ""` (default backups are external HTTPS → DNS/network; repo rule: tests are network-free). EchoServer is **stateful**: request 1 (startup direct shape-check) returns the own-egress body (`198.51.100.9`), subsequent requests return the mode body (elite → `127.0.0.1`, anonymous → `203.0.113.7`, transparent → `198.51.100.9`) — `classify` checks own-egress first, a static server can never yield elite/anonymous. Query assertion: recorded request-target `ends_with("/ip?probe=1")` (SOCKS5+http target sends absolute-form `http://host/ip?probe=1`).

### Batch map amendment
Batch 4: **J owns main.rs + output.rs + model.rs**; K owns `tests/` only. No overlap (G1 already merged model.rs in batch 2; batches are sequential).

---

## Addendum round 3 — Oracle final corrections (BINDING)

**B** (restated as single source of truth — base Step 2 condition superseded; round-2 text governs: `Duration::try_from_secs_f64(v).is_ok_and(|d| !d.is_zero())` + tests for `1e30`, `1e-300`, `10.0/1e-300`). **F base Step 3's `cargo check` was already superseded by Amendments F (`cargo build` + linker env).** Both restated here because the oracle's reads crossed with rounds 1–2; implementers follow the LATEST text for their task.

**F** — Files list amended: F owns `LICENSE`, `Cargo.toml`, `.github/workflows/ci.yml`, **`.github/workflows/release.yml`** (Step 3's permissions move edits it — listing it keeps batch isolation honest; all four are meta files, no clash with E/G1).

**A** — summary visibility (main.rs ~:341-345): change the inputs-loop skip condition from `if *kept == 0 { continue; }` to `if *kept == 0 && *hosts == 0 && *malformed == 0 { continue; }` — otherwise an all-hostname file (kept=0) is suppressed exactly where the audit demands it be reported. Per-file `[parse ]` line gains a note when hosts>0 (` · {h} hostname lines (skipped: no DNS)`); aggregate line text per base Step 8.

**A threading** (resolves oracle round-1 flag-ownership blocker concretely): `main()` keeps `cli`, calls `async_main(cfg, workers, source, &cli)` — `async_main` gains `cli: &Cli` (a main.rs type; NO Config fields, NO config.rs edits). `load_candidates(&cfg, cli.resolve_hostnames)` reads the flag through that param. G2/J later reuse the same `cli: &Cli` param for `min_live`/`skip_recent` (no further signature churn). Note for G1: `async_main` already has the extra `cli: &Cli` param by the time batch 2 runs — keep it.

**C** — `.mode(0o600)` only applies when the file is *created*; a wide-perm `*.tmp` left by a crashed earlier run stays wide. After opening (create+truncate), under `#[cfg(unix)]`: `std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;` before writing. (Temp-name collision already fixed by Amendments C: `file_name + pid`.)

**E** — (1) Bounded body: the **frame-loop is the specified path** (no `Limited`/error-downcast ambiguity): inside the existing timeout window, loop `body.frame().await` (`BodyExt` already in scope; add `bytes::BytesMut`), and **before** `buf.extend_from_slice`, `if buf.len() + data.len() > MAX_BODY { return Err(("tcp-alive", "oversized response".into())) }` — size-checked during read (the audit point), one outer budget preserves the original 1500ms semantics; `Some(Err(e))` → `e.to_string()` transport bucket; `None` → break. Same construction in `read_once` with its passed-in budget. If an implementer prefers `Limited` they MUST downcast to `http_body_util`'s length-limit error type (verify in crate source) to emit `oversized response` — otherwise use the frame-loop. (2) `check_shape` signature becomes `async fn check_shape(&self, target: &CheckTarget, ips: &[IpAddr], authority: &str) -> Shape` — it must NOT take `&TargetSlot` (slots don't exist yet when it runs). `Validator::new` order: resolve all targets → free-standing shape-check per target (primary `Unreachable` → warn + keep; primary `Wrong` → fatal; backups `Unreachable`/`Wrong` → drop; primary `Shape::Ok` sets `own_egress`) → build `TargetSlot`s for survivors with `Semaphore::new(slot_cap(cfg.concurrency, survivor_count))`.

**J** — self-review line claiming the J Step 1 placeholder was "fixed in-line" was false when written; Addendum-round-2 J3 (fully compilable tests, no stubs) is the binding fix.

**L** — README honesty: paste the REAL transcript of running the sample (it honestly shows **0 live** — sample IPs are RFC-5737 doc addresses); keep the `examples/out/` snippet with its existing explicit "illustrative dummy, not a captured run" label. Never present a 3-survivor transcript as runnable output. Test count from the controller's final run.

---

## Final Oracle Verdict (32 findings) — Remaining Deltas (BINDING)

Triage note: findings on B `try_from_secs_f64`, A prefixed-host exclusion/comma keep-set/flag threading/summary-skip, C tmp naming+perms, E frame-loop/`check_shape` signature/`#[allow(dead_code)]`/post-permit timing on both arms, F release.yml+`cargo build`, G2 write-guard scope+qeprintln, J full decoder/tuple shape/placement/saturating_sub/record_key ownership/model fixtures, K stateful echo/`--backup-url ""`/`ends_with` query, L honest transcript, controller-gated validation, `4.floor_div`, G1 top-level country path — are ALREADY binding via the addenda rounds above or the dispatched Batch-1 prompts. The deltas below are the not-yet-recorded remainder:

**E** — the existing test helper `socks4_only_picks_v4_capable_slots` constructs `TargetSlot { … }` as a struct literal (`src/validate.rs:1113-1122`): adding `cap`/`errors` fields breaks it — update that helper in the same task.

**G1** (three deltas):
1. Country extraction must be a pure function `fn country_from_value(v: &serde_json::Value) -> Option<String>` reading **top-level** `["country"]["iso_code"]`, unit-tested with a hand-written serde_json fixture (both present and absent) — the real `.mmdb` is gitignored, so CI can never exercise it otherwise.
2. **Supersedes** rounds 1/3 ("G1 does not touch summary()"): G1 ALSO prints the unjudged bucket in the verdict line — `live {total} (elite {e} · anonymous {a} · transparent {t} · unjudged {u})` — so the batch-2 commit is internally consistent (`live_total()` already includes unjudged from G1's model change; G2 later adds only the caps/target-err lines). G1 and G2 are sequential batches; no clash.
3. Module-doc refresh lands in G1's file edits: `src/main.rs:8-9` header claims, `src/output.rs:4-5` field list (+ `source`/`country`), `src/geo.rs:6` (City db) — so Task L owns README only.

**G2** — counter read: clone the `Arc<Validator>` **before** the `tokio::spawn` move; read `slot_caps`/`slot_errors` only **after** `runner.await?` (reading earlier always yields zeros). Mid-run target-error observability is asserted by K (below).

**J** — freshness tests must include a record with `last_checked` in the FUTURE (clock rollback / copied pool): `now.saturating_sub(last_checked)` keeps it fresh, never panics.

**K** — assertion channels (the oracle: `LiveRecord` has NO `status` field; only live/auth-required rows exist in jsonl):
- live → jsonl row with `anonymity` set;
- auth-required → jsonl row with `auth-required` tag;
- dead → **no jsonl row** — assert via summary stdout (`dead` verdict count) + mock accept-counter;
- comment-only / hostname-only inputs → `[parse ]`/summary stdout counts + mock counter proves only real lines were dialed;
- target-err: one run against a mock echo answering 503 → summary stdout contains `target-err` (exercises G2's per-slot counter end-to-end).

**A** (recorded for the dispatched steers): `scan_bare`'s caller (`src/parse.rs:53-61`, `for (addr, _) in …`) must migrate to carry `Option<Auth>` into `Entry` (quad auth) — no unused params; add mixed-case quad test `1.2.3.4:8080:Admin:Secret` → user `Admin`, password `Secret` (`extend_token` must not lowercase).
