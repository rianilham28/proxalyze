//! proxalyze — validate proxy lists into clean, judged proxies. Configuration
//! is command-line arguments only; optional ASN and City databases are
//! auto-detected (geo/GeoLite2-ASN.mmdb and geo/GeoLite2-City.mmdb).
//!
//! Reads plain proxy files (each with a DECLARED protocol — nothing is
//! guessed), checks every proxy on a raw hyper connection against an echo
//! URL whose body reveals the exit IP, and writes raw data: proxy lists
//! plus one JSONL record per survivor with source, timings, anonymity, exit
//! IP, ASN, org, network-class tags, and optional country. Run with --help.

mod config;
mod geo;
mod model;
mod output;
mod parse;
mod validate;

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::net::IpAddr;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use tokio::sync::mpsc;

use config::{Config, InputFile, detect_asn_db, detect_city_db, split_input_spec};
use geo::Judge;
use model::{Candidate, ProbeResult, Registry, Stats};
use output::{read_records, sort_records, write_out};
use parse::{HostEntry, parse_proxies_stats};
use validate::{CheckCfg, Validator};

#[derive(Parser)]
#[command(name = "proxalyze", version, about, long_about = None)]
struct Cli {
    /// Input proxy file, optionally with scheme: FILE[:http|https|socks4|socks5].
    /// Repeatable. Bare ip:port lines inherit the declared scheme; an inline
    /// scheme:// prefix on a line always wins. [default: ./proxies.txt]
    #[arg(short = 'i', long = "input")]
    inputs: Vec<String>,
    /// Scheme for input files given without a :scheme suffix
    #[arg(short = 's', long, default_value = "http")]
    scheme: String,

    /// Echo URL every proxy must fetch; body must be the exit IP, plain or
    /// {"origin": ...} / {"ip": ...}
    #[arg(long, default_value = "https://ipv4.icanhazip.com")]
    check_url: String,
    /// Additional echo endpoints, round-robin with the primary; `""` alone
    /// selects primary only; mixed with real URLs, empty entries are ignored
    #[arg(long = "backup-url")]
    backup_urls: Vec<String>,

    /// Proxies checked at once (fd limit is raised automatically). Measured
    /// safe to 2048 on residential links; beyond that carrier SYN-limits can
    /// turn live proxies into false deads (values below 16 are honored
    /// exactly; the 16 floor applies only when -j >= 16)
    #[arg(short = 'j', long, default_value_t = 1024)]
    concurrency: usize,
    /// Total seconds per check, never retried (must be finite, > 0, and
    /// convert to a non-zero Duration)
    #[arg(long, default_value_t = 10.0)]
    timeout: f64,
    /// Seconds to connect; 2.0 is the measured sweet spot (retains every live
    /// dial, cuts wall ~35% vs 5.0; 1.0 clips live proxies)
    #[arg(long, default_value_t = 2.0)]
    connect_timeout: f64,

    /// Output directory
    #[arg(short, long, default_value = "./out")]
    out: String,

    /// Runtime worker threads; 0 = auto: 80% of available parallelism
    /// (portable, cgroup/affinity aware; the 20% reserve keeps the box usable)
    #[arg(long, default_value_t = 0)]
    workers: usize,
    /// Log every failed proxy with its reason (very verbose)
    #[arg(long)]
    debug: bool,
    /// Resolve hostname:port candidates via DNS at load (one lookup per unique host)
    #[arg(long)]
    resolve_hostnames: bool,

    /// Exit non-zero (code 3) when fewer than N live survivors are produced,
    /// counted AFTER write-stage filters; 0 disables the gate (CI pipelines
    /// that must not accept a silently-empty result)
    #[arg(long, default_value_t = 0)]
    min_live: usize,

    /// Skip candidates whose previous proxies.jsonl record is younger than SECONDS (incremental re-check; 0 = off)
    #[arg(long, default_value_t = 0)]
    skip_recent: u64,

    /// Record must carry ALL these tags to survive (repeatable)
    #[arg(long = "require-tag")]
    require_tag: Vec<String>,
    /// Record carrying ANY of these tags is dropped (repeatable)
    #[arg(long = "exclude-tag")]
    exclude_tag: Vec<String>,
    /// Drop records with speed_ms above this value
    #[arg(long)]
    max_speed: Option<u32>,
    /// Keep only this anonymity rank or better: elite | anonymous
    #[arg(long)]
    min_anonymity: Option<String>,
    /// Keep only these ISO country codes, comma-separated (no country → dropped)
    #[arg(long)]
    country: Option<String>,
    /// Keep only the top N records after ranking
    #[arg(long)]
    keep_top: Option<usize>,
}

/// Resource governor: reserve ~20% of the machine's parallelism for
/// everything else. `available_parallelism` is portable and honours cgroup
/// limits / CPU affinity (containers and tasksets included); 80% of it,
/// floor 2. Override with --workers to go all-in or pin a number.
fn detect_workers() -> usize {
    let n = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    (n * 4 / 5).max(2)
}

fn resolve_backup_urls(user: &[String]) -> Vec<String> {
    if user.is_empty() {
        config::Validate::default().backup_urls
    } else {
        user.iter().filter(|url| !url.is_empty()).cloned().collect()
    }
}

fn build_config(cli: &Cli) -> Result<Config, String> {
    let inputs = if cli.inputs.is_empty() {
        vec![InputFile {
            path: "proxies.txt".into(),
            scheme: cli.scheme.clone(),
        }]
    } else {
        cli.inputs
            .iter()
            .map(|spec| {
                let (path, scheme) = split_input_spec(spec);
                InputFile {
                    path,
                    scheme: scheme.unwrap_or_else(|| cli.scheme.clone()),
                }
            })
            .collect()
    };
    let backup_urls = resolve_backup_urls(&cli.backup_urls);
    let countries: Vec<String> = match &cli.country {
        None => Vec::new(),
        Some(raw) => {
            let parsed: Vec<String> = raw
                .split(',')
                .map(|c| c.trim().to_ascii_uppercase())
                .filter(|c| !c.is_empty())
                .collect();
            if parsed.is_empty() {
                return Err("--country requires at least one ISO code".into());
            }
            parsed
        }
    };
    let cfg = Config {
        debug: cli.debug,
        inputs,
        validate: config::Validate {
            check_url: cli.check_url.clone(),
            backup_urls,
            max_concurrent_checks: cli.concurrency,
            timeout: cli.timeout,
            connect_timeout: cli.connect_timeout,
        },
        asn_db: detect_asn_db(),
        city_db: detect_city_db(),
        output: config::Output {
            dir: cli.out.clone(),
        },
        filters: config::Filters {
            require_tags: cli.require_tag.clone(),
            exclude_tags: cli.exclude_tag.clone(),
            max_speed: cli.max_speed,
            min_anonymity: cli.min_anonymity.clone(),
            countries,
            keep_top: cli.keep_top,
        },
    };
    cfg.check()?;
    Ok(cfg)
}

async fn load_candidates(
    cfg: &Config,
    resolve_hostnames: bool,
) -> Result<(Registry, Vec<(String, usize, usize, usize)>, usize, usize), Box<dyn Error>> {
    use std::io::Read;

    let mut registry = Registry::new();
    let mut per_file = Vec::new();
    let mut dns_cache: HashMap<(String, u16), Vec<IpAddr>> = HashMap::new();
    let (mut total_resolved, mut total_unresolved) = (0, 0);
    for file in &cfg.inputs {
        let scheme = cfg.scheme_of(file).expect("validated in Config::check");
        for path in expand_inputs(&file.path)? {
            let body = if path.as_os_str() == "-" {
                let mut body = Vec::new();
                std::io::stdin().read_to_end(&mut body)?;
                body
            } else {
                std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?
            };
            // The parser suppresses an auth-less bare re-sighting of any
            // prefixed line as a substring artifact; exact identity is
            // (addr, scheme, credentials), and cross-file exact duplicates
            // are Registry's job.
            let parsed = parse_proxies_stats(&body, scheme);
            let label = path.display().to_string();
            let mut kept = 0;
            let row = per_file.len();
            for e in parsed.entries {
                if registry.add(
                    Candidate::new(e.addr, e.scheme, e.auth, label.clone()).with_input_row(row),
                ) {
                    kept += 1;
                }
            }
            let hosts_len = parsed.hosts.len();
            if resolve_hostnames {
                let (resolved, unresolved, added) = resolve_host_entries(
                    &[(&parsed.hosts, label.as_str())],
                    row,
                    &mut registry,
                    &mut dns_cache,
                    |host, port| {
                        tokio::task::block_in_place(|| {
                            tokio::runtime::Handle::current().block_on(async move {
                                tokio::net::lookup_host((host, port))
                                    .await
                                    .map(|addrs| addrs.map(|addr| addr.ip()).collect())
                            })
                        })
                    },
                );
                kept += added;
                total_resolved += resolved;
                total_unresolved += unresolved;
            }
            per_file.push((label, kept, parsed.malformed, hosts_len));
        }
    }
    Ok((registry, per_file, total_resolved, total_unresolved))
}

fn resolve_host_entries<F>(
    groups: &[(&[HostEntry], &str)],
    input_row: usize,
    registry: &mut Registry,
    cache: &mut HashMap<(String, u16), Vec<IpAddr>>,
    mut resolver: F,
) -> (usize, usize, usize)
where
    F: FnMut(&str, u16) -> std::io::Result<Vec<IpAddr>>,
{
    let (mut resolved, mut unresolved, mut added) = (0, 0, 0);
    let mut declarations = HashSet::new();
    for (hosts, label) in groups {
        for host in *hosts {
            let identity = (
                host.host.clone(),
                host.port,
                host.scheme,
                host.auth.as_ref().map(ToString::to_string),
            );
            if !declarations.insert(identity) {
                continue;
            }
            let key = (host.host.clone(), host.port);
            cache
                .entry(key)
                .or_insert_with(|| resolver(&host.host, host.port).unwrap_or_default());
            let ips = cache.get(&(host.host.clone(), host.port)).unwrap();
            if ips.is_empty() {
                unresolved += 1;
                continue;
            }
            resolved += 1;
            for ip in ips {
                let addr = std::net::SocketAddr::new(*ip, host.port);
                if registry.add(
                    Candidate::new(addr, host.scheme, host.auth.clone(), (*label).to_string())
                        .with_input_row(input_row),
                ) {
                    added += 1;
                }
            }
        }
    }
    (resolved, unresolved, added)
}

fn expand_inputs(path: &str) -> Result<Vec<std::path::PathBuf>, Box<dyn Error>> {
    if path == "-" {
        return Ok(vec![std::path::PathBuf::from("-")]);
    }
    let p = std::path::Path::new(path);
    if p.is_dir() {
        let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(p)
            .map_err(|e| format!("{}: {e}", p.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|f| {
                f.extension().and_then(|x| x.to_str()).is_some_and(|x| {
                    matches!(x.to_ascii_lowercase().as_str(), "txt" | "lst" | "csv")
                })
            })
            .collect();
        files.sort();
        if files.is_empty() {
            return Err(format!("{path}: directory has no list files (.txt/.lst/.csv)").into());
        }
        return Ok(files);
    }
    Ok(vec![p.to_path_buf()])
}

/// Informational print that never panics on a closed pipe (`| head`,
/// `| grep -m1`): the reader leaving early is a display choice, not a
/// reason to fail a completed run.
macro_rules! qprintln {
    ($($a:tt)*) => {{
        use std::io::Write;
        let _ = writeln!(std::io::stdout(), $($a)*);
    }};
}

/// Error-path stderr print that never panics on a closed pipe.
macro_rules! qeprintln {
    ($($a:tt)*) => {{
        use std::io::Write;
        let _ = writeln!(std::io::stderr(), $($a)*);
    }};
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
async fn check_all(
    cfg: &Config,
    candidates: Vec<Candidate>,
    judge: &Judge,
) -> Result<
    (
        Vec<model::LiveRecord>,
        Stats,
        Vec<(u64, u64, u64)>,
        Vec<String>,
        Vec<usize>,
        Vec<u64>,
    ),
    Box<dyn Error>,
> {
    let targets = cfg.all_targets()?;
    let check_cfg = CheckCfg::from_validate(&cfg.validate, cfg.debug)?;
    let validator = std::sync::Arc::new(Validator::new(check_cfg, targets).await?);
    let labels = validator.active_targets();
    // Clone before the Arc moves into spawn; read counters only after
    // `runner.await`, since reading while validation is active yields zeros.
    let v = validator.clone();
    let (tx, mut rx) = mpsc::channel::<ProbeResult>(4096);
    let runner = tokio::spawn(async move { validator.run(candidates, tx).await });

    let mut stats = Stats::default();
    let mut records: Vec<model::LiveRecord> = Vec::new();
    let mut per_target: Vec<(u64, u64, u64)> = vec![(0, 0, 0); labels.len()]; // live, tls-fail, permit-waits
    let checked_at = now_secs();
    while let Some(r) = rx.recv().await {
        stats.record(&r);
        if r.slot >= 0 {
            let t = &mut per_target[r.slot as usize];
            if r.status == "live" {
                t.0 += 1;
            }
            if r.status == "tls-fail" {
                t.1 += 1;
            }
            if r.fail_reason
                .as_deref()
                .is_some_and(|s| s.starts_with("echo target saturated"))
            {
                t.2 += 1;
            }
        }
        let include = r.status == "live" || r.status == "auth-required";
        if !include {
            continue;
        }
        let mut tags: Vec<&'static str> = Vec::new();
        let (mut asn, mut org) = (None, None);
        if let (true, Some(ip)) = (judge.active(), r.exit_ip) {
            let net = judge.locate(ip);
            asn = net.asn;
            org = net.org;
            tags = net.tags;
        }
        if r.status == "auth-required" {
            tags.push("auth-required");
        }
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
            source: r.input.clone(),
            country: r.exit_ip.and_then(|ip| judge.country(ip)),
            tags,
        });
    }
    runner.await?;

    let slot_caps = v.slot_caps();
    let slot_errors = v.slot_errors();
    Ok((records, stats, per_target, labels, slot_caps, slot_errors))
}
fn is_fresh(now: u64, last_checked: u64, max_age: u64) -> bool {
    now.saturating_sub(last_checked) <= max_age
}

fn persisted_record_key(record: &model::LiveRecord) -> Option<String> {
    let (scheme, tail) = record.proxy.split_once("://")?;
    let (credentials, address) = tail
        .rsplit_once('@')
        .map_or((None, tail), |(a, b)| (Some(a), b));
    let auth = credentials.and_then(|raw| {
        let (user, password) = match raw.split_once(':') {
            Some((user, password)) => (user, Some(password)),
            None => (raw, None),
        };
        (!user.is_empty()).then(|| model::Auth {
            user: user.to_owned(),
            password: password.map(str::to_owned),
        })
    });
    Some(model::record_key(
        scheme,
        address.parse().ok()?,
        auth.as_ref(),
    ))
}

type ReusedByInput = HashMap<usize, usize>;

fn partition_recent(
    candidates: Vec<Candidate>,
    previous: &[model::LiveRecord],
    now: u64,
    max_age: u64,
) -> (Vec<Candidate>, Vec<model::LiveRecord>, ReusedByInput) {
    let mut fresh: HashMap<String, &model::LiveRecord> = HashMap::new();
    for record in previous {
        if is_fresh(now, record.last_checked, max_age)
            && let Some(key) = persisted_record_key(record)
        {
            fresh.insert(key, record);
        }
    }
    let mut reused = Vec::new();
    let mut reused_by_input: ReusedByInput = HashMap::new();
    let mut candidates = candidates;
    candidates.retain_mut(|candidate| {
        let key = model::record_key(
            candidate.scheme.as_str(),
            candidate.addr,
            candidate.auth.as_ref(),
        );
        if let Some(record) = fresh.remove(&key) {
            if let Some(row) = candidate.input_row {
                *reused_by_input.entry(row).or_default() += 1;
            }
            reused.push(record.clone());
            false
        } else {
            true
        }
    });
    (candidates, reused, reused_by_input)
}

fn input_checked(kept: usize, reused: usize) -> usize {
    kept.saturating_sub(reused)
}

/// 1,487 -> "1,487"
fn fmt_n(n: impl std::fmt::Display) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

type SummaryData<'a> = (
    &'a [(String, usize, usize, usize)],
    &'a [(u64, u64, u64)],
    &'a [String],
    &'a [usize],
    &'a [u64],
);

fn summary(
    stats: &Stats,
    data: &SummaryData<'_>,
    reportable_before_filters: usize,
    filtered: (usize, usize),
    total: usize,
    reused: usize,
    reused_by_input: &ReusedByInput,
    cfg: &Config,
) {
    qprintln!("summary");
    qprintln!(
        "  verdict   live {} (elite {} · anonymous {} · transparent {} · unjudged {}) · auth {} · tls-fail {} · socks-rejected {} · tcp-alive {} · dead {}",
        fmt_n(stats.live_total()),
        fmt_n(stats.live_elite),
        fmt_n(stats.live_anonymous),
        fmt_n(stats.live_transparent),
        fmt_n(stats.live_unjudged),
        fmt_n(stats.auth_required),
        fmt_n(stats.tls_fail),
        fmt_n(stats.socks_rejected),
        fmt_n(stats.tcp_alive),
        fmt_n(stats.dead),
    );
    let mut con = stats.live_connect_ms.clone();
    let mut tot = stats.live_total_ms.clone();
    con.sort_unstable();
    tot.sort_unstable();
    if !con.is_empty() {
        qprintln!(
            "  latency   live connect p50/p90/p99: {} / {} / {} ms \u{b7} whole-check: {} / {} / {} ms  (dead probes each waited the {:.1}s connect window)",
            Stats::percentile(&con, 0.50),
            Stats::percentile(&con, 0.90),
            Stats::percentile(&con, 0.99),
            Stats::percentile(&tot, 0.50),
            Stats::percentile(&tot, 0.90),
            Stats::percentile(&tot, 0.99),
            cfg.validate.connect_timeout,
        );
    }
    let (per_file, per_target, labels, slot_caps, slot_errors) = *data;
    if !labels.is_empty() {
        qprintln!("  echoes    cap per target");
        for (i, url) in labels.iter().enumerate() {
            let (live, tlsf, sat) = per_target.get(i).copied().unwrap_or((0, 0, 0));
            let cap = slot_caps.get(i).copied().unwrap_or(0);
            let target_errors = slot_errors.get(i).copied().unwrap_or(0);
            let error_note = if target_errors > 0 {
                "  <- echo returned 4xx/5xx mid-run; check --check-url or raise -j"
            } else {
                ""
            };
            let permit_note = if sat > 0 {
                "  <- raise -j or add --backup-url"
            } else {
                ""
            };
            qprintln!(
                "            {url:<36} cap {cap:>4} · live {live:>5} \u{b7} tls-fail {tlsf:>5} \u{b7} permit-waits {sat} \u{b7} target-err {target_errors}{error_note}{permit_note}"
            );
        }
    }
    qprintln!("  inputs");
    let mut any = false;
    for (index, (path, kept, malformed, hosts)) in per_file.iter().enumerate() {
        let measured = stats.by_input.get(&index).copied();
        let reused_for_input = reused_by_input.get(&index).copied().unwrap_or(0);
        let checked = input_checked(*kept, reused_for_input);
        // Live/auth remain label-keyed Stats aggregates; this preserves the
        // pre-existing summary behavior when one label declares two schemes.
        let (live, auth) = measured.map_or((0, 0), |(live, auth, _)| (live, auth));
        if *kept == 0 && *hosts == 0 && *malformed == 0 {
            continue;
        }
        any = true;
        let host_note = if *hosts > 0 {
            format!(" · {hosts} hostname lines")
        } else {
            String::new()
        };
        let reuse_note = if reused_for_input > 0 {
            format!(" · reused {reused_for_input}")
        } else {
            String::new()
        };
        qprintln!(
            "            {path:<36} checked {:>7} · live {:>5} ({:.1}%) · auth-only {:>6}{host_note}{reuse_note}",
            fmt_n(checked),
            fmt_n(live),
            100.0_f64 * live as f64 / checked.max(1) as f64,
            fmt_n(auth)
        );
    }
    if !any {
        qprintln!("            (none)");
    }
    qprintln!(
        "  integrity {}/{} results ✓ · {} reportable · {reportable_before_filters} records ✓ · reused {reused} fresh · probed {total}",
        fmt_n(stats.received),
        fmt_n(total),
        fmt_n(stats.live_total() + stats.auth_required),
    );
    if cfg.filters.is_active() {
        let (kept, dropped) = filtered;
        qprintln!("  filters   kept {kept} · dropped {dropped}");
    }
}

fn main() {
    if let Err(e) = run_main() {
        qeprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run_main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let cfg = build_config(&cli)?;
    let (workers, source) = if cli.workers > 0 {
        (cli.workers, "flag")
    } else {
        (detect_workers(), "auto 80%")
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()?;
    rt.block_on(async_main(cfg, workers, source, &cli))
}

async fn async_main(
    cfg: Config,
    workers: usize,
    wsrc: &str,
    cli: &Cli,
) -> Result<(), Box<dyn Error>> {
    let started = Instant::now();
    let judge = Judge::open(cfg.asn_db.as_deref(), cfg.city_db.as_deref())?;
    let geo_state = match (cfg.asn_db.as_deref(), cfg.city_db.as_deref()) {
        (Some(_), Some(_)) => "geo asn+city".to_string(),
        (Some(path), None) => format!("geo asn {path}"),
        (None, Some(path)) => format!("geo city {path}"),
        (None, None) => "geo off".to_string(),
    };
    qprintln!(
        "proxalyze {} · workers {workers} ({wsrc}) · {geo_state}",
        env!("CARGO_PKG_VERSION"),
    );
    let t_parse = Instant::now();
    let (registry, per_file, total_resolved, total_unresolved) =
        load_candidates(&cfg, cli.resolve_hostnames).await?;
    let dupes = registry.dupes;
    let mut candidates = registry.into_candidates();
    let total_mal: usize = per_file.iter().map(|(_, _, m, _)| m).sum();
    let total_hosts: usize = per_file.iter().map(|(_, _, _, h)| h).sum();
    for (path, kept, mal, hosts) in &per_file {
        let mut note = if *mal > 0 {
            format!(" \u{b7} {mal} declared malformed dropped")
        } else {
            String::new()
        };
        if *hosts > 0 {
            let suffix = if cli.resolve_hostnames {
                format!(" \u{b7} {hosts} hostname lines")
            } else {
                format!(
                    " \u{b7} {hosts} hostname lines (skipped: no DNS \u{2014} pass --resolve-hostnames)"
                )
            };
            note.push_str(&suffix);
        }
        qprintln!("[parse ] {path:<36} {:>8} kept{note}", fmt_n(*kept));
    }
    let host_summary = if total_hosts > 0 && cli.resolve_hostnames {
        format!(" \u{b7} {total_resolved} resolved / {total_unresolved} unresolved")
    } else if total_hosts > 0 {
        format!(
            " \u{b7} {total_hosts} hostname lines (skipped: no DNS \u{2014} pass --resolve-hostnames)"
        )
    } else {
        String::new()
    };
    qprintln!(
        "[parse ] {} files \u{b7} {} unique candidates ({} dupes{}){} in {:.1}s \u{b7} check {}",
        per_file.len(),
        fmt_n(candidates.len()),
        fmt_n(dupes),
        if total_mal > 0 {
            format!(", {total_mal} malformed")
        } else {
            String::new()
        },
        host_summary,
        t_parse.elapsed().as_secs_f64(),
        cfg.validate.check_url
    );
    let mut reused = Vec::new();
    let mut reused_by_input = HashMap::new();
    if cli.skip_recent > 0 {
        let path = std::path::Path::new(&cfg.output.dir).join("proxies.jsonl");
        if !path.exists() {
            qeprintln!("[skip ] no previous output · checking all");
        } else {
            let (previous, skipped) = read_records(&path)?;
            if skipped > 0 {
                qeprintln!("[skip ] {skipped} prior records unreadable · ignored");
            }
            (candidates, reused, reused_by_input) =
                partition_recent(candidates, &previous, now_secs(), cli.skip_recent);
        }
    }
    let total = candidates.len();
    let parse_secs = t_parse.elapsed().as_secs_f64();
    let t_check = Instant::now();
    // An all-reused incremental run has no probes to verify. A parse-empty run
    // still constructs the Validator so primary-target health is measured.
    let (mut records, stats, per_target, labels, slot_caps, slot_errors) =
        if total == 0 && !reused.is_empty() {
            qprintln!(
                "[check ] 0 candidates to probe · reusing {} fresh",
                reused.len()
            );
            (
                Vec::new(),
                Stats::default(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )
        } else {
            check_all(&cfg, candidates, &judge).await?
        };
    let check_secs = t_check.elapsed().as_secs_f64();
    if stats.received != total {
        return Err(format!(
            "integrity: {} results for {total} candidates",
            stats.received
        )
        .into());
    }
    let expected = stats.live_total() + stats.auth_required;
    if records.len() != expected {
        return Err(format!(
            "integrity: {} records for {expected} reportable",
            records.len()
        )
        .into());
    }
    records.extend(reused.iter().cloned());
    let reportable_before_filters = records.len();
    // PRE-filter: the guard keeps its original meaning — only a run with zero
    // candidates AND nothing carried forward skips writing. A pooled run
    // filtered down to zero still falls through and writes EMPTY files.
    let pooled_empty = records.is_empty();
    let t_write = Instant::now();
    sort_records(&mut records);
    let filtered = output::apply_filters(&mut records, &cfg.filters);
    let written = if total == 0 && pooled_empty {
        qprintln!("[write ] 0 candidates \u{b7} existing outputs left untouched");
        None
    } else {
        let dir = std::path::Path::new(&cfg.output.dir);
        std::fs::create_dir_all(dir)?;
        Some(write_out(dir, &cfg.output, &records)?)
    };
    if let Some(written) = written {
        let files: Vec<String> = written
            .iter()
            .map(|p| {
                let size = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
                format!("{} ({} bytes)", p, fmt_n(size))
            })
            .collect();
        qprintln!(
            "[write ] {} in {:.2}s",
            files.join(" \u{b7} "),
            t_write.elapsed().as_secs_f64()
        );
    }
    qprintln!(
        "[done  ] {:.1}s total (parse {:.2} \u{b7} check {check_secs:.1} \u{b7} write {:.2})",
        started.elapsed().as_secs_f64(),
        parse_secs,
        t_write.elapsed().as_secs_f64(),
    );
    summary(
        &stats,
        &(&per_file, &per_target, &labels, &slot_caps, &slot_errors),
        reportable_before_filters,
        filtered,
        total,
        reused.len(),
        &reused_by_input,
        &cfg,
    );
    // Live survivors AFTER filters — what actually landed in the outputs.
    let kept_live = records
        .iter()
        .filter(|record| !record.tags.contains(&"auth-required"))
        .count();
    if cli.min_live > 0 && kept_live < cli.min_live {
        qeprintln!(
            "min-live: {} live < required {}",
            fmt_n(kept_live),
            fmt_n(cli.min_live)
        );
        std::process::exit(3);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use model::Scheme;
    use std::cell::Cell;

    fn host(name: &str, port: u16, scheme: Scheme, auth: Option<model::Auth>) -> HostEntry {
        HostEntry {
            host: name.to_string(),
            port,
            scheme,
            auth,
        }
    }

    #[test]
    fn backup_url_resolution_uses_defaults_when_no_backups_are_given() {
        let resolved = resolve_backup_urls(&[]);

        assert_eq!(
            resolved,
            vec![
                "https://api.ipify.org".to_string(),
                "https://checkip.amazonaws.com".to_string(),
            ]
        );
    }

    #[test]
    fn backup_url_resolution_disables_backups_for_a_bare_empty_value() {
        let resolved = resolve_backup_urls(&["".to_string()]);

        assert_eq!(resolved, Vec::<String>::new());
    }

    #[test]
    fn backup_url_resolution_drops_empty_entries_when_mixed_with_real_values() {
        let resolved = resolve_backup_urls(&["https://a.example/x".to_string(), "".to_string()]);

        assert_eq!(resolved, vec!["https://a.example/x"]);
    }

    #[test]
    fn backup_url_resolution_preserves_two_real_values() {
        let resolved = resolve_backup_urls(&[
            "https://one.example".to_string(),
            "https://two.example".to_string(),
        ]);

        assert_eq!(resolved, vec!["https://one.example", "https://two.example"]);
    }

    #[test]
    fn cli_min_live_defaults_to_zero() {
        let cli = Cli::parse_from(["proxalyze"]);

        assert_eq!(cli.min_live, 0);
    }

    #[test]
    fn cli_parses_min_live_override() {
        let cli = Cli::parse_from(["proxalyze", "--min-live", "50"]);

        assert_eq!(cli.min_live, 50);
    }

    #[test]
    fn stdin_input_expands_to_exact_stdin_path() {
        let inputs = expand_inputs("-").unwrap();

        assert_eq!(inputs, vec![std::path::PathBuf::from("-")]);
    }

    #[test]
    fn resolver_error_counts_one_unresolved_and_adds_no_candidate() {
        let hosts = [host("proxy.example", 8080, Scheme::Http, None)];
        let mut registry = Registry::new();
        let mut cache = HashMap::new();
        let calls = Cell::new(0);

        let result =
            resolve_host_entries(&[(&hosts, "test")], 0, &mut registry, &mut cache, |_, _| {
                calls.set(calls.get() + 1);
                Err(std::io::Error::other("lookup failed"))
            });

        assert_eq!(calls.get(), 1);
        assert_eq!((result.0, result.1, result.2), (0, 1, 0));
        assert!(registry.into_candidates().is_empty());
    }

    #[test]
    fn resolver_empty_success_counts_one_unresolved_and_adds_no_candidate() {
        let hosts = [host("proxy.example", 8080, Scheme::Http, None)];
        let mut registry = Registry::new();
        let mut cache = HashMap::new();
        let calls = Cell::new(0);

        let result =
            resolve_host_entries(&[(&hosts, "test")], 0, &mut registry, &mut cache, |_, _| {
                calls.set(calls.get() + 1);
                Ok(vec![])
            });

        assert_eq!(calls.get(), 1);
        assert_eq!((result.0, result.1, result.2), (0, 1, 0));
        assert!(registry.into_candidates().is_empty());
    }

    #[test]
    fn resolver_cache_reuses_host_port_across_entry_groups() {
        let first = [host("proxy.example", 8080, Scheme::Http, None)];
        let second = [host(
            "proxy.example",
            8080,
            Scheme::Http,
            Some(model::Auth {
                user: "user".into(),
                password: Some("pass".into()),
            }),
        )];
        let mut registry = Registry::new();
        let mut cache = HashMap::new();
        let calls = Cell::new(0);

        let result = resolve_host_entries(
            &[(&first, "first"), (&second, "second")],
            0,
            &mut registry,
            &mut cache,
            |_, _| {
                calls.set(calls.get() + 1);
                Ok(vec!["192.0.2.10".parse().unwrap()])
            },
        );

        assert_eq!(calls.get(), 1);
        assert_eq!((result.0, result.1, result.2), (2, 0, 2));
    }

    #[test]
    fn resolver_cache_keeps_different_ports_independent() {
        let first = [host("proxy.example", 8080, Scheme::Http, None)];
        let second = [host("proxy.example", 8081, Scheme::Http, None)];
        let mut registry = Registry::new();
        let mut cache = HashMap::new();
        let calls = Cell::new(0);

        let result = resolve_host_entries(
            &[(&first, "first"), (&second, "second")],
            0,
            &mut registry,
            &mut cache,
            |_, _| {
                calls.set(calls.get() + 1);
                Ok(vec!["192.0.2.10".parse().unwrap()])
            },
        );

        assert_eq!(calls.get(), 2);
        assert_eq!((result.0, result.1, result.2), (2, 0, 2));
    }
    #[test]
    fn future_record_is_fresh() {
        assert!(is_fresh(100, 10_100, 3_600));
    }

    #[test]
    fn skip_recent_partitions_matching_fresh_records() {
        let now = 1_700_000_100;
        let cases = [
            ("http://192.0.2.1:8080", None),
            (
                "http://user:pass@192.0.2.3:8080",
                Some(model::Auth {
                    user: "user".into(),
                    password: Some("pass".into()),
                }),
            ),
            (
                "http://user:@192.0.2.4:8080",
                Some(model::Auth {
                    user: "user".into(),
                    password: Some("".into()),
                }),
            ),
            (
                "http://user@192.0.2.2:8080",
                Some(model::Auth {
                    user: "user".into(),
                    password: None,
                }),
            ),
        ];
        let mut candidates = Vec::new();
        let mut records = Vec::new();
        for (proxy, auth) in cases {
            let tail = proxy.split_once("://").unwrap().1;
            let address = tail.rsplit_once('@').map_or(tail, |(_, a)| a);
            candidates.push(
                Candidate::new(
                    address.parse().unwrap(),
                    Scheme::Http,
                    auth.clone(),
                    "pool.txt".into(),
                )
                .with_input_row(0),
            );
            let label = auth
                .as_ref()
                .map(ToString::to_string)
                .map(|a| format!("{a}@"))
                .unwrap_or_default();
            records.push(model::LiveRecord {
                proxy: format!("http://{label}{address}"),
                type_: "http",
                last_checked: now,
                speed_ms: 10,
                connect_ms: 4,
                ttfb_ms: Some(6),
                anonymity: Some("elite"),
                exit_ip: Some(address.rsplit_once(':').unwrap().0.parse().unwrap()),
                asn: None,
                org: None,
                tags: vec![],
                source: "pool.txt".into(),
                country: None,
            });
        }
        candidates.push(
            Candidate::new(
                "192.0.2.9:8080".parse().unwrap(),
                Scheme::Http,
                None,
                "pool.txt".into(),
            )
            .with_input_row(0),
        );
        let (probed, reused, reused_by_input) = partition_recent(candidates, &records, now, 3_600);
        assert_eq!(probed.len(), 1);
        assert_eq!(probed[0].addr, "192.0.2.9:8080".parse().unwrap());
        assert_eq!(reused.len(), 4);
        assert_eq!(reused_by_input.get(&0), Some(&4));
    }

    #[test]
    fn persisted_empty_user_matches_bare_candidate_key() {
        let bare = model::record_key("http", "192.0.2.10:8080".parse().unwrap(), None);
        let mut record = model::LiveRecord {
            proxy: "http://192.0.2.10:8080".into(),
            type_: "http",
            last_checked: 0,
            speed_ms: 1,
            connect_ms: 1,
            ttfb_ms: None,
            anonymity: None,
            exit_ip: None,
            asn: None,
            org: None,
            tags: vec![],
            source: "pool.txt".into(),
            country: None,
        };
        record.proxy = "http://:pass@192.0.2.10:8080".into();
        assert_eq!(
            persisted_record_key(&record).as_deref(),
            Some(bare.as_str())
        );
    }

    #[test]
    fn input_checked_subtracts_row_specific_reuse() {
        assert_eq!(input_checked(10, 10), 0);
        assert_eq!(input_checked(10, 4), 6);
        assert_eq!(input_checked(10, 0), 10);
    }

    #[test]
    fn freshness_boundary_is_inclusive() {
        assert!(is_fresh(10_000, 6_400, 3_600));
        assert!(!is_fresh(10_000, 6_399, 3_600));
    }

    #[test]
    fn inline_scheme_reuse_is_attributed_to_source_row() {
        let now = 1_700_000_100;
        let candidate = Candidate::new(
            "192.0.2.42:1080".parse().unwrap(),
            Scheme::Socks5,
            None,
            "inline.txt".into(),
        )
        .with_input_row(7);
        let record = model::LiveRecord {
            proxy: "socks5://192.0.2.42:1080".into(),
            type_: "socks5",
            last_checked: now,
            speed_ms: 1,
            connect_ms: 1,
            ttfb_ms: None,
            anonymity: None,
            exit_ip: None,
            asn: None,
            org: None,
            tags: vec![],
            source: "inline.txt".into(),
            country: None,
        };
        let (probed, reused, by_row) = partition_recent(vec![candidate], &[record], now, 3_600);
        assert!(probed.is_empty());
        assert_eq!(reused.len(), 1);
        assert_eq!(by_row.get(&7), Some(&1));
        assert_eq!(input_checked(1, by_row[&7]), 0);
    }

    #[test]
    fn cli_parses_skip_recent() {
        let cli = Cli::parse_from(["proxalyze", "--skip-recent", "42"]);
        assert_eq!(cli.skip_recent, 42);
    }
}
