//! proxalyze — validate proxy lists into clean, judged proxies. Configuration
//! is command-line arguments only; the optional ASN judgment database is
//! auto-detected (geo/GeoLite2-ASN.mmdb), never flagged.
//!
//! Reads plain proxy files (each with a DECLARED protocol — nothing is
//! guessed), checks every proxy on a raw hyper connection against an echo
//! URL whose body reveals the exit IP, and writes raw data: proxy lists
//! plus one JSONL record per survivor with every fact learned (timings,
//! anonymity, exit IP, ASN, org, network-class tags). Run with --help.

mod config;
mod geo;
mod model;
mod output;
mod parse;
mod validate;

use std::error::Error;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use tokio::sync::mpsc;

use config::{Config, InputFile, detect_asn_db, split_input_spec};
use geo::Judge;
use model::{Candidate, ProbeResult, Registry, Stats};
use output::{sort_records, write_out};
use parse::parse_proxies;
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
    /// Additional echo endpoints, round-robin with the primary; pass "" to
    /// run with the primary alone (isolates echo problems)
    #[arg(long = "backup-url")]
    backup_urls: Vec<String>,

    /// Proxies checked at once (fd limit is raised automatically). Measured
    /// safe to 2048 on residential links; beyond that carrier SYN-limits can
    /// turn live proxies into false deads
    #[arg(short = 'j', long, default_value_t = 1024)]
    concurrency: usize,
    /// Total seconds per check, never retried
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
    let backup_urls = if cli.backup_urls.iter().any(|b| b.trim().is_empty()) {
        Vec::new()
    } else if cli.backup_urls.is_empty() {
        config::Validate::default().backup_urls
    } else {
        cli.backup_urls.clone()
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
        output: config::Output {
            dir: cli.out.clone(),
        },
    };
    cfg.check()?;
    Ok(cfg)
}

async fn load_candidates(cfg: &Config) -> Result<(Registry, Vec<(String, usize)>), Box<dyn Error>> {
    let mut registry = Registry::new();
    let mut per_file = Vec::new();
    for file in &cfg.inputs {
        let scheme = cfg.scheme_of(file).expect("validated in Config::check");
        for path in expand_inputs(&file.path)? {
            let body = std::fs::read(&path)?;
            let entries = parse_proxies(&body, scheme);
            let label = path.display().to_string();
            let kept = entries
                .into_iter()
                .filter(|e| {
                    registry.add(Candidate::new(
                        e.addr,
                        e.scheme,
                        e.auth.clone(),
                        label.clone(),
                    ))
                })
                .count();
            per_file.push((label, kept));
        }
    }
    Ok((registry, per_file))
}

/// --input accepts a directory too: all its .txt files share the declared scheme.
fn expand_inputs(path: &str) -> Result<Vec<std::path::PathBuf>, Box<dyn Error>> {
    let p = std::path::Path::new(path);
    if p.is_dir() {
        let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(p)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|f| f.extension().is_some_and(|x| x == "txt"))
            .collect();
        files.sort();
        if files.is_empty() {
            return Err(format!("{path}: directory has no .txt files").into());
        }
        return Ok(files);
    }
    Ok(vec![p.to_path_buf()])
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
    ),
    Box<dyn Error>,
> {
    let targets = cfg.all_targets()?;
    let check_cfg = CheckCfg::from_validate(&cfg.validate, cfg.debug)?;
    let validator = std::sync::Arc::new(Validator::new(check_cfg, targets).await?);
    let labels = validator.active_targets();
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
            tags,
        });
    }
    runner.await?;
    Ok((records, stats, per_target, labels))
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

fn summary(
    stats: &Stats,
    per_file: &[(String, usize)],
    per_target: &[(u64, u64, u64)],
    labels: &[String],
    records: usize,
    total: usize,
    cfg: &Config,
) {
    println!("summary");
    println!(
        "  verdict   live {} (elite {} \u{b7} anonymous {} \u{b7} transparent {}) \u{b7} auth {} \u{b7} tls-fail {} \u{b7} socks-rejected {} \u{b7} tcp-alive {} \u{b7} dead {}",
        fmt_n(stats.live_total()),
        fmt_n(stats.live_elite),
        fmt_n(stats.live_anonymous),
        fmt_n(stats.live_transparent),
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
        println!(
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
    if !labels.is_empty() {
        println!(
            "  echoes    cap {} in-flight each",
            cfg.validate
                .max_concurrent_checks
                .div_ceil(labels.len())
                .max(16)
        );
        for (i, url) in labels.iter().enumerate() {
            let (live, tlsf, sat) = per_target.get(i).copied().unwrap_or((0, 0, 0));
            println!(
                "            {url:<36} live {live:>5} \u{b7} tls-fail {tlsf:>5} \u{b7} permit-waits {sat}{}",
                if sat > 0 {
                    "  <- raise -j or add --backup-url"
                } else {
                    ""
                }
            );
        }
    }
    println!("  inputs");
    let mut any = false;
    for (path, kept) in per_file {
        let (live, checked) = stats.by_input.get(path).copied().unwrap_or((0, *kept));
        if *kept == 0 {
            continue;
        }
        any = true;
        println!(
            "            {path:<36} checked {:>7} \u{b7} live {:>5} ({:.1}%)",
            fmt_n(checked),
            fmt_n(live),
            100.0_f64 * live as f64 / checked.max(1) as f64
        );
    }
    if !any {
        println!("            (none)");
    }
    println!(
        "  integrity {}/{} results \u{2713} \u{b7} {} reportable \u{b7} {records} records \u{2713}",
        fmt_n(stats.received),
        fmt_n(total),
        fmt_n(stats.live_total() + stats.auth_required),
    );
}

fn main() -> Result<(), Box<dyn Error>> {
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
    rt.block_on(async_main(cfg, workers, source))
}

async fn async_main(cfg: Config, workers: usize, wsrc: &str) -> Result<(), Box<dyn Error>> {
    let started = Instant::now();
    let judge = Judge::open(cfg.asn_db.as_deref())?;
    println!(
        "proxalyze {} \u{b7} workers {workers} ({wsrc}){}",
        env!("CARGO_PKG_VERSION"),
        match &cfg.asn_db {
            Some(p) => format!(" \u{b7} geo {p}"),
            None => " \u{b7} geo off".into(),
        }
    );
    let t_parse = Instant::now();
    let (registry, per_file) = load_candidates(&cfg).await?;
    let dupes = registry.dupes;
    let candidates = registry.into_candidates();
    for (path, kept) in &per_file {
        println!("[parse ] {path:<36} {:>8} kept", fmt_n(*kept));
    }
    println!(
        "[parse ] {} files \u{b7} {} unique candidates ({} dupes) in {:.1}s \u{b7} check {}",
        per_file.len(),
        fmt_n(candidates.len()),
        fmt_n(dupes),
        t_parse.elapsed().as_secs_f64(),
        cfg.validate.check_url,
    );
    if candidates.is_empty() {
        return Err("no candidates".into());
    }
    let total = candidates.len();
    let parse_secs = t_parse.elapsed().as_secs_f64();
    let t_check = Instant::now();
    let (mut records, stats, per_target, labels) = check_all(&cfg, candidates, &judge).await?;
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
    summary(
        &stats,
        &per_file,
        &per_target,
        &labels,
        records.len(),
        total,
        &cfg,
    );
    let t_write = Instant::now();
    sort_records(&mut records);
    let dir = std::path::Path::new(&cfg.output.dir);
    std::fs::create_dir_all(dir)?;
    let written = write_out(dir, &cfg.output, &records)?;
    let files: Vec<String> = written
        .iter()
        .map(|p| {
            let size = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
            format!("{} ({} bytes)", p, fmt_n(size))
        })
        .collect();
    println!(
        "[write ] {} in {:.2}s",
        files.join(" \u{b7} "),
        t_write.elapsed().as_secs_f64()
    );
    println!(
        "[done  ] {:.1}s total (parse {:.2} \u{b7} check {check_secs:.1} \u{b7} write {:.2})",
        started.elapsed().as_secs_f64(),
        parse_secs,
        t_write.elapsed().as_secs_f64(),
    );
    Ok(())
}
