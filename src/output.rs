//! Output stage: raw data, two files.
//!
//!   OUT/proxies.txt     scheme://[user:pass@]ip:port — every survivor
//!   OUT/proxies.jsonl   one raw record per line: source, timings, anonymity,
//!                       exit IP, ASN, org, network-class tags, optional country
//!
//! Order is deterministic (protocol, IP, port) so runs diff cleanly. Both
//! files are rewritten every run.

use std::error::Error;
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;

use serde_json::Value;

use crate::config::{Filters, Output};
use crate::model::{KNOWN_TAGS, LiveRecord};

/// Read persisted JSONL records, counting malformed or version-skew lines.
pub fn read_records(path: &Path) -> Result<(Vec<LiveRecord>, usize), String> {
    let body = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut records = Vec::new();
    let mut skipped = 0;
    for raw_line in body.split(|byte| *byte == b'\n') {
        let Ok(line) = std::str::from_utf8(raw_line) else {
            skipped += 1;
            continue;
        };
        if line.trim().is_empty() {
            continue;
        }
        match decode_record(line) {
            Ok(record) => records.push(record),
            Err(_) => skipped += 1,
        }
    }
    Ok((records, skipped))
}

fn decode_record(line: &str) -> Result<LiveRecord, String> {
    let value: Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
    let proxy = value["proxy"].as_str().ok_or("missing proxy")?.to_owned();
    let type_ = match value["type"].as_str() {
        Some("http") => "http",
        Some("https") => "https",
        Some("socks4") => "socks4",
        Some("socks5") => "socks5",
        _ => return Err("unknown proxy type".into()),
    };
    if proxy.split_once("://").map(|(scheme, _)| scheme) != Some(type_) {
        return Err("proxy/type scheme mismatch".into());
    }
    let tags = value["tags"]
        .as_array()
        .ok_or_else(|| "missing tags".to_string())?
        .iter()
        .map(|tag| {
            let tag = tag.as_str().ok_or("invalid tag")?;
            KNOWN_TAGS
                .iter()
                .copied()
                .find(|known| *known == tag)
                .ok_or_else(|| "unknown tag".to_string())
        })
        .collect::<Result<Vec<_>, String>>()?;
    let anonymity = match value.get("anonymity") {
        None | Some(Value::Null) => None,
        Some(value) => match value.as_str() {
            Some("elite") => Some("elite"),
            Some("anonymous") => Some("anonymous"),
            Some("transparent") => Some("transparent"),
            _ => return Err("unknown anonymity".into()),
        },
    };
    let optional_string = |name: &str| -> Result<Option<String>, String> {
        match value.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(value) => value
                .as_str()
                .map(str::to_owned)
                .map(Some)
                .ok_or_else(|| format!("invalid {name}")),
        }
    };
    let optional_u32 = |name: &str| -> Result<Option<u32>, String> {
        match value.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(value) => value
                .as_u64()
                .ok_or_else(|| format!("invalid {name}"))?
                .try_into()
                .map(Some)
                .map_err(|_| format!("{name} overflow")),
        }
    };
    let exit_ip = match value.get("exit_ip") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            value
                .as_str()
                .ok_or("invalid exit_ip")?
                .parse()
                .map_err(|_| "invalid exit_ip")?,
        ),
    };
    let runs_live = match value.get("runs_live") {
        None | Some(Value::Null) => 1,
        Some(value) => u32::try_from(value.as_u64().ok_or("invalid runs_live")?)
            .map_err(|_| "runs_live overflow")?,
    };
    let speed_tier = match value.get("speed_tier") {
        None | Some(Value::Null) => None,
        Some(value) => {
            let tier = value.as_str().ok_or("invalid speed_tier")?;
            Some(
                crate::model::SPEED_TIERS
                    .iter()
                    .copied()
                    .find(|known| *known == tier)
                    .ok_or("unknown speed_tier")?,
            )
        }
    };
    Ok(LiveRecord {
        proxy,
        type_,
        last_checked: value["last_checked"]
            .as_u64()
            .ok_or("missing last_checked")?,
        speed_ms: value["speed_ms"]
            .as_u64()
            .ok_or("missing speed_ms")?
            .try_into()
            .map_err(|_| "speed_ms overflow")?,
        connect_ms: value["connect_ms"]
            .as_u64()
            .ok_or("missing connect_ms")?
            .try_into()
            .map_err(|_| "connect_ms overflow")?,
        ttfb_ms: optional_u32("ttfb_ms")?,
        anonymity,
        exit_ip,
        asn: optional_u32("asn")?,
        org: optional_string("org")?,
        tags,
        source: match value.get("source") {
            None | Some(Value::Null) => "unknown".into(),
            Some(v) => v.as_str().ok_or("invalid source")?.into(),
        },
        country: optional_string("country")?,
        runs_live,
        kbps: optional_u32("kbps")?,
        speed_tier,
    })
}

fn scheme_key(s: &str) -> u8 {
    match s {
        "http" => 0,
        "https" => 1,
        "socks4" => 2,
        "socks5" => 3,
        _ => 9,
    }
}

fn hostport(proxy_url: &str) -> &str {
    proxy_url
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(proxy_url)
}

/// (ip, port) from the host[:port] tail; unparseable sorts last, never panics.
fn addr_of(proxy_url: &str) -> (Option<SocketAddr>, &str) {
    let hp = hostport(proxy_url);
    (hp.rsplit_once('@').map_or(hp, |(_, a)| a).parse().ok(), hp)
}

/// 0 elite · 1 anonymous · 2 transparent · 3 live-unjudged · 4 auth-required
fn rank(r: &LiveRecord) -> u8 {
    if r.tags.contains(&"auth-required") {
        return 4;
    }
    match r.anonymity {
        Some("elite") => 0,
        Some("anonymous") => 1,
        Some("transparent") => 2,
        _ => 3,
    }
}

pub fn sort_records(records: &mut [LiveRecord]) {
    records.sort_by(|a, b| {
        let ka = (rank(a), a.speed_ms, scheme_key(a.type_), addr_of(&a.proxy));
        let kb = (rank(b), b.speed_ms, scheme_key(b.type_), addr_of(&b.proxy));
        ka.cmp(&kb)
    });
}

/// Apply the write-stage filters in the spec-mandated order — require ALL,
/// exclude NONE, speed, anonymity floor, country — then truncate to
/// `keep_top`. Four gates share one retain pass; `keep_top` truncates
/// afterwards so it sees the ranked head of the surviving list.
/// Returns `(kept, dropped)`.
pub fn apply_filters(records: &mut Vec<LiveRecord>, f: &Filters) -> (usize, usize) {
    let before = records.len();
    if f.is_active() {
        let require = &f.require_tags;
        let exclude = &f.exclude_tags;
        let max_speed = f.max_speed;
        let floor = f.min_anonymity.as_deref().map(str::trim).map(|a| match a {
            "anonymous" => 1u8,
            _ => 0u8,
        });
        let countries = &f.countries;
        records.retain(|r| {
            if !require.iter().all(|t| r.tags.iter().any(|x| x == t)) {
                return false;
            }
            if exclude.iter().any(|t| r.tags.iter().any(|x| x == t)) {
                return false;
            }
            if max_speed.is_some_and(|max| r.speed_ms > max) {
                return false;
            }
            if floor.is_some_and(|floor| rank(r) > floor) {
                return false;
            }
            if !countries.is_empty() {
                // Every arm must decide: a record with a country outside the
                // list is dropped, not merely "kept with a country".
                let wanted = match r.country.as_deref() {
                    Some(c) => countries
                        .iter()
                        .any(|w| w.trim().eq_ignore_ascii_case(c.trim())),
                    None => false,
                };
                if !wanted {
                    return false;
                }
            }
            true
        });
        if let Some(n) = f.keep_top {
            records.truncate(n);
        }
    }
    (records.len(), before - records.len())
}

#[cfg(unix)]
fn open_opts() -> std::fs::OpenOptions {
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true).mode(0o600);
    opts
}

#[cfg(not(unix))]
fn open_opts() -> std::fs::OpenOptions {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    opts
}

fn write_atomic(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    // unique per process AND per file: with_extension("tmp") would collide
    // proxies.txt <-> proxies.jsonl on "proxies.tmp" and across concurrent runs
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "out".into());
    let tmp = path.with_file_name(format!("{name}.{}.tmp", std::process::id()));
    let result = (|| -> std::io::Result<()> {
        let mut f = std::io::BufWriter::new(open_opts().open(&tmp)?);
        // .mode() only applies on creation — a stale wide tmp from a crashed
        // run must be tightened explicitly:
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(contents)?;
        f.flush()?;
        f.get_ref().sync_all()?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(error);
    }
    if let Err(error) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(error);
    }
    Ok(())
}

/// Push one RFC 4180 cell: quoted only when it carries a delimiter, a quote
/// or a newline, with inner quotes doubled. Writes straight into `out` so a
/// row costs no intermediate `String` per column.
fn push_csv_cell(out: &mut String, value: &str) {
    if value.contains([',', '"', '\r', '\n']) {
        out.push('"');
        for ch in value.chars() {
            if ch == '"' {
                out.push_str("\"\"");
            } else {
                out.push(ch);
            }
        }
        out.push('"');
    } else {
        out.push_str(value);
    }
}

/// Fixed CSV column set. `runs_live`/`kbps` (Task 3 schema) stay JSONL-only:
/// CSV is the stable interchange shape.
pub fn render_csv(records: &[LiveRecord]) -> String {
    use std::fmt::Write as _;
    let mut out = String::from(
        "proxy,type,last_checked,speed_ms,connect_ms,ttfb_ms,anonymity,exit_ip,asn,org,tags,source,country\n",
    );
    for r in records {
        // Every column is written positionally; absent optionals push nothing
        // between the commas, so the row keeps a stable 13-cell shape.
        push_csv_cell(&mut out, &r.proxy);
        out.push(',');
        push_csv_cell(&mut out, r.type_);
        out.push(',');
        let _ = write!(out, "{}", r.last_checked);
        out.push(',');
        let _ = write!(out, "{}", r.speed_ms);
        out.push(',');
        let _ = write!(out, "{}", r.connect_ms);
        out.push(',');
        if let Some(v) = r.ttfb_ms {
            let _ = write!(out, "{v}");
        }
        out.push(',');
        push_csv_cell(&mut out, r.anonymity.unwrap_or_default());
        out.push(',');
        if let Some(ip) = r.exit_ip {
            let _ = write!(out, "{ip}");
        }
        out.push(',');
        if let Some(asn) = r.asn {
            let _ = write!(out, "{asn}");
        }
        out.push(',');
        push_csv_cell(&mut out, r.org.as_deref().unwrap_or_default());
        out.push(',');
        push_csv_cell(&mut out, &r.tags.join(";"));
        out.push(',');
        push_csv_cell(&mut out, r.source.as_str());
        out.push(',');
        push_csv_cell(&mut out, r.country.as_deref().unwrap_or_default());
        out.push('\n');
    }
    out
}

/// Single-quoted shell word: a literal `'` closes, escapes, and reopens.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// One runnable `curl -x` command per record.
pub fn render_curl(records: &[LiveRecord], check_url: &str) -> String {
    let mut out = String::new();
    for r in records {
        out.push_str(&format!(
            "curl -x {} {} -sS\n",
            shell_quote(&r.proxy),
            shell_quote(check_url)
        ));
    }
    out
}
/// JS double-quoted literal body: a proxy reaching `render_playwright` can
/// carry `"` or `\` (decode_record validates nothing), and interpolating it
/// raw would terminate the string early.
fn js_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(ch),
        }
    }
    out
}

/// JS array literal of `--proxy-server=` args (trailing commas are valid JS).
pub fn render_playwright(records: &[LiveRecord]) -> String {
    let mut out = String::from("[\n");
    for r in records {
        out.push_str("  \"--proxy-server=");
        out.push_str(&js_quote(&r.proxy));
        out.push_str("\",\n");
    }
    out.push_str("]\n");
    out
}

/// One JSONL row of run stats. Every field is always written so a consumer
/// never has to distinguish "absent" from "zero".
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct HistoryRow {
    pub run_ts: u64,
    pub live: usize,
    pub elite: usize,
    pub anonymous: usize,
    pub transparent: usize,
    pub unjudged: usize,
    pub auth: usize,
    pub tls_fail: usize,
    pub socks_rejected: usize,
    pub tcp_alive: usize,
    pub dead: usize,
    pub median_speed_ms: Option<u32>,
    pub kept: usize,
    pub dropped: usize,
    pub pool_size: usize,
    pub added: usize,
    pub removed: usize,
}

/// Append one row to `dir/history.jsonl`, returning how many PRE-EXISTING
/// lines failed to parse. The file is never rewritten: a malformed or
/// truncated prior line survives verbatim, because a read-and-reserialize
/// pass would silently destroy history.
pub fn append_history(dir: &Path, row: &HistoryRow) -> Result<usize, String> {
    let path = dir.join("history.jsonl");
    let mut skipped = 0;
    // A file left unterminated by an interrupted run would otherwise have the
    // new row fused onto its torn last line, corrupting BOTH.
    let mut unterminated = false;
    if path.exists() {
        let body = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        for raw in body.split(|b| *b == b'\n') {
            if raw.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            if std::str::from_utf8(raw)
                .ok()
                .and_then(|line| serde_json::from_str::<HistoryRow>(line).ok())
                .is_none()
            {
                skipped += 1;
            }
        }
        unterminated = !body.is_empty() && !body.ends_with(b"\n");
    }
    let line = serde_json::to_string(row).map_err(|e| format!("history row: {e}"))?;
    let mut f = open_opts()
        .append(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if unterminated {
        f.write_all(b"\n")
            .map_err(|e| format!("{}: {e}", path.display()))?;
    }
    f.write_all(line.as_bytes())
        .and_then(|()| f.write_all(b"\n"))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(skipped)
}

/// Median `speed_ms` over live records; an even count takes the lower middle.
/// `auth-required` records are excluded — their timing came from a 407, not
/// from a completed check.
pub fn median_speed(records: &[LiveRecord]) -> Option<u32> {
    let mut speeds: Vec<u32> = records
        .iter()
        .filter(|r| !r.tags.contains(&"auth-required"))
        .map(|r| r.speed_ms)
        .collect();
    speeds.sort_unstable();
    // Lower median: the even-length case takes the element BELOW the midpoint
    // (10,20,30,40 → 20, not 30).
    if speeds.is_empty() {
        return None;
    }
    speeds.get((speeds.len() - 1) / 2).copied()
}

pub fn write_out(
    dir: &Path,
    cfg: &Output,
    records: &[LiveRecord],
    check_url: &str,
) -> Result<Vec<String>, Box<dyn Error>> {
    // Validate every format BEFORE the first write: a bad renderer name must
    // not leave a half-updated directory behind. Unreachable via
    // `Config::check`, but `write_out` is a public entry point.
    for format in &cfg.emit {
        if !matches!(format.as_str(), "curl" | "playwright") {
            return Err(format!("--emit FORMAT must be curl or playwright (got {format})").into());
        }
    }
    let path = dir.join("proxies.txt");
    let jpath = dir.join("proxies.jsonl");
    let mut txt_bytes = Vec::new();
    for r in records {
        txt_bytes.extend_from_slice(r.proxy.as_bytes());
        txt_bytes.push(b'\n');
    }
    let mut jsonl_bytes = Vec::new();
    for r in records {
        jsonl_bytes.extend_from_slice(&serde_json::to_vec(r)?);
        jsonl_bytes.push(b'\n');
    }
    write_atomic(&path, &txt_bytes)?;
    write_atomic(&jpath, &jsonl_bytes)?;
    let mut written = vec![path.display().to_string(), jpath.display().to_string()];
    if cfg.csv {
        let cpath = dir.join("proxies.csv");
        write_atomic(&cpath, render_csv(records).as_bytes())?;
        written.push(cpath.display().to_string());
    }
    for format in &cfg.emit {
        let epath = dir.join(format!("proxies.{format}"));
        let body = match format.as_str() {
            "playwright" => render_playwright(records),
            // validated above
            _ => render_curl(records, check_url),
        };
        write_atomic(&epath, body.as_bytes())?;
        written.push(epath.display().to_string());
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Stats;

    fn rec(scheme: &str, addr: &str) -> LiveRecord {
        LiveRecord {
            proxy: format!("{scheme}://{addr}"),
            type_: match scheme {
                "http" => "http",
                "socks5" => "socks5",
                _ => "https",
            },
            last_checked: 0,
            speed_ms: 0,
            connect_ms: 0,
            ttfb_ms: None,
            anonymity: None,
            exit_ip: None,
            asn: None,
            org: None,
            source: "examples/sample.txt".into(),
            country: None,
            tags: vec![],
            runs_live: 1,
            kbps: None,
            speed_tier: None,
        }
    }
    #[test]
    fn read_records_round_trips_every_field() {
        let dir = std::env::temp_dir().join(format!("pxz-read-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let record = LiveRecord {
            proxy: "socks4://user:p%40ss@192.0.2.1:1080".into(),
            type_: "socks4",
            last_checked: 1_700_000_123,
            speed_ms: 41,
            connect_ms: 17,
            ttfb_ms: Some(29),
            anonymity: Some("anonymous"),
            exit_ip: Some("198.51.100.8".parse().unwrap()),
            asn: Some(64512),
            org: Some("Example Network".into()),
            source: "pool.txt".into(),
            country: Some("US".into()),
            tags: vec!["vpn", "residential-proxy"],
            runs_live: 1,
            kbps: None,
            speed_tier: None,
        };
        write_out(
            &dir,
            &crate::config::Output::default(),
            std::slice::from_ref(&record),
            "https://check.example/ip",
        )
        .unwrap();
        let (back, skipped) = read_records(&dir.join("proxies.jsonl")).unwrap();
        assert_eq!(skipped, 0);
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].proxy, record.proxy);
        assert_eq!(back[0].type_, record.type_);
        assert_eq!(back[0].last_checked, record.last_checked);
        assert_eq!(back[0].speed_ms, record.speed_ms);
        assert_eq!(back[0].connect_ms, record.connect_ms);
        assert_eq!(back[0].ttfb_ms, record.ttfb_ms);
        assert_eq!(back[0].anonymity, record.anonymity);
        assert_eq!(back[0].exit_ip, record.exit_ip);
        assert_eq!(back[0].asn, record.asn);
        assert_eq!(back[0].org, record.org);
        assert_eq!(back[0].source, record.source);
        assert_eq!(back[0].country, record.country);
        assert_eq!(back[0].tags, record.tags);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A pre-upgrade row: no `runs_live`, no `kbps`, no `speed_tier`. It must
    /// still decode — a `runs_live` of 1 is the honest default, and the line
    /// must NOT be counted as skipped.
    #[test]
    fn legacy_row_decodes_with_default_runs_live() {
        let line = r#"{"proxy":"http://203.0.113.10:8080","type":"http","last_checked":1789165501,"speed_ms":457,"connect_ms":128,"ttfb_ms":110,"anonymity":"elite","exit_ip":"203.0.113.10","asn":64512,"org":"Documentation Example ISP","tags":[],"source":"examples/sample.txt"}"#;
        let record = decode_record(line).expect("legacy row must decode");
        assert_eq!(record.runs_live, 1);
        assert_eq!(record.kbps, None);
        assert_eq!(record.speed_tier, None);
    }

    #[test]
    fn new_fields_round_trip_through_write_and_read() {
        let dir = std::env::temp_dir().join(format!("pxz-newfields-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut record = rec("http", "192.0.2.7:8080");
        record.runs_live = 3;
        record.kbps = Some(2048);
        record.speed_tier = Some("fast");
        write_out(
            &dir,
            &crate::config::Output::default(),
            std::slice::from_ref(&record),
            "https://check.example/ip",
        )
        .unwrap();
        let raw = std::fs::read_to_string(dir.join("proxies.jsonl")).unwrap();
        let written: serde_json::Value = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        assert_eq!(written["runs_live"], 3);
        assert_eq!(written["kbps"], 2048);
        assert_eq!(written["speed_tier"], "fast");
        let (back, skipped) = read_records(&dir.join("proxies.jsonl")).unwrap();
        assert_eq!(skipped, 0);
        assert_eq!(back[0].runs_live, 3);
        assert_eq!(back[0].kbps, Some(2048));
        assert_eq!(back[0].speed_tier, Some("fast"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Strict interning: an unrecognized `speed_tier` is a version-skew line,
    /// counted as skipped — never silently coerced to a valid tier.
    #[test]
    fn unknown_speed_tier_is_skipped_not_mangled() {
        let dir = std::env::temp_dir().join(format!("pxz-tierskip-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let good = r#"{"proxy":"http://192.0.2.8:8080","type":"http","last_checked":1,"speed_ms":10,"connect_ms":5,"tags":[],"source":"s.txt"}"#;
        let bad = r#"{"proxy":"http://192.0.2.9:8080","type":"http","last_checked":1,"speed_ms":10,"connect_ms":5,"speed_tier":"warp","tags":[],"source":"s.txt"}"#;
        std::fs::write(dir.join("proxies.jsonl"), format!("{good}\n{bad}\n")).unwrap();
        let (records, skipped) = read_records(&dir.join("proxies.jsonl")).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(skipped, 1);
        assert_eq!(records[0].speed_tier, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn new_tags_intern_via_known_tags_decoder() {
        let line = r#"{"proxy":"http://192.0.2.11:8080","type":"http","last_checked":1,"speed_ms":10,"connect_ms":5,"tags":["stable","keep-alive","chunked-post"],"source":"s.txt"}"#;
        let record = decode_record(line).expect("extended tags must intern");
        assert_eq!(record.tags, vec!["stable", "keep-alive", "chunked-post"]);
        for tag in &record.tags {
            assert!(
                crate::model::KNOWN_TAGS.contains(tag),
                "{tag} did not intern through KNOWN_TAGS"
            );
        }
    }

    #[test]
    fn read_records_skips_unknown_tag_without_mangling_type() {
        let dir = std::env::temp_dir().join(format!("pxz-unknown-tag-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("proxies.jsonl");
        std::fs::write(&path, br#"{"proxy":"socks4://192.0.2.1:1080","type":"socks4","last_checked":1,"speed_ms":1,"connect_ms":1,"ttfb_ms":null,"anonymity":null,"exit_ip":null,"tags":["quantum"],"source":"x"}"#).unwrap();
        let (records, skipped) = read_records(&path).unwrap();
        assert!(records.is_empty());
        assert_eq!(skipped, 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn read_records_skips_truncated_final_line() {
        let dir = std::env::temp_dir().join(format!("pxz-torn-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("proxies.jsonl");
        let complete = serde_json::to_string(&rec("http", "192.0.2.2:8080")).unwrap();
        let mut bytes = complete.into_bytes();
        bytes.extend_from_slice(b"\n{\"proxy\":");
        bytes.push(0xff);
        std::fs::write(&path, bytes).unwrap();
        let (records, skipped) = read_records(&path).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].proxy, "http://192.0.2.2:8080");
        assert_eq!(skipped, 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    fn fixture_bytes(mutations: &[(&str, &str)]) -> Vec<u8> {
        let base = br#"{"proxy":"http://192.0.2.20:8080","type":"http","last_checked":1,"speed_ms":1,"connect_ms":1,"ttfb_ms":1,"anonymity":null,"exit_ip":null,"asn":null,"org":null,"tags":[],"source":"x","country":null}"#;
        let mut line = String::from_utf8(base.to_vec()).unwrap();
        for (field, replacement) in mutations {
            let start = line.find(&format!("\"{field}\":")).unwrap() + field.len() + 3;
            let end = line[start..].find([',', '}']).unwrap() + start;
            line.replace_range(start..end, replacement);
        }
        line.into_bytes()
    }

    fn assert_skipped(line: &[u8], name: &str) {
        let path = std::env::temp_dir().join(format!("pxz-{name}-{}", std::process::id()));
        std::fs::write(&path, line).unwrap();
        let (records, skipped) = read_records(&path).unwrap();
        assert!(records.is_empty(), "{name} record was reused");
        assert_eq!(skipped, 1, "{name}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn read_records_rejects_non_utf8_in_complete_json() {
        let mut line = fixture_bytes(&[("org", "\"badorg\"")]);
        let position = line.windows(3).position(|window| window == b"bad").unwrap() + 3;
        line.splice(position..position, [0xff]);
        assert_skipped(&line, "strict-utf8");
    }

    #[test]
    fn read_records_rejects_u32_overflow() {
        for field in ["speed_ms", "connect_ms", "ttfb_ms", "asn"] {
            assert_skipped(
                &fixture_bytes(&[(field, "4294967296")]),
                &format!("overflow-{field}"),
            );
        }
    }

    #[test]
    fn read_records_rejects_present_invalid_optionals() {
        for (field, value) in [
            ("ttfb_ms", "\"nope\""),
            ("exit_ip", "\"not-an-ip\""),
            ("asn", "-1"),
            ("org", "123"),
            ("country", "123"),
        ] {
            assert_skipped(
                &fixture_bytes(&[(field, value)]),
                &format!("invalid-{field}"),
            );
        }
    }

    #[test]
    fn read_records_accepts_absent_and_null_optionals() {
        let path = std::env::temp_dir().join(format!("pxz-null-optionals-{}", std::process::id()));
        let without = br#"{"proxy":"http://192.0.2.20:8080","type":"http","last_checked":1,"speed_ms":1,"connect_ms":1,"anonymity":null,"tags":[],"source":"x"}"#.to_vec();
        std::fs::write(
            &path,
            [without, b"\n".to_vec(), fixture_bytes(&[])].concat(),
        )
        .unwrap();
        let (records, skipped) = read_records(&path).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(skipped, 0);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn read_records_rejects_unknown_anonymity_but_accepts_null() {
        assert_skipped(
            &fixture_bytes(&[("anonymity", "\"banana\"")]),
            "unknown-anonymity",
        );
        let path = std::env::temp_dir().join(format!("pxz-null-anonymity-{}", std::process::id()));
        std::fs::write(&path, fixture_bytes(&[])).unwrap();
        let (records, skipped) = read_records(&path).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].anonymity, None);
        assert_eq!(skipped, 0);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn read_records_rejects_proxy_type_scheme_mismatch() {
        assert_skipped(&fixture_bytes(&[("type", "\"socks4\"")]), "scheme-mismatch");
    }

    #[test]
    fn output_files_are_owner_only() {
        let dir = std::env::temp_dir().join(format!("pxz-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let r = rec("http", "1.2.3.4:80");
        write_out(
            &dir,
            &crate::config::Output {
                csv: true,
                emit: vec!["curl".into(), "playwright".into()],
                ..Default::default()
            },
            std::slice::from_ref(&r),
            "https://check.example/ip",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for f in [
                "proxies.txt",
                "proxies.jsonl",
                "proxies.csv",
                "proxies.curl",
                "proxies.playwright",
            ] {
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
        write_out(
            &dir,
            &crate::config::Output::default(),
            &[],
            "https://check.example/ip",
        )
        .unwrap();
        assert!(
            nested.join("keep.txt").exists(),
            "unrelated dir was deleted"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn order_is_deterministic_by_protocol_then_address() {
        let mut v = vec![
            rec("socks5", "1.1.1.1:1080"),
            rec("http", "9.9.9.9:80"),
            rec("http", "2.2.2.2:8080"),
        ];
        sort_records(&mut v);
        assert_eq!(
            v.iter().map(|r| r.proxy.as_str()).collect::<Vec<_>>(),
            vec![
                "http://2.2.2.2:8080",
                "http://9.9.9.9:80",
                "socks5://1.1.1.1:1080"
            ]
        );
    }

    /// The checked-in dummy outputs must stay honest: same row set and order
    /// as proxies.txt, keys of the real schema, classification semantics per
    /// validate::classify, credentials that exist in the sample input, and an
    /// order that survives the real sort_records. CI runs this on every push.
    #[test]
    fn checked_in_samples_stay_self_consistent() {
        let jsonl_raw = include_str!("../examples/out/proxies.jsonl");
        let txt_raw = include_str!("../examples/out/proxies.txt");
        let input_raw = include_str!("../examples/sample.txt");
        let rows: Vec<serde_json::Value> = jsonl_raw
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let txt: Vec<&str> = txt_raw.lines().filter(|l| !l.trim().is_empty()).collect();
        // 1) file order equals what the real sorter produces for these rows
        let intern_anon = |s: Option<&str>| -> Option<&'static str> {
            match s {
                Some("elite") => Some("elite"),
                Some("anonymous") => Some("anonymous"),
                Some("transparent") => Some("transparent"),
                _ => None,
            }
        };
        let intern_tag = |s: &str| -> &'static str {
            match s {
                "hosting" => "hosting",
                "auth-required" => "auth-required",
                "cdn" => "cdn",
                "mobile" => "mobile",
                "vpn" => "vpn",
                _ => "residential-proxy",
            }
        };
        let mut sorted: Vec<LiveRecord> = rows
            .iter()
            .map(|r| LiveRecord {
                proxy: r["proxy"].as_str().unwrap().to_string(),
                type_: "http",
                last_checked: 0,
                speed_ms: r["speed_ms"].as_u64().unwrap() as u32,
                connect_ms: 0,
                ttfb_ms: None,
                anonymity: intern_anon(r["anonymity"].as_str()),
                exit_ip: None,
                asn: None,
                source: r["source"]
                    .as_str()
                    .expect("checked-in row missing mandatory source")
                    .to_string(),
                country: None,
                org: None,
                tags: r["tags"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|t| intern_tag(t.as_str().unwrap()))
                    .collect(),
                runs_live: 1,
                kbps: None,
                speed_tier: None,
            })
            .collect();
        sort_records(&mut sorted);
        let order_after: Vec<&str> = sorted.iter().map(|r| r.proxy.as_str()).collect();
        let order_file: Vec<&str> = rows.iter().map(|r| r["proxy"].as_str().unwrap()).collect();
        assert_eq!(
            order_after, order_file,
            "sample rows must already be in best-first order"
        );
        // 2) proxies.txt and proxies.jsonl describe identical survivors, same order
        assert_eq!(
            txt, order_file,
            "proxies.txt rows must equal jsonl proxy rows"
        );
        // 3) schema keys exactly the emittable set; classification is self-consistent
        for r in &rows {
            let keys: std::collections::BTreeSet<String> =
                r.as_object().unwrap().keys().cloned().collect();
            let expected: std::collections::BTreeSet<String> = [
                "proxy",
                "type",
                "last_checked",
                "speed_ms",
                "connect_ms",
                "ttfb_ms",
                "anonymity",
                "exit_ip",
                "asn",
                "org",
                "tags",
                "source",
                "country",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect();
            assert!(keys.is_subset(&expected), "unexpected key in {r}");
            assert!(keys.contains("source"), "row missing mandatory source: {r}");
            assert!(expected.iter().any(|k| keys.contains(k)));
            let proxy = r["proxy"].as_str().unwrap();
            let host = proxy
                .split("://")
                .nth(1)
                .unwrap()
                .rsplit('@')
                .next()
                .unwrap();
            let hostip = host.rsplit(':').nth(1).unwrap();
            let anon = r["anonymity"].as_str();
            let exit = r["exit_ip"].as_str();
            let auth = r["tags"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t == "auth-required");
            match (anon, auth) {
                (Some("elite"), _) => {
                    assert_eq!(exit, Some(hostip), "elite exit_ip must equal proxy ip: {r}")
                }
                (Some("anonymous"), _) => assert!(
                    exit.is_some() && exit != Some(hostip),
                    "anonymous needs NAT-distinct exit: {r}"
                ),
                (None, true) => assert!(exit.is_none(), "auth-required rows carry no exit: {r}"),
                (Some("transparent"), false) => {
                    assert!(exit.is_some(), "transparent needs an exit: {r}")
                }
                (Some(_), _) | (None, false) => panic!("no other shape is valid: {r}"),
            }
            // 4) credentials in outputs must exist in the input that produced them
            if proxy.contains('@') {
                assert!(
                    input_raw.contains(
                        proxy
                            .split("://")
                            .nth(1)
                            .unwrap()
                            .split('@')
                            .next()
                            .unwrap()
                    ),
                    "credential {proxy} absent from sample.txt"
                );
            }
        }
        // 5) input placeholders must not parse into phantom candidates
        let comment_candidates =
            crate::parse::parse_proxies(input_raw.as_bytes(), crate::model::Scheme::Http);
        assert_eq!(
            comment_candidates.len(),
            3,
            "sample.txt comments leaked parseable patterns"
        );
    }

    #[test]
    fn stats_percentile_edges() {
        let s = Stats::default();
        assert_eq!(Stats::percentile(&s.live_total_ms, 0.5), 0);
        assert_eq!(Stats::percentile(&[1, 2, 3, 4], 1.0), 4);
    }

    fn tagged(tags: &'static [&'static str]) -> LiveRecord {
        let mut r = rec("http", "192.0.2.1:8080");
        r.tags = tags.to_vec();
        r
    }

    /// A record with a distinct identity, so "which record survived" is
    /// checkable rather than merely "how many did".
    fn ident(last: u8, tags: &'static [&'static str]) -> LiveRecord {
        let mut r = rec("http", &format!("192.0.2.{last}:8080"));
        r.tags = tags.to_vec();
        r
    }

    fn addrs(records: &[LiveRecord]) -> Vec<&str> {
        records.iter().map(|r| r.proxy.as_str()).collect()
    }

    fn with_speed(ms: u32) -> LiveRecord {
        let mut r = tagged(&[]);
        r.speed_ms = ms;
        r
    }

    #[test]
    fn require_and_exclude_tag_gates() {
        let mut v = vec![tagged(&["hosting"])];
        let f = Filters {
            require_tags: vec!["hosting".into()],
            ..Default::default()
        };
        assert_eq!(apply_filters(&mut v, &f), (1, 0));

        let mut v = vec![tagged(&["hosting"])];
        let f = Filters {
            require_tags: vec!["cdn".into()],
            ..Default::default()
        };
        assert_eq!(apply_filters(&mut v, &f), (0, 1));

        let mut v = vec![tagged(&["hosting"])];
        let f = Filters {
            exclude_tags: vec!["hosting".into()],
            ..Default::default()
        };
        assert_eq!(apply_filters(&mut v, &f), (0, 1));
    }

    #[test]
    fn require_and_exclude_on_same_tag_drops_record() {
        let mut v = vec![tagged(&["hosting"])];
        let f = Filters {
            require_tags: vec!["hosting".into()],
            exclude_tags: vec!["hosting".into()],
            ..Default::default()
        };
        assert_eq!(apply_filters(&mut v, &f), (0, 1));
    }

    #[test]
    fn max_speed_drops_slow_and_keeps_boundary() {
        let mut v = vec![with_speed(100), with_speed(500), with_speed(501)];
        let f = Filters {
            max_speed: Some(500),
            ..Default::default()
        };
        assert_eq!(apply_filters(&mut v, &f), (2, 1));
    }

    #[test]
    fn min_anonymity_floor_elite_drops_transparent_unjudged_auth() {
        let recs = [
            (1u8, "elite", &[][..]),
            (2, "anonymous", &[][..]),
            (3, "transparent", &[][..]),
            (4, "", &[][..]),
            (5, "", &["auth-required"][..]),
        ];
        let mut v: Vec<LiveRecord> = recs
            .iter()
            .map(|(n, a, t)| {
                let mut r = ident(*n, t);
                r.anonymity = if a.is_empty() { None } else { Some(*a) };
                r
            })
            .collect();
        let f = Filters {
            min_anonymity: Some("elite".into()),
            ..Default::default()
        };
        assert_eq!(apply_filters(&mut v, &f), (1, 4));
        assert_eq!(
            addrs(&v),
            vec!["http://192.0.2.1:8080"],
            "only the elite record survives; anonymous/transparent/unjudged/auth all go"
        );
    }

    #[test]
    fn country_filter_keeps_only_listed_countries() {
        let mut fr = ident(1, &[]);
        fr.country = Some("FR".into());
        let mut de = ident(2, &[]);
        de.country = Some("DE".into());
        let mut us = ident(3, &[]);
        us.country = Some("US".into());
        let mut v = vec![fr, de, us, ident(4, &[])];
        let f = Filters {
            countries: vec!["fr".into(), "de".into()],
            ..Default::default()
        };
        assert_eq!(apply_filters(&mut v, &f), (2, 2));
        assert_eq!(
            addrs(&v),
            vec!["http://192.0.2.1:8080", "http://192.0.2.2:8080"],
            "US and the country-less record must both be dropped"
        );
    }

    #[test]
    fn tag_gates_select_the_matching_record_only() {
        let mut v = vec![ident(1, &["hosting"]), ident(2, &["cdn"])];
        let f = Filters {
            require_tags: vec!["hosting".into()],
            ..Default::default()
        };
        assert_eq!(apply_filters(&mut v, &f), (1, 1));
        assert_eq!(addrs(&v), vec!["http://192.0.2.1:8080"]);

        let mut v = vec![ident(1, &["hosting"]), ident(2, &["cdn"])];
        let f = Filters {
            exclude_tags: vec!["hosting".into()],
            ..Default::default()
        };
        assert_eq!(apply_filters(&mut v, &f), (1, 1));
        assert_eq!(addrs(&v), vec!["http://192.0.2.2:8080"]);
    }

    #[test]
    fn max_speed_keeps_exactly_the_in_boundary_set() {
        let mut v = vec![ident(1, &[]), ident(2, &[]), ident(3, &[])];
        for (i, ms) in [100u32, 500, 501].into_iter().enumerate() {
            v[i].speed_ms = ms;
        }
        let f = Filters {
            max_speed: Some(500),
            ..Default::default()
        };
        assert_eq!(apply_filters(&mut v, &f), (2, 1));
        assert_eq!(
            addrs(&v),
            vec!["http://192.0.2.1:8080", "http://192.0.2.2:8080"],
            "500 is the inclusive boundary; 501 must go"
        );
    }

    #[test]
    fn min_anonymity_floor_anonymous_keeps_two_ranks() {
        let recs = [
            (1u8, "elite", &[][..]),
            (2, "anonymous", &[][..]),
            (3, "transparent", &[][..]),
            (4, "", &[][..]),
            (5, "", &["auth-required"][..]),
        ];
        let mut v: Vec<LiveRecord> = recs
            .iter()
            .map(|(n, a, t)| {
                let mut r = ident(*n, t);
                r.anonymity = if a.is_empty() { None } else { Some(*a) };
                r
            })
            .collect();
        let f = Filters {
            min_anonymity: Some("anonymous".into()),
            ..Default::default()
        };
        assert_eq!(apply_filters(&mut v, &f), (2, 3));
        assert_eq!(
            addrs(&v),
            vec!["http://192.0.2.1:8080", "http://192.0.2.2:8080"],
            "the anonymous floor keeps ranks 0-1; transparent/unjudged/auth go"
        );
    }

    #[test]
    fn keep_top_truncates_sorted_prefix() {
        let mut v = vec![ident(1, &[]), ident(2, &[]), ident(3, &[])];
        for (i, ms) in [10u32, 20, 30].into_iter().enumerate() {
            v[i].speed_ms = ms;
        }
        let f = Filters {
            keep_top: Some(2),
            ..Default::default()
        };
        assert_eq!(apply_filters(&mut v, &f), (2, 1));
        assert_eq!(
            v.iter().map(|r| r.speed_ms).collect::<Vec<_>>(),
            vec![10, 20],
            "top-N must truncate the head of the already-sorted list"
        );
        assert_eq!(
            addrs(&v),
            vec!["http://192.0.2.1:8080", "http://192.0.2.2:8080"],
            "the two FASTEST records survive, not the first two by position"
        );
    }

    #[test]
    fn keep_top_zero_empties_and_counts_as_active() {
        let mut v = vec![ident(1, &[]), ident(2, &[]), ident(3, &[])];
        for (i, ms) in [10u32, 20, 30].into_iter().enumerate() {
            v[i].speed_ms = ms;
        }
        let f = Filters {
            keep_top: Some(0),
            ..Default::default()
        };
        assert_eq!(apply_filters(&mut v, &f), (0, 3));
        assert!(f.is_active());
        assert!(addrs(&v).is_empty(), "keep-top 0 must empty the list");
    }

    #[test]
    fn inactive_filters_change_nothing() {
        let mut v = vec![ident(1, &[]), ident(2, &[]), ident(3, &[])];
        for (i, ms) in [30u32, 10, 20].into_iter().enumerate() {
            v[i].speed_ms = ms;
        }
        let before = addrs(&v)
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        let f = Filters::default();
        assert_eq!(apply_filters(&mut v, &f), (3, 0));
        assert!(!f.is_active());
        assert_eq!(
            addrs(&v),
            before.iter().map(String::as_str).collect::<Vec<_>>(),
            "identity and order both preserved"
        );
    }

    fn rich(over: impl FnOnce(&mut LiveRecord)) -> LiveRecord {
        let mut r = rec("http", "192.0.2.7:8080");
        r.last_checked = 1_700_000_500;
        r.speed_ms = 120;
        r.connect_ms = 30;
        r.ttfb_ms = Some(90);
        r.anonymity = Some("elite");
        r.exit_ip = Some("192.0.2.7".parse().unwrap());
        r.asn = Some(64512);
        r.org = Some("Example \"Net\", Ltd".into());
        r.tags = vec!["vpn", "cdn"];
        r.country = Some("US".into());
        over(&mut r);
        r
    }

    fn history_row(added: usize, removed: usize) -> HistoryRow {
        HistoryRow {
            run_ts: 1_700_000_000,
            live: 4,
            elite: 1,
            anonymous: 2,
            transparent: 1,
            unjudged: 0,
            auth: 0,
            tls_fail: 1,
            socks_rejected: 0,
            tcp_alive: 2,
            dead: 3,
            median_speed_ms: Some(120),
            kept: 4,
            dropped: 1,
            pool_size: 4,
            added,
            removed,
        }
    }

    #[test]
    fn csv_quotes_commas_and_quotes() {
        let mut r = rich(|_| {});
        r.proxy = "http://user:pa,ss@192.0.2.7:8080".into();
        let csv = render_csv(&[r]);
        assert_eq!(
            csv.lines().next().unwrap(),
            "proxy,type,last_checked,speed_ms,connect_ms,ttfb_ms,anonymity,exit_ip,asn,org,tags,source,country"
        );
        assert!(
            csv.contains("\"http://user:pa,ss@192.0.2.7:8080\""),
            "a comma field must be quoted whole: {csv}"
        );
        assert!(
            csv.contains("\"Example \"\"Net\"\", Ltd\""),
            "embedded quotes must be doubled inside a quoted cell: {csv}"
        );
        assert!(csv.contains("vpn;cdn"), "tags join with a semicolon: {csv}");
    }

    #[test]
    fn csv_row_count_matches_record_count_plus_header() {
        let recs = [
            rich(|r| r.proxy = "http://192.0.2.1:8080".into()),
            rich(|r| r.proxy = "http://192.0.2.2:8080".into()),
            rich(|r| r.proxy = "http://192.0.2.3:8080".into()),
        ];
        let csv = render_csv(&recs);
        assert_eq!(csv.lines().count(), 4);
        assert!(csv.ends_with('\n'));
        assert_eq!(
            render_csv(&[]).lines().count(),
            1,
            "header alone for no records"
        );
    }

    #[test]
    fn csv_leaves_absent_optionals_as_empty_cells() {
        let mut r = rich(|_| {});
        r.ttfb_ms = None;
        r.asn = None;
        r.org = None;
        r.country = None;
        r.anonymity = None;
        r.exit_ip = None;
        let row = render_csv(&[r]);
        let cells: Vec<&str> = row.lines().nth(1).unwrap().split(',').collect();
        assert_eq!(cells.len(), 13);
        assert_eq!(cells[3], "120", "speed_ms is present");
        for empty in [cells[5], cells[6], cells[7], cells[8], cells[9], cells[12]] {
            assert_eq!(empty, "", "absent optional must render an empty cell");
        }
    }

    #[test]
    fn curl_escapes_single_quotes_in_credentials() {
        let mut r = rich(|_| {});
        r.proxy = "http://user:pa'ss@192.0.2.7:8080".into();
        let out = render_curl(&[r], "https://echo.example/ip");
        assert!(out.contains("curl -x '"));
        assert!(!out.contains("pa'ss"), "raw quote leaked: {out}");
        assert!(
            out.contains("pa'\\''ss"),
            "the quote must close, escape, reopen: {out}"
        );
        assert!(
            out.ends_with("' -sS\n"),
            "one complete line per record: {out}"
        );
    }

    #[test]
    fn curl_uses_the_check_url_verbatim() {
        let out = render_curl(&[rec("http", "1.2.3.4:8080")], "https://echo.example/ip");
        assert_eq!(
            out,
            "curl -x 'http://1.2.3.4:8080' 'https://echo.example/ip' -sS\n"
        );
    }

    #[test]
    fn playwright_emits_one_proxy_server_arg_per_record() {
        let out = render_playwright(&[rec("http", "1.2.3.4:8080"), rec("socks5", "5.6.7.8:1080")]);
        assert!(out.starts_with("[\n"));
        assert_eq!(out.matches("--proxy-server=").count(), 2);
        assert!(out.contains("  \"--proxy-server=http://1.2.3.4:8080\",\n"));
        assert!(out.ends_with("]\n"));
        assert_eq!(render_playwright(&[]), "[\n]\n");
    }

    #[test]
    fn playwright_escapes_quotes_and_backslashes_in_proxy() {
        // decode_record accepts ANY proxy string, so a --skip-recent record
        // can carry a quote or backslash. Interpolating it raw would end the
        // JS string early and emit invalid JavaScript.
        let mut r = rec("http", "1.2.3.4:8080");
        r.proxy = r#"http://user:p"a\ss@1.2.3.4:8080"#.into();
        let out = render_playwright(&[r]);
        assert_eq!(
            out,
            "[\n  \"--proxy-server=http://user:p\\\"a\\\\ss@1.2.3.4:8080\",\n]\n"
        );
        // the arg must not be terminated early: one record, one element
        assert_eq!(out.matches("\"--proxy-server=").count(), 1);
        assert!(out.ends_with("\",\n]\n"), "arg shape preserved: {out}");
    }

    #[test]
    fn history_terminates_an_unterminated_partial_line_before_appending() {
        let dir = std::env::temp_dir().join(format!("pxz-history-partial-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("history.jsonl");
        // An interrupted run leaves a torn line with no trailing newline.
        std::fs::write(&path, b"{\"run_ts\":1,\"liv").unwrap();

        assert_eq!(append_history(&dir, &history_row(2, 3)).unwrap(), 1);
        let body = std::fs::read(&path).unwrap();
        assert_eq!(
            body,
            [
                b"{\"run_ts\":1,\"liv\n".to_vec(),
                format!("{}\n", serde_json::to_string(&history_row(2, 3)).unwrap()).into_bytes(),
            ]
            .concat(),
            "the torn line must be closed, not fused with the new row"
        );
        // the new row is independently parseable, not concatenated garbage:
        // the file must hold exactly two non-empty lines
        let lines: Vec<&[u8]> = body
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .collect();
        assert_eq!(lines.len(), 2, "torn line and new row are separate");
        assert_eq!(
            serde_json::from_str::<HistoryRow>(std::str::from_utf8(lines[1]).unwrap()).unwrap(),
            history_row(2, 3)
        );
        assert_eq!(append_history(&dir, &history_row(0, 0)).unwrap(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn history_appends_one_line_and_leaves_malformed_lines_counted() {
        let dir = std::env::temp_dir().join(format!("pxz-history-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("history.jsonl");
        std::fs::write(&path, b"not json at all\n").unwrap();

        assert_eq!(append_history(&dir, &history_row(3, 1)).unwrap(), 1);
        let after_first = std::fs::read(&path).unwrap();
        assert_eq!(
            after_first,
            [
                b"not json at all\n".to_vec(),
                format!("{}\n", serde_json::to_string(&history_row(3, 1)).unwrap()).into_bytes(),
            ]
            .concat(),
            "the malformed line must survive byte-for-byte, ahead of the new row"
        );

        assert_eq!(append_history(&dir, &history_row(0, 2)).unwrap(), 1);
        let after_second = std::fs::read(&path).unwrap();
        assert!(
            after_second.starts_with(&after_first),
            "a second append must extend the file, never rewrite it"
        );
        assert_eq!(after_second.iter().filter(|b| **b == b'\n').count(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn history_counts_zero_skipped_for_a_clean_file() {
        let dir = std::env::temp_dir().join(format!("pxz-history-clean-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(append_history(&dir, &history_row(0, 0)).unwrap(), 0);
        assert_eq!(append_history(&dir, &history_row(0, 0)).unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn history_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("pxz-history-perm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        append_history(&dir, &history_row(1, 0)).unwrap();
        let mode = std::fs::metadata(dir.join("history.jsonl"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "history mode {:o}", mode & 0o777);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn median_speed_lower_median_on_even_counts() {
        let speeds = |values: &[u32]| -> Option<u32> {
            let recs: Vec<LiveRecord> = values
                .iter()
                .enumerate()
                .map(|(i, ms)| {
                    let mut r = rec("http", &format!("192.0.2.{}:8080", i + 1));
                    r.speed_ms = *ms;
                    r
                })
                .collect();
            median_speed(&recs)
        };
        assert_eq!(
            speeds(&[40, 10, 30, 20]),
            Some(20),
            "even count takes the lower middle"
        );
        assert_eq!(speeds(&[30, 10, 20]), Some(20));
        assert_eq!(speeds(&[]), None);
    }

    #[test]
    fn median_speed_ignores_auth_required_records() {
        let mut authed = rec("http", "192.0.2.9:8080");
        authed.speed_ms = 5;
        authed.tags = vec!["auth-required"];
        let mut live = rec("http", "192.0.2.10:8080");
        live.speed_ms = 100;
        assert_eq!(median_speed(&[authed, live]), Some(100));
    }
}
