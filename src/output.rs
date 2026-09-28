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
use crate::model::LiveRecord;

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
        .map(|tag| match tag.as_str() {
            Some("hosting") => Ok("hosting"),
            Some("cdn") => Ok("cdn"),
            Some("mobile") => Ok("mobile"),
            Some("vpn") => Ok("vpn"),
            Some("residential-proxy") => Ok("residential-proxy"),
            Some("auth-required") => Ok("auth-required"),
            _ => Err("unknown tag".into()),
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
        let floor = f
            .min_anonymity
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .map(|a| if a == "anonymous" { 1u8 } else { 0u8 });
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
                match r.country.as_deref() {
                    Some(c) => countries
                        .iter()
                        .any(|w| w.trim().eq_ignore_ascii_case(c.trim())),
                    None => return false,
                };
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

pub fn write_out(
    dir: &Path,
    _cfg: &Output,
    records: &[LiveRecord],
) -> Result<Vec<String>, Box<dyn Error>> {
    // Legacy proxies/ dir (pre-two-file format) is intentionally left in place: deleting an operator-named directory is not our call.
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
    Ok(vec![
        path.display().to_string(),
        jpath.display().to_string(),
    ])
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
        };
        write_out(
            &dir,
            &crate::config::Output::default(),
            std::slice::from_ref(&record),
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
            &crate::config::Output::default(),
            std::slice::from_ref(&r),
        )
        .unwrap();
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

    fn with_speed(ms: u32) -> LiveRecord {
        let mut r = tagged(&[]);
        r.speed_ms = ms;
        r
    }

    fn with_anonymity(kind: &'static str) -> LiveRecord {
        let mut r = tagged(&[]);
        r.anonymity = Some(kind);
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
        let mut v = vec![
            with_anonymity("elite"),
            with_anonymity("anonymous"),
            with_anonymity("transparent"),
            tagged(&[]),
            tagged(&["auth-required"]),
        ];
        let f = Filters {
            min_anonymity: Some("elite".into()),
            ..Default::default()
        };
        assert_eq!(apply_filters(&mut v, &f), (1, 4));
    }

    #[test]
    fn country_filter_drops_records_without_country() {
        let mut fr = tagged(&[]);
        fr.country = Some("FR".into());
        let mut v = vec![fr, tagged(&[])];
        let f = Filters {
            countries: vec!["fr".into()],
            ..Default::default()
        };
        assert_eq!(apply_filters(&mut v, &f), (1, 1));
    }

    #[test]
    fn keep_top_truncates_sorted_prefix() {
        let mut v = vec![with_speed(10), with_speed(20), with_speed(30)];
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
    }

    #[test]
    fn keep_top_zero_empties_and_counts_as_active() {
        let mut v = vec![with_speed(10), with_speed(20), with_speed(30)];
        let f = Filters {
            keep_top: Some(0),
            ..Default::default()
        };
        assert_eq!(apply_filters(&mut v, &f), (0, 3));
        assert!(f.is_active());
    }

    #[test]
    fn inactive_filters_change_nothing() {
        let mut v = vec![with_speed(30), with_speed(10), with_speed(20)];
        let before: Vec<u32> = v.iter().map(|r| r.speed_ms).collect();
        let f = Filters::default();
        assert_eq!(apply_filters(&mut v, &f), (3, 0));
        assert!(!f.is_active());
        let after: Vec<u32> = v.iter().map(|r| r.speed_ms).collect();
        assert_eq!(after, before);
    }
}
