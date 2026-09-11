//! Output stage: raw data, two files.
//!
//!   OUT/proxies.txt     scheme://[user:pass@]ip:port — every survivor
//!   OUT/proxies.jsonl   one raw record per line: timings, anonymity, exit
//!                       IP, ASN, org, network-class tags
//!
//! Order is deterministic (protocol, IP, port) so runs diff cleanly. Both
//! files are rewritten every run.

use std::error::Error;
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;

use crate::config::Output;
use crate::model::LiveRecord;

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

pub fn write_out(
    dir: &Path,
    _cfg: &Output,
    records: &[LiveRecord],
) -> Result<Vec<String>, Box<dyn Error>> {
    // Older runs wrote a proxies/ directory; the format is two files now.
    let stale = dir.join("proxies");
    if stale.exists() {
        std::fs::remove_dir_all(&stale)?;
    }
    let path = dir.join("proxies.txt");
    let mut f = std::io::BufWriter::new(std::fs::File::create(&path)?);
    for r in records {
        writeln!(f, "{}", r.proxy)?;
    }
    f.flush()?;

    let jpath = dir.join("proxies.jsonl");
    let mut jf = std::io::BufWriter::new(std::fs::File::create(&jpath)?);
    for r in records {
        serde_json::to_writer(&mut jf, r)?;
        jf.write_all(b"\n")?;
    }
    jf.flush()?;
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
            tags: vec![],
        }
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
            ]
            .iter()
            .map(|s| s.to_string())
            .collect();
            assert!(keys.is_subset(&expected), "unexpected key in {r}");
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
}
