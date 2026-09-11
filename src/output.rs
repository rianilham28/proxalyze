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

    #[test]
    fn stats_percentile_edges() {
        let s = Stats::default();
        assert_eq!(Stats::percentile(&s.live_total_ms, 0.5), 0);
        assert_eq!(Stats::percentile(&[1, 2, 3, 4], 1.0), 4);
    }
}
