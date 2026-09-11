//! Runtime configuration, built entirely from CLI arguments (see main.rs).
//! Plain structs here; clap flags are the user-facing surface.

use url::Url;

use crate::model::Scheme;

#[derive(Debug, Default)]
pub struct Config {
    pub debug: bool,
    pub inputs: Vec<InputFile>,
    pub validate: Validate,
    pub asn_db: Option<String>,
    pub output: Output,
}

#[derive(Debug, Clone)]
pub struct InputFile {
    pub path: String,
    /// Protocol for bare `ip:port` lines in this file. Inline `scheme://`
    /// prefixes always win per entry.
    pub scheme: String,
}

#[derive(Debug, Clone)]
pub struct Validate {
    /// Primary echo URL.
    pub check_url: String,
    /// Extra echoes, round-robin with the primary.
    pub backup_urls: Vec<String>,
    pub max_concurrent_checks: usize,
    /// total seconds per check (connect + whole response); never retried
    pub timeout: f64,
    /// Seconds to connect. 2.0 is the measured sweet spot: it retains every
    /// live dial (first-SYN-retransmit survivors land at 0.95-1.9 s) while
    /// cutting wall time ~35% vs 5.0; 1.0 clips live proxies.
    pub connect_timeout: f64,
}

/// GeoLite2-ASN database for network-class judgment. Auto-detected at
/// geo/GeoLite2-ASN.mmdb (cwd) and ~/.local/share/proxalyze/GeoLite2-ASN.mmdb;
/// absent = judgment from anonymity + latency only. Location is deliberately
/// not part of the judgment.
pub fn detect_asn_db() -> Option<String> {
    [
        "geo/GeoLite2-ASN.mmdb",
        "~/.local/share/proxalyze/GeoLite2-ASN.mmdb",
    ]
    .iter()
    .filter_map(|p| {
        let expanded = match p.strip_prefix("~") {
            Some(rest) => format!("{}{}", std::env::var("HOME").ok()?, rest),
            None => (*p).to_string(),
        };
        std::path::Path::new(&expanded).exists().then_some(expanded)
    })
    .next()
}

#[derive(Debug, Clone, Default)]
pub struct Output {
    pub dir: String,
}

impl Default for Validate {
    fn default() -> Self {
        Self {
            check_url: "https://ipv4.icanhazip.com".into(),
            backup_urls: vec![
                "https://api.ipify.org".into(),
                "https://checkip.amazonaws.com".into(),
            ],
            max_concurrent_checks: 512,
            timeout: 10.0,
            connect_timeout: 2.0,
        }
    }
}

/// Where and how to talk to the check target.
#[derive(Debug, Clone)]
pub struct CheckTarget {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub url: String,
}

impl Config {
    pub fn check(&self) -> Result<(), String> {
        if self.inputs.is_empty() {
            return Err("no input files (pass --input FILE[:scheme])".into());
        }
        for f in &self.inputs {
            if Scheme::from_claim(&f.scheme).is_none() {
                return Err(format!(
                    "{}: scheme \"{}\" invalid (http|https|socks4|socks5)",
                    f.path, f.scheme
                ));
            }
        }
        self.all_targets()?;
        if self.validate.max_concurrent_checks == 0 {
            return Err("--concurrency must be > 0".into());
        }
        Ok(())
    }

    /// Primary check_url first, then backups.
    pub fn all_targets(&self) -> Result<Vec<CheckTarget>, String> {
        let mut v = vec![parse_target(&self.validate.check_url)?];
        for b in &self.validate.backup_urls {
            if !b.trim().is_empty() {
                v.push(parse_target(b)?);
            }
        }
        Ok(v)
    }

    pub fn scheme_of(&self, f: &InputFile) -> Option<Scheme> {
        Scheme::from_claim(&f.scheme)
    }
}

pub fn parse_target(raw: &str) -> Result<CheckTarget, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("check url is required".into());
    }
    let u = Url::parse(raw).map_err(|e| format!("check url: {e}"))?;
    let tls = match u.scheme() {
        "https" => true,
        "http" => false,
        s => return Err(format!("check url scheme {s} unsupported")),
    };
    let host = u.host_str().ok_or("check url: no host")?.to_string();
    let port = u
        .port_or_known_default()
        .unwrap_or(if tls { 443 } else { 80 });
    let path = {
        let p = u.path();
        if p.is_empty() { "/" } else { p }.to_string()
    };
    Ok(CheckTarget {
        tls,
        host,
        port,
        path,
        url: raw.to_string(),
    })
}

/// Split `path[:scheme]`; the suffix only counts when it is a known scheme
/// (so Windows drive letters and bare paths survive untouched).
pub fn split_input_spec(s: &str) -> (String, Option<String>) {
    if let Some((path, sch)) = s.rsplit_once(':')
        && Scheme::from_claim(sch).is_some()
    {
        return (path.to_string(), Some(sch.to_ascii_lowercase()));
    }
    (s.to_string(), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_the_shipped_sweet_spot() {
        let v = Validate::default();
        assert_eq!(v.connect_timeout, 2.0);
        assert_eq!(v.max_concurrent_checks, 512);
        assert_eq!(v.backup_urls.len(), 2);
    }

    #[test]
    fn input_specs_with_and_without_scheme() {
        assert_eq!(
            split_input_spec("socks.txt:socks5"),
            ("socks.txt".into(), Some("socks5".into()))
        );
        assert_eq!(split_input_spec("plain.txt"), ("plain.txt".into(), None));
        assert_eq!(
            split_input_spec("C:/lists/prox.txt"),
            ("C:/lists/prox.txt".into(), None)
        );
        assert_eq!(
            split_input_spec("prox:http"),
            ("prox".into(), Some("http".into()))
        );
    }

    #[test]
    fn target_parses_and_rejects() {
        let t = parse_target("https://example.org/ip").unwrap();
        assert!(t.tls && t.port == 443 && t.path == "/ip");
        assert!(parse_target("ftp://x").is_err());
        assert!(parse_target("").is_err());
    }
}
