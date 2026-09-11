use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, SocketAddr};

/// Transport a proxy speaks. Always declared: by the input file's `scheme`
/// or an inline `socks5://` prefix — never guessed.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum Scheme {
    Http,
    Https,
    Socks4,
    Socks5,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
            Scheme::Socks4 => "socks4",
            Scheme::Socks5 => "socks5",
        }
    }

    /// Parse a scheme label (config value or inline prefix), lowercase.
    pub fn from_claim(s: &str) -> Option<Scheme> {
        match s.trim().to_ascii_lowercase().as_str() {
            "http" => Some(Scheme::Http),
            "https" => Some(Scheme::Https),
            "socks4" | "socks4a" => Some(Scheme::Socks4),
            "socks5" | "socks5h" | "socks" => Some(Scheme::Socks5),
            _ => None,
        }
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Credentials attached to a list entry (`user:pass@host:port`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Auth {
    pub user: String,
    pub password: Option<String>,
}

impl fmt::Display for Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.password {
            Some(p) => write!(f, "{}:{}", self.user, p),
            None => write!(f, "{}", self.user),
        }
    }
}

/// One candidate proxy, tagged with the input file it was parsed from.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub addr: SocketAddr,
    pub scheme: Scheme,
    pub auth: Option<Auth>,
    pub input: String,
}

impl Candidate {
    pub fn new(addr: SocketAddr, scheme: Scheme, auth: Option<Auth>, input: String) -> Self {
        Self {
            addr,
            scheme,
            auth,
            input,
        }
    }
}

/// Outcome of one check.
#[derive(serde::Serialize, Clone, Debug)]
pub struct ProbeResult {
    /// `user:pass@ip:port` when the entry carried credentials, else `ip:port`
    pub proxy: String,
    pub scheme: &'static str,
    pub input: String,
    /// live | auth-required | tls-fail | socks-rejected | tcp-alive | dead
    pub status: &'static str,
    /// elite | anonymous | transparent (live only)
    pub anonymity: Option<&'static str>,
    pub connect_ms: u32,
    pub ttfb_ms: Option<u32>,
    pub total_ms: u32,
    pub exit_ip: Option<IpAddr>,
    /// index of the echo target (slot) this probe used; -1 = never reached one
    pub slot: i16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail_reason: Option<String>,
}

/// A judged, live proxy as written to the output files.
#[derive(serde::Serialize, Clone, Debug)]
pub struct LiveRecord {
    /// scheme://[user:pass@]ip:port — directly usable by downstream tools
    pub proxy: String,
    #[serde(rename = "type")]
    pub type_: &'static str,
    pub last_checked: u64,
    pub speed_ms: u32,
    pub connect_ms: u32,
    pub ttfb_ms: Option<u32>,
    pub anonymity: Option<&'static str>,
    pub exit_ip: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    /// hosting | cdn | mobile | vpn | residential-proxy | auth-required
    pub tags: Vec<&'static str>,
}

/// Aggregated check stats printed at the end of a run.
#[derive(Default, Debug)]
pub struct Stats {
    pub received: usize,
    pub live_elite: usize,
    pub live_anonymous: usize,
    pub live_transparent: usize,
    pub auth_required: usize,
    pub tls_fail: usize,
    pub socks_rejected: usize,
    pub tcp_alive: usize,
    pub dead: usize,
    /// latency samples from LIVE probes only — mixing dead-probe connect
    /// windows into percentiles reads as "p50 connect 0ms" nonsense
    pub live_connect_ms: Vec<u32>,
    pub live_total_ms: Vec<u32>,
    pub by_input: HashMap<String, (usize, usize)>, // (live, checked)
}

impl Stats {
    pub fn record(&mut self, r: &ProbeResult) {
        self.received += 1;
        let e = self.by_input.entry(r.input.clone()).or_insert((0, 0));
        e.1 += 1;
        if r.status == "live" {
            e.0 += 1;
        }
        if r.status == "live" {
            self.live_connect_ms.push(r.connect_ms);
            self.live_total_ms.push(r.total_ms);
        }
        match (r.status, r.anonymity) {
            ("live", Some("elite")) => self.live_elite += 1,
            ("live", Some("anonymous")) => self.live_anonymous += 1,
            ("live", _) => self.live_transparent += 1,
            ("auth-required", _) => self.auth_required += 1,
            ("tls-fail", _) => self.tls_fail += 1,
            ("socks-rejected", _) => self.socks_rejected += 1,
            ("tcp-alive", _) => self.tcp_alive += 1,
            _ => self.dead += 1,
        }
    }

    pub fn live_total(&self) -> usize {
        self.live_elite + self.live_anonymous + self.live_transparent
    }

    pub fn percentile(sorted: &[u32], p: f64) -> u32 {
        if sorted.is_empty() {
            return 0;
        }
        let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
        sorted[idx]
    }
}

/// Deduplicates candidates across all input files (by address + scheme +
/// credentials: the same host with a different login is a different proxy).
pub struct Registry {
    seen: HashSet<(IpAddr, u16, Scheme, Option<String>)>,
    entries: Vec<Candidate>,
    pub dupes: u64,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            seen: HashSet::new(),
            entries: Vec::new(),
            dupes: 0,
        }
    }

    pub fn add(&mut self, c: Candidate) -> bool {
        let key = (
            c.addr.ip(),
            c.addr.port(),
            c.scheme,
            c.auth.as_ref().map(|a| a.to_string()),
        );
        if !self.seen.insert(key) {
            self.dupes += 1;
            return false;
        }
        self.entries.push(c);
        true
    }

    pub fn into_candidates(self) -> Vec<Candidate> {
        self.entries
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}
