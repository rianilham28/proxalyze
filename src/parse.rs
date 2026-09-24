//! Proxy-list text parser. Addresses are pattern-matched out of any text,
//! but nothing here guesses *protocols*: a bare `ip:port` inherits the
//! scheme declared for its input file, while an inline `socks5://ip:port`
//! (or http/https/socks4) always wins for that entry. Credentials
//! (`user:pass@`) are carried through as authentication to try.
//!
//! Recognized forms (the config contract):
//!   1.2.3.4:8080
//!   1.2.3.4,8080
//!   1.2.3.4:8080:user[:pass]
//!   socks5://1.2.3.4:1080
//!   socks5://user:pass@1.2.3.4:1080
//!   user:pass@1.2.3.4:8080              (scheme from the file claim)
//!   hostname.example:8080              (reported separately; no implicit DNS)
//!   [2001:db8::1]:3128
//!   1.2.3.0/24:8080                   CIDR /16..=/32, expanded to hosts
//!   03.161.30.65:82                   zero-padded octets are normalized
//!
//! Credential characters are preserved exactly except for the structural
//! delimiters required to identify each supported format.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::model::{Auth, Scheme};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub addr: SocketAddr,
    pub scheme: Scheme,
    pub auth: Option<Auth>,
}

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
    pub malformed: usize,
    pub hosts: Vec<HostEntry>,
}

#[cfg(test)]
pub fn parse_proxies(body: &[u8], claim: Scheme) -> Vec<Entry> {
    parse_proxies_stats(body, claim).entries
}

pub fn parse_proxies_stats(body: &[u8], claim: Scheme) -> Parsed {
    let body = strip_comments(body);
    let (mut entries, mut malformed, mut hosts) = (Vec::new(), 0, Vec::new());
    let rejected = scan_prefixed(&body, claim, &mut entries, &mut hosts, &mut malformed);
    let prefixed_addrs: HashSet<SocketAddr> =
        entries.iter().map(|e| e.addr).chain(rejected).collect();
    let mut seen: HashSet<(SocketAddr, Scheme, Option<String>)> = entries
        .iter()
        .map(|e| (e.addr, e.scheme, e.auth.as_ref().map(ToString::to_string)))
        .collect();
    for (addr, auth) in scan_bare(&body) {
        if auth.is_none() && prefixed_addrs.contains(&addr) {
            continue;
        }
        let key = (addr, claim, auth.as_ref().map(ToString::to_string));
        if seen.insert(key) {
            entries.push(Entry {
                addr,
                scheme: claim,
                auth,
            });
        }
    }
    hosts.extend(scan_host_lines(&body, claim));
    Parsed {
        entries,
        malformed,
        hosts,
    }
}

fn strip_comments(body: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    let lines: Vec<&[u8]> = body.split(|&b| b == b'\n').collect();
    if !lines.iter().any(|l| {
        l.iter()
            .find(|b| !b.is_ascii_whitespace())
            .is_some_and(|&b| matches!(b, b'#' | b';'))
    }) {
        return std::borrow::Cow::Borrowed(body);
    }
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let is_comment = line
            .iter()
            .find(|b| !b.is_ascii_whitespace())
            .is_some_and(|&b| matches!(b, b'#' | b';'));
        if !is_comment {
            out.extend_from_slice(line);
            if i + 1 < lines.len() {
                out.push(b'\n');
            }
        }
    }
    std::borrow::Cow::Owned(out)
}

fn scan_prefixed(
    body: &[u8],
    claim: Scheme,
    out: &mut Vec<Entry>,
    hosts: &mut Vec<HostEntry>,
    mal: &mut usize,
) -> HashSet<SocketAddr> {
    let mut rejected = HashSet::new();
    let keep = |b: u8| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'.' | b':'
                    | b'/'
                    | b'@'
                    | b'-'
                    | b'_'
                    | b'['
                    | b']'
                    | b'+'
                    | b'='
                    | b'%'
                    | b'!'
                    | b'#'
                    | b'$'
                    | b'&'
                    | b'*'
                    | b'('
                    | b')'
                    | b'~'
            )
    };
    let mut start = None;
    for i in 0..=body.len() {
        if i < body.len() && keep(body[i]) {
            start.get_or_insert(i);
            continue;
        }
        let Some(s) = start.take() else { continue };
        let tok = String::from_utf8_lossy(&body[s..i]);
        let (scheme, rest, has_scheme_prefix) = if let Some((sch, rest)) = tok.split_once("://") {
            let Some(scheme) = Scheme::from_claim(sch) else {
                continue;
            };
            (scheme, rest, true)
        } else if tok.contains('@') {
            (claim, tok.as_ref(), false)
        } else {
            continue;
        };
        let (auth, hostport) = split_auth(rest);
        let hostport = hostport.split('/').next().unwrap_or(hostport);
        let hostport = hostport.split_once('#').map_or(hostport, |(host, _)| host);
        if !has_scheme_prefix {
            rejected.extend(parse_addr_str(hostport));
            if rest
                .rsplit_once('@')
                .is_none_or(|(creds, _)| !creds.contains(':'))
            {
                continue;
            }
            if auth.is_none() {
                continue;
            }
        }
        if let Some(addr) = parse_addr_str(hostport) {
            out.push(Entry { addr, scheme, auth });
        } else if proxy_ish(hostport) {
            push_unresolved(hostport, scheme, auth, hosts, mal);
        }
    }
    rejected
}

fn push_unresolved(
    hp: &str,
    scheme: Scheme,
    auth: Option<Auth>,
    hosts: &mut Vec<HostEntry>,
    mal: &mut usize,
) {
    let Some((host, port)) = hp.rsplit_once(':') else {
        *mal += 1;
        return;
    };
    if host.bytes().any(|b| b.is_ascii_alphabetic())
        && !host.contains(':')
        && let Ok(port) = port.parse::<u16>()
        && (1..=65535).contains(&port)
    {
        hosts.push(HostEntry {
            host: host.to_ascii_lowercase(),
            port,
            scheme,
            auth,
        });
    } else {
        *mal += 1;
    }
}

fn split_auth(s: &str) -> (Option<Auth>, &str) {
    match s.rsplit_once('@') {
        Some((creds, hp)) => {
            let (user, password) = match creds.split_once(':') {
                Some((u, p)) => (u.to_string(), Some(p.to_string())),
                None => (creds.to_string(), None),
            };
            if user.is_empty() {
                (None, hp)
            } else {
                (Some(Auth { user, password }), hp)
            }
        }
        None => (None, s),
    }
}

fn scan_bare(body: &[u8]) -> Vec<(SocketAddr, Option<Auth>)> {
    let mut out = Vec::new();
    let mut start = None;
    let keep = |b: u8| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'.' | b':'
                    | b'/'
                    | b'['
                    | b']'
                    | b','
                    | b'-'
                    | b'_'
                    | b'+'
                    | b'='
                    | b'%'
                    | b'!'
                    | b'#'
                    | b'$'
                    | b'&'
                    | b'*'
                    | b'('
                    | b')'
                    | b'~'
            )
    };
    for i in 0..=body.len() {
        if i < body.len() && keep(body[i]) {
            start.get_or_insert(i);
        } else if let Some(s) = start.take() {
            extend_token(&body[s..i], &mut out);
        }
    }
    out
}

fn extend_token(tok: &[u8], out: &mut Vec<(SocketAddr, Option<Auth>)>) {
    let t = String::from_utf8_lossy(tok);
    if let Some(addr) = parse_addr_str(&t) {
        out.push((addr, None));
        return;
    }
    if let Some((cidr, port)) = t.split_once(':')
        && let Some((net, prefix)) = cidr.split_once('/')
    {
        let prefix: u8 = prefix.parse().unwrap_or(64);
        if let (Some(net), Ok(port)) = (parse_v4_lenient(net), port.parse::<u16>())
            && (16..=32).contains(&prefix)
        {
            for h in expand_v4(net, prefix) {
                out.push((SocketAddr::new(h, port), None));
            }
            return;
        }
    }
    if let Some((ip, port)) = t.split_once(',')
        && parse_v4_lenient(ip).is_some()
        && let Ok(port) = port.parse::<u16>()
    {
        if let Some(a) = parse_addr_str(&format!("{ip}:{port}")) {
            out.push((a, None));
        }
        return;
    }
    let p: Vec<&str> = t.splitn(4, ':').collect();
    if (p.len() == 3 || p.len() == 4)
        && let Some(a) = parse_addr_str(&format!("{}:{}", p[0], p[1]))
        && !p[2].is_empty()
    {
        out.push((
            a,
            Some(Auth {
                user: p[2].to_string(),
                password: p
                    .get(3)
                    .and_then(|x| (!x.is_empty()).then(|| (*x).to_string())),
            }),
        ));
        return;
    }
    if t.contains(',') {
        for cell in t.split(',') {
            extend_cell(cell, out);
        }
    }
}

fn extend_cell(t: &str, out: &mut Vec<(SocketAddr, Option<Auth>)>) {
    if let Some(a) = parse_addr_str(t) {
        out.push((a, None));
        return;
    }
    let p: Vec<&str> = t.splitn(4, ':').collect();
    if (p.len() == 3 || p.len() == 4)
        && let Some(a) = parse_addr_str(&format!("{}:{}", p[0], p[1]))
        && !p[2].is_empty()
    {
        out.push((
            a,
            Some(Auth {
                user: p[2].to_string(),
                password: p
                    .get(3)
                    .and_then(|x| (!x.is_empty()).then(|| (*x).to_string())),
            }),
        ));
    }
}

fn scan_host_lines(body: &[u8], claim: Scheme) -> Vec<HostEntry> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for raw in body.split(|&b| b == b'\n') {
        let line = String::from_utf8_lossy(raw);
        let line = line.trim();
        if line.is_empty()
            || line.contains("://")
            || line.contains('@')
            || line.split_whitespace().count() != 1
        {
            continue;
        }
        let Some((host, port_s)) = line.rsplit_once(':') else {
            continue;
        };
        let Ok(port) = port_s.parse::<u16>() else {
            continue;
        };
        if !(1..=65535).contains(&port) {
            continue;
        }
        if host.is_empty()
            || host.contains(':')
            || !host.bytes().any(|b| b.is_ascii_alphabetic())
            || host.parse::<IpAddr>().is_ok()
            || !proxy_ish(line)
        {
            continue;
        }
        if seen.insert((host.to_ascii_lowercase(), port, claim)) {
            out.push(HostEntry {
                host: host.to_ascii_lowercase(),
                port,
                scheme: claim,
                auth: None,
            });
        }
    }
    out
}

fn expand_v4(net: Ipv4Addr, prefix: u8) -> Vec<IpAddr> {
    let base = u32::from(net) & mask(prefix);
    let count = 1u32 << (32 - prefix);
    let mut out = Vec::with_capacity(count.min(65536) as usize);
    for off in 0..count {
        if prefix <= 30 && (off == 0 || off == count - 1) {
            continue; // network + broadcast
        }
        out.push(IpAddr::V4(Ipv4Addr::from(base.wrapping_add(off))));
    }
    out
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

pub fn parse_addr_str(tok: &str) -> Option<SocketAddr> {
    if tok.len() < 5 {
        return None;
    }
    if let Some(rest) = tok.strip_prefix('[') {
        let (ip, port) = rest.split_once("]:")?;
        Some(SocketAddr::new(
            ip.parse::<IpAddr>().ok()?,
            port.parse().ok()?,
        ))
    } else {
        let (ip, port) = tok.rsplit_once(':')?;
        if ip.contains(':') {
            return None;
        }
        let ip = match parse_v4_lenient(ip) {
            Some(v4) => IpAddr::V4(v4),
            None => ip.parse::<IpAddr>().ok()?,
        };
        Some(SocketAddr::new(ip, port.parse().ok()?))
    }
}

/// A `host:port` *declaration* (proxy-ish), not a general URL: host of
/// `[alnum.-]`/brackets with a short numeric port after the final colon.
/// Guards the malformed counter so `http://example.com/path` in prose is
/// never tallied as a lost proxy.
fn proxy_ish(rest: &str) -> bool {
    let Some((host, port)) = rest.rsplit_once(':') else {
        return false;
    };
    !host.is_empty()
        && !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|b| b.is_ascii_digit())
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'[' | b']'))
}

/// IPv4 with decimal zero-padded octets normalized: scraper lists emit
/// `03.161.30.65`/`103.250.166.04` routinely and the decimal intent is
/// unambiguous (`u8` FromStr reads "072" as 72; Rust has no octal).
/// std's Ipv4Addr rejects the padding outright, which would silently cost
/// those lines — so try lenient first, then fall through.
fn parse_v4_lenient(s: &str) -> Option<Ipv4Addr> {
    let mut octets = [0u8; 4];
    let mut parts = s.split('.');
    for slot in octets.iter_mut() {
        *slot = parts.next()?.parse().ok()?;
    }
    parts.next().is_none().then_some(Ipv4Addr::from(octets))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schemes_creds_and_claims() {
        let body = b"1.2.3.4:8080\nsocks5://5.6.7.8:1080\nhttp://bob:s3cret-9@9.9.9.9:3128\nuser:pass@7.7.7.7:80\n# comment\n";
        let out = parse_proxies(body, Scheme::Http);
        let find = |s: &str| out.iter().find(|e| e.addr.to_string() == s);
        assert_eq!(
            find("1.2.3.4:8080").map(|e| (e.scheme, e.auth.as_ref().map(|a| a.to_string()))),
            Some((Scheme::Http, None))
        );
        let e = find("5.6.7.8:1080").unwrap();
        assert_eq!(e.scheme, Scheme::Socks5);
        // one candidate per address — no bare phantoms of prefixed lines
        let addrs: Vec<String> = out.iter().map(|e| e.addr.to_string()).collect();
        let uniq: std::collections::HashSet<&String> = addrs.iter().collect();
        assert_eq!(addrs.len(), uniq.len(), "phantom duplicates: {addrs:?}");
        let e = find("9.9.9.9:3128").unwrap();
        assert_eq!(
            (e.scheme, e.auth.as_ref().unwrap().to_string()),
            (Scheme::Http, "bob:s3cret-9".into())
        );
        let e = find("7.7.7.7:80").unwrap(); // creds without scheme: file claim + auth
        assert_eq!(
            (e.scheme, e.auth.as_ref().unwrap().to_string()),
            (Scheme::Http, "user:pass".into())
        );
    }

    #[test]
    fn zero_padded_octets_are_normalized() {
        assert_eq!(
            parse_addr_str("03.161.30.65:82"),
            Some("3.161.30.65:82".parse().unwrap())
        );
        assert_eq!(
            parse_proxies(b"http://04.207.61.44:3128\n", Scheme::Socks5).len(),
            1
        );
        // out-of-range stays out of range
        assert!(parse_addr_str("1.2.3.256:80").is_none());
        // CIDR nets too
        let out = parse_proxies(b"010.1.2.0/30:8080\n", Scheme::Http);
        assert_eq!(out.len(), 2);
        // full padding matrix: zero forms and mid-token pads
        assert_eq!(
            parse_addr_str("1.2.3.00:80"),
            Some("1.2.3.0:80".parse().unwrap())
        );
        assert_eq!(
            parse_addr_str("007.0.000.4:80"),
            Some("7.0.0.4:80".parse().unwrap())
        );
        assert_eq!(
            parse_addr_str("1.2.3.04:8080"),
            Some("1.2.3.4:8080".parse().unwrap())
        );
        // still rejecting what is invalid in any reading
        assert!(parse_addr_str("999.1.1.1:3128").is_none());
        assert!(parse_addr_str("1015118.97.107.65:5430").is_none());
        assert!(parse_addr_str("1.2.3:80").is_none());
    }

    #[test]
    fn declared_malformed_lines_are_counted_once() {
        let body = "socks5://wsip-98-175-31-195.host.example.net:4145\n\
            http://1.2.3.256:80\n\
            user:pass@999.1.1.1:3128\n\
            see http://example.com/path for docs\n\
            random text, not a proxy\n"
            .as_bytes();
        let p = parse_proxies_stats(body, Scheme::Http);
        assert!(p.entries.is_empty(), "got {:?}", p.entries);
        assert_eq!(p.malformed, 2, "octet256 + octet999; URL prose uncounted");
        assert_eq!(p.hosts.len(), 1, "hostname is reported, not malformed");
    }

    #[test]
    fn credentials_keep_their_case() {
        let out = parse_proxies(b"http://Admin:Secret@1.2.3.4:80\n", Scheme::Http);
        let a = out[0].auth.as_ref().unwrap();
        assert_eq!(
            (a.user.as_str(), a.password.as_deref()),
            ("Admin", Some("Secret"))
        );
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
    fn unterminated_comment_lines_are_ignored() {
        for body in [
            b"# 9.9.9.9:3128".as_slice(),
            b"; socks5://1.2.3.4:1080".as_slice(),
        ] {
            let p = parse_proxies_stats(body, Scheme::Http);
            assert!(p.entries.is_empty(), "got {:?}", p.entries);
            assert_eq!(p.malformed, 0);
            assert!(p.hosts.is_empty(), "got {:?}", p.hosts);
        }
    }

    #[test]
    fn host_port_boundaries_are_enforced() {
        let invalid = parse_proxies_stats(b"proxy.example.net:0", Scheme::Socks5);
        assert!(invalid.entries.is_empty());
        assert_eq!(invalid.malformed, 0);
        assert!(invalid.hosts.is_empty());

        let valid = parse_proxies_stats(b"host.example.net:65535", Scheme::Socks5);
        assert!(valid.entries.is_empty());
        assert_eq!(valid.malformed, 0);
        assert_eq!(valid.hosts.len(), 1);
        assert_eq!(valid.hosts[0].port, 65535);
    }

    #[test]
    fn symbol_passwords_are_preserved_not_rewritten() {
        let out = parse_proxies(b"user:p+ss#1@1.2.3.4:80\n", Scheme::Http);
        let a = out[0].auth.as_ref().unwrap();
        assert_eq!(
            (a.user.as_str(), a.password.as_deref()),
            ("user", Some("p+ss#1"))
        );
    }

    #[test]
    fn colon_quad_and_csv_formats_parse() {
        let p = parse_proxies_stats(b"1.2.3.4:8080:root:sec:ret\n5.6.7.8,8080\n", Scheme::Http);
        assert_eq!(p.entries.len(), 2);
        let a = p.entries[0].auth.as_ref().unwrap();
        assert_eq!(
            (a.user.as_str(), a.password.as_deref()),
            ("root", Some("sec:ret"))
        );
    }

    #[test]
    fn bare_colon_quad_credentials_keep_their_case() {
        let out = parse_proxies(b"1.2.3.4:8080:Admin:Secret\n", Scheme::Http);
        let a = out[0].auth.as_ref().unwrap();
        assert_eq!(
            (a.user.as_str(), a.password.as_deref()),
            ("Admin", Some("Secret"))
        );
    }
    #[test]
    fn bare_quad_passwords_preserve_symbols() {
        let out = parse_proxies(b"1.2.3.4:8080:user:p+ss_w-rd!#1", Scheme::Http);
        let a = out[0].auth.as_ref().unwrap();
        assert_eq!(
            (a.user.as_str(), a.password.as_deref()),
            ("user", Some("p+ss_w-rd!#1"))
        );
    }

    #[test]
    fn bare_semicolon_separates_entries() {
        let out = parse_proxies(b"1.2.3.4:8080:u:p;x 5.6.7.8:80", Scheme::Http);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].addr.to_string(), "1.2.3.4:8080");
        assert_eq!(out[0].scheme, Scheme::Http);
        let a = out[0].auth.as_ref().unwrap();
        assert_eq!((a.user.as_str(), a.password.as_deref()), ("u", Some("p")));
        assert_eq!(out[1].addr.to_string(), "5.6.7.8:80");
        assert_eq!(out[1].scheme, Scheme::Http);
        assert_eq!(out[1].auth, None);
    }
    #[test]
    fn mixed_plain_and_bare_auth_preserve_both_entries() {
        for body in [
            b"1.2.3.4:8080\n1.2.3.4:8080:user:pass\n".as_slice(),
            b"1.2.3.4:8080:user:pass\n1.2.3.4:8080\n".as_slice(),
        ] {
            let out = parse_proxies(body, Scheme::Http);
            assert_eq!(out.len(), 2);
            assert_eq!(out.iter().filter(|e| e.auth.is_none()).count(), 1);
            let auth = out.iter().find_map(|e| e.auth.as_ref()).unwrap();
            assert_eq!(
                (auth.user.as_str(), auth.password.as_deref()),
                ("user", Some("pass"))
            );
        }
    }

    #[test]
    fn prefix_and_bare_auth_lines_remain_distinct_entries() {
        let parsed = parse_proxies_stats(
            b"http://user:pass@1.2.3.4:80\n1.2.3.4:80:user:pass\n",
            Scheme::Socks5,
        );
        assert_eq!(parsed.entries.len(), 2);

        let repeated = parse_proxies_stats(
            b"1.2.3.4:80:user:pass\n1.2.3.4:80:user:pass\n",
            Scheme::Socks5,
        );
        assert_eq!(repeated.entries.len(), 1);
    }
    #[test]
    fn incomplete_credentials_are_rejected_without_side_channels() {
        for body in [
            b"user@1.2.3.4:80\n".as_slice(),
            b":secret@1.2.3.4:80\n".as_slice(),
        ] {
            let parsed = parse_proxies_stats(body, Scheme::Http);
            assert_eq!(
                (parsed.entries.len(), parsed.malformed, parsed.hosts.len()),
                (0, 0, 0),
                "got {parsed:?}",
            );
        }

        let valid = parse_proxies_stats(b"http://1.2.3.4:80\n", Scheme::Http);
        assert_eq!(valid.entries.len(), 1);
    }

    #[test]
    fn prefixed_hostname_ports_enforce_valid_range() {
        let invalid = parse_proxies_stats(b"socks5://proxy.example.net:0", Scheme::Http);
        assert_eq!(
            (invalid.hosts.len(), invalid.malformed),
            (0, 1),
            "got {invalid:?}",
        );

        let valid = parse_proxies_stats(b"socks5://proxy.example.net:65535", Scheme::Http);
        assert_eq!(
            (valid.hosts.len(), valid.malformed),
            (1, 0),
            "got {valid:?}",
        );
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

    #[test]
    fn prefixed_line_claims_its_address() {
        // credentialed line: exactly one entry, carrying the credentials
        let out = parse_proxies(b"http://bob:p@1.2.3.4:80\n", Scheme::Http);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].auth.as_ref().unwrap().user, "bob");
        // scheme-prefixed line: one entry — no twin under the file claim
        let out = parse_proxies(b"socks5://1.2.3.4:1080\n", Scheme::Http);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].scheme, Scheme::Socks5);
        // bare lines: one candidate each under the claim
        let out = parse_proxies(b"1.2.3.4:8080\n5.6.7.8:8080\n", Scheme::Http);
        assert_eq!(out.len(), 2);
        // bracketed IPv6: scheme-prefixed with and without credentials
        let out = parse_proxies(b"socks5://bob:p@[2001:db8::1]:1080\n", Scheme::Http);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].scheme, Scheme::Socks5);
        assert_eq!(out[0].auth.as_ref().unwrap().user, "bob");
        let out = parse_proxies(b"socks5://[2001:db8::1]:1080\n", Scheme::Http);
        assert_eq!(out.len(), 1);
        // malformed (missing open bracket) is rejected, not half-parsed
        assert!(parse_proxies(b"socks5://bob:p@2001:db8::1]:1080\n", Scheme::Http).is_empty());
        // prefixed wins over a real duplicate bare line (documented loss)
        let out = parse_proxies(b"1.2.3.4:8080\nsocks5://1.2.3.4:8080\n", Scheme::Http);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].scheme, Scheme::Socks5);
    }

    #[test]
    fn brackets_and_cidr() {
        let out = parse_proxies(b"[2001:db8::1]:3128 10.0.0.0/30:8080", Scheme::Socks5);
        let strs: Vec<String> = out.iter().map(|e| e.addr.to_string()).collect();
        assert!(strs.contains(&"[2001:db8::1]:3128".to_string()), "{strs:?}");
        assert!(strs.contains(&"10.0.0.1:8080".to_string()), "{strs:?}");
        assert!(strs.contains(&"10.0.0.2:8080".to_string()), "{strs:?}");
        assert!(!strs.contains(&"10.0.0.0:8080".to_string()));
        assert!(out.iter().all(|e| e.scheme == Scheme::Socks5));
    }

    #[test]
    fn garbage_is_skipped_not_fatal() {
        let out = parse_proxies(
            b"hello world\nnot-an-ip:99\n:80\n1.2.3.400:80\n",
            Scheme::Socks5,
        );
        assert!(out.is_empty(), "{out:?}");
    }
}
