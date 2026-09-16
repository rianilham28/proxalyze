//! Proxy-list text parser. Addresses are pattern-matched out of any text,
//! but nothing here guesses *protocols*: a bare `ip:port` inherits the
//! scheme declared for its input file, while an inline `socks5://ip:port`
//! (or http/https/socks4) always wins for that entry. Credentials
//! (`user:pass@`) are carried through as authentication to try.
//!
//! Recognized forms (the config contract):
//!   1.2.3.4:8080
//!   socks5://1.2.3.4:1080
//!   socks5://user:pass@1.2.3.4:1080
//!   user:pass@1.2.3.4:8080              (scheme from the file claim)
//!   [2001:db8::1]:3128
//!   1.2.3.0/24:8080                     CIDR /16..=/32, expanded to hosts
//!   03.161.30.65:82                     zero-padded octets are normalized
//!
//! Note: passwords are matched over `[A-Za-z0-9._\-]` inside the token;
//! exotic symbol-heavy passwords should be re-encoded at the proxy.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::model::{Auth, Scheme};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub addr: SocketAddr,
    pub scheme: Scheme,
    pub auth: Option<Auth>,
}

/// Parse only — malformed declared lines are folded away. Test convenience
/// over [`parse_proxies_stats`] (which the CLI uses for the drop log).
#[cfg(test)]
pub fn parse_proxies(body: &[u8], claim: Scheme) -> Vec<Entry> {
    parse_proxies_stats(body, claim).0
}

/// Second value = lines that *declared* a proxy (valid `scheme://` or
/// `user:pass@`) but whose address failed to parse — e.g. hostnames (out of
/// contract: no DNS) or octets > 255. Only prefixed forms count: a scheme
/// prefix is an explicit declaration; bare tokens are candidate sightings,
/// and random text must never inflate the number.
pub fn parse_proxies_stats(body: &[u8], claim: Scheme) -> (Vec<Entry>, usize) {
    let mut out: Vec<Entry> = Vec::new();
    let mut malformed = 0usize;
    scan_prefixed(body, claim, &mut out, &mut malformed);
    // A bare re-sighting of an address already explained by a prefixed line
    // (`scheme://…` or `user:pass@…`) is a substring artifact of that very
    // line, not a second declaration — checking the phantom would double-
    // probe credentialed entries and mislabel scheme-prefixed ones under the
    // file claim. Set-based: real-world lists run 100k+ prefixed lines, and
    // a per-candidate linear scan is quadratic on exactly that input.
    let mut seen: HashSet<SocketAddr> = out.iter().map(|e| e.addr).collect();
    for (addr, _) in scan_bare(body) {
        if seen.insert(addr) {
            out.push(Entry {
                addr,
                scheme: claim,
                auth: None,
            });
        }
    }
    (out, malformed)
}

/// Letter-aware pass: tokens containing `://` (scheme + optional creds) or
/// `@ip:port` (creds + file claim).
fn scan_prefixed(body: &[u8], claim: Scheme, out: &mut Vec<Entry>, mal: &mut usize) {
    // brackets included: scheme-prefixed IPv6 (`socks5://[v6]:1080`) and
    // credentialed IPv6 (`user:pass@[v6]:8080`) are real list shapes
    let keep = |b: u8| {
        b.is_ascii_alphanumeric()
            || matches!(b, b'.' | b':' | b'/' | b'@' | b'-' | b'_' | b'[' | b']')
    };
    let mut start = None::<usize>;
    let mut flush = |s: Option<usize>, e: usize, out: &mut Vec<Entry>| {
        let Some(s) = s else { return };
        let tok = String::from_utf8_lossy(&body[s..e]).to_ascii_lowercase();
        if let Some((sch, rest)) = tok.split_once("://") {
            let Some(scheme) = Scheme::from_claim(sch) else {
                return;
            };
            let (auth, hostport) = split_auth(rest);
            if let Some(addr) = parse_addr_str(hostport.split('/').next().unwrap_or(hostport)) {
                out.push(Entry { addr, scheme, auth });
            } else if proxy_ish(hostport.split('/').next().unwrap_or(hostport)) {
                *mal += 1;
            }
        } else if tok.contains('@') {
            let (auth, hostport) = split_auth(&tok);
            if auth.is_some() {
                if let Some(addr) = parse_addr_str(hostport) {
                    out.push(Entry {
                        addr,
                        scheme: claim,
                        auth,
                    });
                } else if proxy_ish(hostport) {
                    *mal += 1;
                }
            }
        }
    };
    for (i, &b) in body.iter().enumerate() {
        if keep(b) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            flush(Some(s), i, out);
        }
    }
    if let Some(s) = start {
        flush(Some(s), body.len(), out);
    }
}

fn split_auth(s: &str) -> (Option<Auth>, &str) {
    match s.rsplit_once('@') {
        Some((creds, hostport)) => {
            let (user, pass) = match creds.split_once(':') {
                Some((u, p)) => (u.to_string(), Some(p.to_string())),
                None => (creds.to_string(), None),
            };
            if user.is_empty() {
                (None, hostport)
            } else {
                (
                    Some(Auth {
                        user,
                        password: pass,
                    }),
                    hostport,
                )
            }
        }
        None => (None, s),
    }
}

/// Numeric pass for bare `ip:port`, `[v6]:port`, and CIDR ranges.
fn scan_bare(body: &[u8]) -> Vec<(SocketAddr, Option<Auth>)> {
    let mut out = Vec::new();
    let mut start = None::<usize>;
    let keep = |b: u8| matches!(b, b'0'..=b'9' | b'.' | b':' | b'/' | b'[' | b']' | b'a'..=b'f' | b'A'..=b'F');
    for (i, &b) in body.iter().enumerate() {
        match start {
            None if keep(b) => start = Some(i),
            Some(s) if !keep(b) => {
                extend_token(&body[s..i], &mut out);
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        extend_token(&body[s..], &mut out);
    }
    out
}

fn extend_token(tok: &[u8], out: &mut Vec<(SocketAddr, Option<Auth>)>) {
    let t = String::from_utf8_lossy(tok).to_ascii_lowercase();
    let rest = t.rsplit_once('@').map(|(_, hp)| hp).unwrap_or(&t);
    if let Some(addr) = parse_addr_str(rest) {
        out.push((addr, None));
        return;
    }
    if let Some((cidr, port)) = rest.split_once(':')
        && let Some((net, prefix)) = cidr.split_once('/')
    {
        let prefix: u8 = prefix.parse().unwrap_or(64);
        if let (Some(net), Ok(port)) = (parse_v4_lenient(net), port.parse::<u16>())
            && (16..=32).contains(&prefix)
        {
            for host in expand_v4(net, prefix) {
                out.push((SocketAddr::new(host, port), None));
            }
        }
    }
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
        let (out, mal) = parse_proxies_stats(body, Scheme::Http);
        assert!(out.is_empty(), "got {out:?}");
        assert_eq!(
            mal, 3,
            "hostname + octet256 + octet999; URLs/noise uncounted"
        );
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
