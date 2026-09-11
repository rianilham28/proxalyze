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

pub fn parse_proxies(body: &[u8], claim: Scheme) -> Vec<Entry> {
    let mut out: Vec<Entry> = Vec::new();
    scan_prefixed(body, claim, &mut out);
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
    out
}

/// Letter-aware pass: tokens containing `://` (scheme + optional creds) or
/// `@ip:port` (creds + file claim).
fn scan_prefixed(body: &[u8], claim: Scheme, out: &mut Vec<Entry>) {
    // brackets included: scheme-prefixed IPv6 (`socks5://[v6]:1080`) and
    // credentialed IPv6 (`user:pass@[v6]:8080`) are real list shapes
    let keep = |b: u8| {
        b.is_ascii_alphanumeric()
            || matches!(b, b'.' | b':' | b'/' | b'@' | b'-' | b'_' | b'[' | b']')
    };
    let mut start = None::<usize>;
    let flush = |s: Option<usize>, e: usize, out: &mut Vec<Entry>| {
        let Some(s) = s else { return };
        let tok = String::from_utf8_lossy(&body[s..e]).to_ascii_lowercase();
        if let Some((sch, rest)) = tok.split_once("://") {
            let Some(scheme) = Scheme::from_claim(sch) else {
                return;
            };
            let (auth, hostport) = split_auth(rest);
            if let Some(addr) = parse_addr_str(hostport.split('/').next().unwrap_or(hostport)) {
                out.push(Entry { addr, scheme, auth });
            }
        } else if tok.contains('@') {
            let (auth, hostport) = split_auth(&tok);
            if auth.is_some()
                && let Some(addr) = parse_addr_str(hostport)
            {
                out.push(Entry {
                    addr,
                    scheme: claim,
                    auth,
                });
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
        if let (Ok(IpAddr::V4(net)), Ok(port)) = (net.parse::<IpAddr>(), port.parse::<u16>())
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
        Some(SocketAddr::new(
            ip.parse::<IpAddr>().ok()?,
            port.parse().ok()?,
        ))
    }
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
