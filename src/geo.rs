//! Proxy judgment from offline MaxMind GeoLite2 databases.
//!
//! The operator provides the .mmdb files (paths in [geo]); proxalyze opens
//! them at startup and fails loudly if a configured file is missing or
//! corrupt. The ASN database classifies the exit network (hosting / cdn /
//! mobile / vpn / residential-proxy). Location is not part of the judgment.
//! These facts, together with anonymity class and latency, are the judgment
//! of *how useful* a working proxy is — emitted raw, without derived grades.

use std::net::IpAddr;
use std::path::Path;

use serde_json::Value;

pub struct Judge {
    asn: Option<maxminddb::Reader<Vec<u8>>>,
}

#[derive(Default, Clone)]
pub struct Network {
    pub asn: Option<u32>,
    pub org: Option<String>,
    /// hosting | cdn | mobile | vpn | residential-proxy
    pub tags: Vec<&'static str>,
}

impl Judge {
    /// `path` = auto-detected ASN database path, if any. A configured file
    /// that fails to open is an error (loud), absence is not.
    pub fn open(path: Option<&str>) -> Result<Self, String> {
        let asn = match path {
            Some(p) => Some(open_db(p, "ASN database")?),
            None => None,
        };
        Ok(Self { asn })
    }

    pub fn active(&self) -> bool {
        self.asn.is_some()
    }

    pub fn locate(&self, ip: IpAddr) -> Network {
        let mut net = Network::default();
        let Some(db) = &self.asn else { return net };
        let Ok(v) = db.lookup(ip).and_then(|r| r.decode::<Value>()) else {
            return net;
        };
        let Some(v) = v else { return net };
        net.asn = v
            .get("autonomous_system_number")
            .and_then(Value::as_u64)
            .map(|n| n as u32);
        net.org = v
            .get("autonomous_system_organization")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let flag = |k: &str| v.get(k).and_then(Value::as_bool).unwrap_or(false);
        if flag("is_hosting") {
            net.tags.push("hosting");
        }
        if flag("is_cdn") {
            net.tags.push("cdn");
        }
        if flag("is_mobile") {
            net.tags.push("mobile");
        }
        if flag("is_vpn") {
            net.tags.push("vpn");
        }
        if flag("is_residential_proxy") {
            net.tags.push("residential-proxy");
        }
        if net.tags.is_empty() {
            net.tags = infer_class(net.asn.unwrap_or(0), net.org.as_deref().unwrap_or(""));
        }
        net
    }
}

/// Datacenter/CDN providers that dominate public proxy pools. Used only as a
/// fallback when the operator's database carries no is_hosting/is_cdn flags
/// (the community GeoLite mirror ships without them). Unknown networks stay
/// untagged — residential ISPs are the default, which is the honest prior
/// for a proxy of unknown ownership.
const HOSTING_ASNS: &[u32] = &[
    14061,  // DigitalOcean
    24940,  // Hetzner
    16276,  // OVH
    16509,  // Amazon
    20473,  // Choopa/Vultr
    63949,  // Linode
    36351,  // Softlayer
    138915, // Kagisystem
    45638,  // Sphera IP
    49505,  // Selectel
    7979,   // Servers.com
    8100,   // QuadraNet
    14576,  // Constix
    29854,  // The Constant Company
    32748,  // Steadfast
    32475,  // SingleHop
    20860,  // A2 Hosting / one2one
    197540, // Critical Move
    55293,  // Hoสติง (BGP servers)
    201100, // SpICYFIRE
    398704, // STACKS INC (cloud hosting)
];
const CDN_ASNS: &[u32] = &[13335, 16625, 20940, 54825, 21854]; // Cloudflare, AirTrunk/Edgecast, Akamai, Fastly, NSONS

const HOSTING_ORGS: &[&str] = &[
    "digitalocean",
    "hetzner",
    "ovh",
    "vultr",
    "linode",
    "amazon",
    "microsoft",
    "google llc",
    "google cloud",
    "alibaba",
    "tencent",
    "aceville",
    "kagisystem",
    "sphera",
    "selectel",
    "softlayer",
    "ibm cloud",
    "bytedance",
    "datacenter",
    "hosting",
    "servers",
    "cloud services",
    "constant",
    "steadfast",
    "choopa",
    "stacks",
];
const CDN_ORGS: &[&str] = &["cloudflare", "akamai", "fastly", "edgecast", "cdn"];

fn infer_class(asn: u32, org: &str) -> Vec<&'static str> {
    let org = org.to_ascii_lowercase();
    let mut tags = Vec::new();
    if HOSTING_ASNS.contains(&asn) || HOSTING_ORGS.iter().any(|k| org.contains(k)) {
        tags.push("hosting");
    } else if CDN_ASNS.contains(&asn) || CDN_ORGS.iter().any(|k| org.contains(k)) {
        tags.push("cdn");
    }
    tags
}

fn open_db(path: &str, key: &str) -> Result<maxminddb::Reader<Vec<u8>>, String> {
    if !Path::new(path).exists() {
        return Err(format!(
            "[geo] {key} = \"{path}\" does not exist — download GeoLite2 from \
             https://github.com/P3TERX/GeoLite.mmdb (raw `download` branch) or unset the key"
        ));
    }
    maxminddb::Reader::open_readfile(path).map_err(|e| format!("[geo] {key} \"{path}\": {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infer_class_covers_mirror_database_gaps() {
        // DigitalOcean and Cloudflare are flagged even without mmdb booleans.
        assert_eq!(infer_class(14061, "DigitalOcean, LLC"), vec!["hosting"]);
        assert_eq!(infer_class(13335, "Cloudflare, Inc."), vec!["cdn"]);
        assert_eq!(
            infer_class(0, "Alibaba Cloud (Beijing) Network Technology"),
            vec!["hosting"]
        );
        assert_eq!(infer_class(398704, "STACKS INC"), vec!["hosting"]);
        // A real residential ISP stays untagged.
        assert!(infer_class(7713, "Telekom Indonesia").is_empty());
    }
}
