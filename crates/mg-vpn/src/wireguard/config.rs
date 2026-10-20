//! WireGuard configuration, parsed from the `wg-quick` file format users already have.

use std::net::IpAddr;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::{IpNet, VpnError};

/// One `[Peer]`: who it is, where it is, and which addresses live behind it.
#[derive(Clone, PartialEq, Eq)]
pub struct WgPeer {
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    /// `host:port`, resolved when the tunnel starts. `None`: the peer has to reach us first.
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<IpNet>,
    pub keepalive: Option<u16>,
}

impl std::fmt::Debug for WgPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgPeer")
            .field("public_key", &STANDARD.encode(self.public_key))
            .field("endpoint", &self.endpoint)
            .field("allowed_ips", &self.allowed_ips)
            .field("keepalive", &self.keepalive)
            .finish_non_exhaustive()
    }
}

/// One `[Interface]` and its `[Peer]`s. Script hooks (`PostUp`, …) are ignored on purpose:
/// nothing is configured on the host, the tunnel lives inside MorphGate.
#[derive(Clone, PartialEq, Eq)]
pub struct WgConfig {
    pub private_key: [u8; 32],
    pub addresses: Vec<IpNet>,
    pub dns: Vec<IpAddr>,
    pub mtu: u16,
    pub peers: Vec<WgPeer>,
    pub handshake_timeout: Duration,
}

impl std::fmt::Debug for WgConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgConfig")
            .field("addresses", &self.addresses)
            .field("dns", &self.dns)
            .field("peers", &self.peers)
            .finish_non_exhaustive()
    }
}

fn key(value: &str, what: &str) -> Result<[u8; 32], VpnError> {
    STANDARD
        .decode(value.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| {
            VpnError::Config(format!(
                "{what} is not a WireGuard key (44 base64 characters)"
            ))
        })
}

/// Public key for a private key, base64 (what `wg pubkey` prints).
pub fn public_key(private: &[u8; 32]) -> String {
    let secret = boringtun::x25519::StaticSecret::from(*private);
    STANDARD.encode(boringtun::x25519::PublicKey::from(&secret).as_bytes())
}

/// A `[Peer]` while it is being read: the key is required, but only known at the end.
#[derive(Default)]
struct PeerDraft {
    public_key: Option<[u8; 32]>,
    preshared_key: Option<[u8; 32]>,
    endpoint: Option<String>,
    allowed_ips: Vec<IpNet>,
    keepalive: Option<u16>,
}

impl PeerDraft {
    /// `name` says which peer for error messages: "[Peer]" or "[Peer] 2".
    fn finish(self, name: &str) -> Result<WgPeer, VpnError> {
        let public_key = self
            .public_key
            .ok_or_else(|| VpnError::Config(format!("{name} PublicKey is missing")))?;
        if self.allowed_ips.is_empty() {
            return Err(VpnError::Config(format!("{name} AllowedIPs is missing")));
        }
        Ok(WgPeer {
            public_key,
            preshared_key: self.preshared_key,
            endpoint: self.endpoint,
            allowed_ips: self.allowed_ips,
            keepalive: self.keepalive,
        })
    }
}

impl WgConfig {
    pub fn parse(text: &str) -> Result<Self, VpnError> {
        #[derive(PartialEq)]
        enum Section {
            None,
            Interface,
            Peer,
        }
        let mut section = Section::None;
        let mut private_key = None;
        let mut drafts: Vec<PeerDraft> = Vec::new();
        let mut cfg = WgConfig {
            private_key: [0; 32],
            addresses: vec![],
            dns: vec![],
            mtu: 1420,
            peers: vec![],
            handshake_timeout: Duration::from_secs(10),
        };
        for (n, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') {
                section = match line.to_ascii_lowercase().as_str() {
                    "[interface]" => Section::Interface,
                    "[peer]" => {
                        drafts.push(PeerDraft::default());
                        Section::Peer
                    }
                    other => {
                        return Err(VpnError::Config(format!(
                            "line {}: unknown section {other}",
                            n + 1
                        )));
                    }
                };
                continue;
            }
            let (k, v) = line
                .split_once('=')
                .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim()))
                .ok_or_else(|| VpnError::Config(format!("line {}: expected Key = Value", n + 1)))?;
            let list = || v.split(',').map(str::trim).filter(|s| !s.is_empty());
            match section {
                Section::Interface => match k.as_str() {
                    "privatekey" => private_key = Some(key(v, "PrivateKey")?),
                    "address" => {
                        for a in list() {
                            cfg.addresses.push(IpNet::parse(a)?);
                        }
                    }
                    // Non-IP entries are search domains; not needed for direct connections.
                    "dns" => cfg
                        .dns
                        .extend(list().filter_map(|d| d.parse::<IpAddr>().ok())),
                    "mtu" => {
                        cfg.mtu = v
                            .parse()
                            .ok()
                            .filter(|m| (576..=9000).contains(m))
                            .ok_or_else(|| VpnError::Config("MTU must be 576..9000".into()))?
                    }
                    _ => {} // ListenPort, Table, PostUp/PostDown, … : host-level, ignored
                },
                Section::Peer => {
                    let peer = drafts.last_mut().expect("a [Peer] section is open");
                    match k.as_str() {
                        "publickey" => peer.public_key = Some(key(v, "PublicKey")?),
                        "presharedkey" => peer.preshared_key = Some(key(v, "PresharedKey")?),
                        "endpoint" => peer.endpoint = Some(v.to_owned()),
                        "allowedips" => {
                            for a in list() {
                                peer.allowed_ips.push(IpNet::parse(a)?);
                            }
                        }
                        "persistentkeepalive" => {
                            peer.keepalive = match v {
                                "off" | "0" => None,
                                n => Some(n.parse().map_err(|_| {
                                    VpnError::Config("PersistentKeepalive must be seconds".into())
                                })?),
                            }
                        }
                        _ => {}
                    }
                }
                Section::None => {
                    return Err(VpnError::Config(format!(
                        "line {}: setting outside a section",
                        n + 1
                    )));
                }
            }
        }
        cfg.private_key = private_key
            .ok_or_else(|| VpnError::Config("[Interface] PrivateKey is missing".into()))?;
        if cfg.addresses.is_empty() {
            return Err(VpnError::Config("[Interface] Address is missing".into()));
        }
        if drafts.is_empty() {
            return Err(VpnError::Config("the configuration has no [Peer]".into()));
        }
        let several = drafts.len() > 1;
        for (i, draft) in drafts.into_iter().enumerate() {
            let name = if several {
                format!("[Peer] {}:", i + 1)
            } else {
                "[Peer]".to_owned()
            };
            let peer = draft.finish(&name)?;
            if cfg.peers.iter().any(|p| p.public_key == peer.public_key) {
                return Err(VpnError::Config(format!(
                    "{name} has the same PublicKey as an earlier peer"
                )));
            }
            cfg.peers.push(peer);
        }
        if cfg.peers.iter().all(|p| p.endpoint.is_none()) {
            let msg = if several {
                "no [Peer] has an Endpoint; MorphGate connects out, so at least one peer needs one"
            } else {
                "[Peer] Endpoint is missing"
            };
            return Err(VpnError::Config(msg.into()));
        }
        Ok(cfg)
    }

    /// Every peer's endpoint, in the file's order.
    pub fn endpoints(&self) -> Vec<&str> {
        self.peers
            .iter()
            .filter_map(|p| p.endpoint.as_deref())
            .collect()
    }

    /// Every network reachable through the tunnel (all peers' AllowedIPs).
    pub fn allowed_ips(&self) -> Vec<IpNet> {
        self.peers
            .iter()
            .flat_map(|p| p.allowed_ips.iter().copied())
            .collect()
    }

    pub fn routes(&self, ip: IpAddr) -> bool {
        self.peer_for(ip).is_some()
    }

    /// Which peer carries traffic to `ip`: cryptokey routing, the most specific AllowedIPs
    /// entry wins.
    pub fn peer_for(&self, ip: IpAddr) -> Option<usize> {
        RouteTable::new(self).lookup(ip)
    }
}

/// AllowedIPs of every peer as one table, like WireGuard's: a packet to an address goes to the
/// peer with the longest matching prefix, and a packet from a peer is only accepted when its
/// source address routes back to that same peer. When two peers list the very same prefix, the
/// later one has it (as `wg setconf` does).
#[derive(Clone, Debug, Default)]
pub(crate) struct RouteTable(Vec<(IpNet, usize)>);

impl RouteTable {
    pub fn new(cfg: &WgConfig) -> Self {
        Self(
            cfg.peers
                .iter()
                .enumerate()
                .flat_map(|(i, p)| p.allowed_ips.iter().map(move |n| (*n, i)))
                .collect(),
        )
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<usize> {
        let mut best: Option<(u8, usize)> = None;
        for (net, peer) in &self.0 {
            if net.contains(ip) && best.is_none_or(|(len, _)| net.prefix >= len) {
                best = Some((net.prefix, *peer));
            }
        }
        best.map(|(_, peer)| peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONF: &str = "
# client A, office VPN
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.8.0.2/32, fd00::2/128
DNS = 10.8.0.1, corp.internal
MTU = 1380
PostUp = iptables -A FORWARD -j ACCEPT

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
PresharedKey = /UwcSPg38hW/D9Y3tcS1FOV0K1wuURMbS0sesJEP5ak=
AllowedIPs = 10.8.0.0/24, 192.168.50.0/24
Endpoint = vpn.client-a.example:51820
PersistentKeepalive = 25
";

    const SECOND_PEER: &str = "
[Peer]
# the lab, reached through its own gateway
PublicKey = TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=
AllowedIPs = 10.8.0.128/25, 172.16.0.0/12
Endpoint = lab.client-a.example:51821

[Peer]
# a roaming laptop that calls in
PublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=
AllowedIPs = 10.8.0.77/32
PersistentKeepalive = 15
";

    #[test]
    fn parses_wg_quick() {
        let c = WgConfig::parse(CONF).unwrap();
        assert_eq!(c.addresses.len(), 2);
        assert_eq!(c.addresses[0].to_string(), "10.8.0.2/32");
        assert_eq!(c.dns, vec!["10.8.0.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(c.mtu, 1380);
        assert_eq!(c.peers.len(), 1);
        assert_eq!(c.endpoints(), vec!["vpn.client-a.example:51820"]);
        assert_eq!(c.peers[0].keepalive, Some(25));
        assert!(c.peers[0].preshared_key.is_some());
        assert!(c.routes("192.168.50.17".parse().unwrap()));
        assert!(!c.routes("192.168.51.1".parse().unwrap()));
        assert!(
            !format!("{c:?}").contains("yAnz5"),
            "debug output must not leak keys"
        );
    }

    #[test]
    fn public_key_matches_wg_tool() {
        // `echo yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk= | wg pubkey`
        let c = WgConfig::parse(CONF).unwrap();
        assert_eq!(
            public_key(&c.private_key),
            "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
        );
    }

    #[test]
    fn several_peers_route_by_longest_prefix() {
        let c = WgConfig::parse(&format!("{CONF}{SECOND_PEER}")).unwrap();
        assert_eq!(c.peers.len(), 3);
        assert_eq!(
            c.endpoints(),
            vec!["vpn.client-a.example:51820", "lab.client-a.example:51821"]
        );
        assert_eq!(c.peers[1].keepalive, None, "keepalive is per peer");
        assert_eq!(c.peers[2].keepalive, Some(15));
        assert_eq!(c.peers[2].endpoint, None);
        assert_eq!(c.allowed_ips().len(), 5);
        let peer = |ip: &str| c.peer_for(ip.parse().unwrap());
        assert_eq!(peer("10.8.0.5"), Some(0));
        assert_eq!(peer("10.8.0.200"), Some(1), "/25 beats /24");
        assert_eq!(peer("10.8.0.77"), Some(2), "/32 beats both");
        assert_eq!(peer("172.20.1.1"), Some(1));
        assert_eq!(peer("192.168.50.1"), Some(0));
        assert_eq!(peer("8.8.8.8"), None);
    }

    #[test]
    fn the_same_prefix_belongs_to_the_later_peer() {
        let text = format!(
            "{CONF}\n[Peer]\nPublicKey = TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=\n\
             AllowedIPs = 192.168.50.0/24\n"
        );
        let c = WgConfig::parse(&text).unwrap();
        assert_eq!(c.peer_for("192.168.50.9".parse().unwrap()), Some(1));
        assert_eq!(c.peer_for("10.8.0.9".parse().unwrap()), Some(0));
    }

    #[test]
    fn rejects_incomplete_or_unsupported() {
        assert!(WgConfig::parse("[Interface]\nPrivateKey = abc\n").is_err());
        assert!(WgConfig::parse(&CONF.replace("Endpoint", "# Endpoint")).is_err());
        let err = |text: &str| WgConfig::parse(text).unwrap_err().to_string();
        let same_key =
            format!("{CONF}\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n");
        assert!(err(&same_key).contains("[Peer] 2: AllowedIPs"));
        let same_key = format!("{same_key}AllowedIPs = 10.9.0.0/24\n");
        assert!(
            err(&same_key).contains("same PublicKey"),
            "{}",
            err(&same_key)
        );
        let no_endpoint = format!("{}{SECOND_PEER}", CONF.replace("Endpoint", "# Endpoint"))
            .replace("Endpoint = lab", "# Endpoint = lab");
        assert!(err(&no_endpoint).contains("at least one peer needs one"));
        let no_key = format!("{CONF}\n[Peer]\nAllowedIPs = 10.9.0.0/24\n");
        assert!(err(&no_key).contains("[Peer] 2: PublicKey is missing"));
        assert!(err("[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.0.0.2/32\n").contains("no [Peer]"));
    }
}
