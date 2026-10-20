//! `PUSH_REPLY`: the options the server sends after authentication (address, DNS, routes,
//! negotiated cipher, …).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::config::{Cipher, Compress};
use crate::IpNet;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Pushed {
    pub ifconfig: Option<(Ipv4Addr, Ipv4Addr)>,
    pub topology_subnet: bool,
    pub ifconfig_ipv6: Option<IpNet>,
    pub routes: Vec<IpNet>,
    pub redirect_gateway: bool,
    pub dns: Vec<IpAddr>,
    pub domains: Vec<String>,
    /// Pushed but not one we speak (we can't follow the server then).
    pub cipher_name: Option<String>,
    pub cipher: Option<Cipher>,
    pub peer_id: Option<u32>,
    pub ping: Option<u32>,
    pub ping_restart: Option<u32>,
    pub tun_mtu: Option<u16>,
    pub ekm: bool,
    pub compress: Option<Compress>,
    pub auth_token: Option<String>,
    pub auth_token_user: Option<String>,
}

impl Pushed {
    /// Adds the options of one `PUSH_REPLY,…` message. Returns `true` when more messages follow
    /// (`push-continuation 2`).
    pub fn add(&mut self, msg: &str) -> bool {
        let mut more = false;
        let body = msg.strip_prefix("PUSH_REPLY").unwrap_or(msg);
        for opt in body.split(',').map(str::trim).filter(|o| !o.is_empty()) {
            let words: Vec<&str> = opt.split_whitespace().collect();
            let arg = |i: usize| words.get(i).copied();
            match words[0] {
                "ifconfig" => {
                    if let (Some(Ok(a)), Some(Ok(b))) =
                        (arg(1).map(str::parse), arg(2).map(str::parse))
                    {
                        self.ifconfig = Some((a, b));
                    }
                }
                "ifconfig-ipv6" => {
                    if let Some(Ok(net)) = arg(1).map(IpNet::parse) {
                        self.ifconfig_ipv6 = Some(net);
                    }
                }
                "topology" => self.topology_subnet = arg(1) == Some("subnet"),
                "route" => {
                    let mask = arg(2).unwrap_or("255.255.255.255");
                    if let (Some(Ok(net)), Ok(m)) = (arg(1).map(str::parse), mask.parse())
                        && let Some(n) = IpNet::from_netmask(net, m)
                    {
                        self.routes.push(n);
                    }
                }
                "route-ipv6" => {
                    if let Some(Ok(n)) = arg(1).map(IpNet::parse) {
                        self.routes.push(n);
                    }
                }
                "redirect-gateway" | "redirect-private" => self.redirect_gateway = true,
                "dhcp-option" => match arg(1).map(str::to_ascii_uppercase).as_deref() {
                    Some("DNS" | "DNS6") => {
                        if let Some(Ok(ip)) = arg(2).map(str::parse) {
                            self.dns.push(ip);
                        }
                    }
                    Some("DOMAIN" | "DOMAIN-SEARCH" | "ADAPTER_DOMAIN_SUFFIX") => {
                        if let Some(d) = arg(2) {
                            self.domains.push(d.to_owned());
                        }
                    }
                    _ => {}
                },
                // OpenVPN 2.6 `dns` option: `dns server 0 address 10.0.0.1`, `dns search-domains a b`.
                "dns" => match arg(1) {
                    Some("server") if arg(3) == Some("address") => {
                        for a in words.iter().skip(4) {
                            let host = a.trim_start_matches('[').split(']').next().unwrap_or(a);
                            let host = if host.matches(':').count() == 1 {
                                host.split(':').next().unwrap_or(host)
                            } else {
                                host
                            };
                            if let Ok(ip) = host.parse() {
                                self.dns.push(ip);
                            }
                        }
                    }
                    Some("search-domains") => {
                        self.domains
                            .extend(words.iter().skip(2).map(|d| (*d).to_owned()));
                    }
                    _ => {}
                },
                "cipher" => {
                    self.cipher_name = arg(1).map(Into::into);
                    self.cipher = arg(1).and_then(Cipher::parse);
                }
                "peer-id" => self.peer_id = arg(1).and_then(|p| p.parse().ok()),
                "ping" => self.ping = arg(1).and_then(|p| p.parse().ok()),
                "ping-restart" => self.ping_restart = arg(1).and_then(|p| p.parse().ok()),
                "tun-mtu" => self.tun_mtu = arg(1).and_then(|p| p.parse().ok()),
                "key-derivation" => self.ekm |= arg(1) == Some("tls-ekm"),
                "protocol-flags" => self.ekm |= words.contains(&"tls-ekm"),
                "comp-lzo" => self.compress = Compress::from_comp_lzo(arg(1)),
                "compress" => self.compress = Compress::from_compress(arg(1)),
                "auth-token" => self.auth_token = arg(1).map(Into::into),
                "auth-token-user" => self.auth_token_user = arg(1).map(Into::into),
                "push-continuation" => more = arg(1) == Some("2"),
                _ => {}
            }
        }
        more
    }

    /// This device's address(es) inside the VPN.
    pub fn addresses(&self) -> Vec<IpNet> {
        let mut out = Vec::new();
        if let Some((local, second)) = self.ifconfig {
            // `topology subnet`: the second value is a netmask; `net30`/`p2p`: the peer.
            let prefix = match IpNet::from_netmask(local, second) {
                Some(n) if self.topology_subnet || second.octets()[0] == 255 => n.prefix,
                _ => 32,
            };
            out.push(IpNet::new(IpAddr::V4(local), prefix));
        }
        if let Some(v6) = self.ifconfig_ipv6 {
            out.push(v6);
        }
        out
    }

    /// The networks reachable through the tunnel, including the VPN subnet itself.
    pub fn networks(&self) -> Vec<IpNet> {
        if self.redirect_gateway {
            return vec![
                IpNet::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                IpNet::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            ];
        }
        let mut out: Vec<IpNet> = self
            .addresses()
            .into_iter()
            .map(|a| IpNet::new(a.addr, a.prefix))
            .collect();
        if let Some((_, peer)) = self.ifconfig
            && !self.topology_subnet
            && peer.octets()[0] != 255
        {
            out.push(IpNet::new(IpAddr::V4(peer), 32));
        }
        out.extend(self.routes.iter().copied());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_2_6_push_reply() {
        let mut p = Pushed::default();
        let more = p.add(
            "PUSH_REPLY,dhcp-option DNS 10.8.0.1,dhcp-option DOMAIN corp.internal,route-gateway 10.8.0.1,\
             topology subnet,ping 10,ping-restart 120,ifconfig 10.8.0.2 255.255.255.0,\
             route 192.168.50.0 255.255.255.0,peer-id 3,cipher AES-256-GCM,\
             protocol-flags cc-exit tls-ekm dyn-tls-crypt,tun-mtu 1500,push-continuation 2",
        );
        assert!(more);
        assert!(!p.add("PUSH_REPLY,ifconfig-ipv6 fd00::1000/64 fd00::1,push-continuation 1"));
        assert_eq!(p.peer_id, Some(3));
        assert_eq!(p.cipher, Some(Cipher::Aes256Gcm));
        assert!(p.ekm);
        assert_eq!(p.ping, Some(10));
        assert_eq!(p.domains, vec!["corp.internal".to_string()]);
        let addrs: Vec<String> = p.addresses().iter().map(ToString::to_string).collect();
        assert_eq!(addrs, vec!["10.8.0.2/24", "fd00::1000/64"]);
        let nets: Vec<String> = p.networks().iter().map(ToString::to_string).collect();
        assert!(nets.contains(&"192.168.50.0/24".to_string()));
    }

    #[test]
    fn net30_and_new_dns_option() {
        let mut p = Pushed::default();
        p.add("PUSH_REPLY,route 10.8.0.1,topology net30,ifconfig 10.8.0.6 10.8.0.5,dns server 0 address 10.8.0.1 [fd00::1]:53,key-derivation tls-ekm,comp-lzo no");
        assert_eq!(p.addresses()[0].to_string(), "10.8.0.6/32");
        assert!(
            p.networks()
                .iter()
                .any(|n| n.contains("10.8.0.5".parse().unwrap()))
        );
        assert_eq!(p.dns.len(), 2);
        assert!(p.ekm);
        assert_eq!(p.compress, Some(Compress::LzoStub));
    }
}
