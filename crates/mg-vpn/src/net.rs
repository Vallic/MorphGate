//! Small address helpers shared by every VPN kind.

use std::net::{IpAddr, Ipv4Addr};

use crate::VpnError;

/// An address with a prefix length: `10.8.0.2/24`, `fd00::/8`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpNet {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl IpNet {
    pub fn new(addr: IpAddr, prefix: u8) -> Self {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        Self {
            addr,
            prefix: prefix.min(max),
        }
    }

    /// `a.b.c.d/len`, `a.b.c.d` (host) or `::1/128`.
    pub fn parse(s: &str) -> Result<Self, VpnError> {
        let s = s.trim();
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| VpnError::Config(format!("invalid address {s}")))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| VpnError::Config(format!("invalid prefix in {s}")))?,
            None => max,
        };
        Ok(Self { addr, prefix })
    }

    /// An IPv4 network written as address + dotted netmask (`10.0.0.0 255.255.0.0`).
    pub fn from_netmask(addr: Ipv4Addr, mask: Ipv4Addr) -> Option<Self> {
        let m = u32::from(mask);
        // Contiguous ones only.
        if m.leading_ones() + m.trailing_zeros() != 32 {
            return None;
        }
        Some(Self {
            addr: IpAddr::V4(addr),
            prefix: m.leading_ones() as u8,
        })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for IpNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_math() {
        let n = IpNet::parse("10.0.0.0/8").unwrap();
        assert!(n.contains("10.255.1.1".parse().unwrap()));
        assert!(!n.contains("11.0.0.1".parse().unwrap()));
        assert!(
            IpNet::parse("0.0.0.0/0")
                .unwrap()
                .contains("8.8.8.8".parse().unwrap())
        );
        assert!(
            IpNet::parse("fd00::/8")
                .unwrap()
                .contains("fd12::1".parse().unwrap())
        );
        assert!(IpNet::parse("10.0.0.0/33").is_err());
    }

    #[test]
    fn netmasks() {
        let n = IpNet::from_netmask(
            "10.8.0.0".parse().unwrap(),
            "255.255.255.0".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(n.to_string(), "10.8.0.0/24");
        assert!(
            IpNet::from_netmask("10.8.0.0".parse().unwrap(), "255.0.255.0".parse().unwrap())
                .is_none()
        );
        assert_eq!(
            IpNet::from_netmask("0.0.0.0".parse().unwrap(), "0.0.0.0".parse().unwrap())
                .unwrap()
                .prefix,
            0
        );
    }
}
