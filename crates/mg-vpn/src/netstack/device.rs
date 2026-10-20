//! A virtual IP-layer device: smoltcp reads packets the VPN decrypted from `rx` and writes
//! outgoing packets to `tx`, which the driver hands to the VPN link.

use std::collections::VecDeque;

use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

pub(crate) struct VirtualDevice {
    pub rx: VecDeque<Vec<u8>>,
    pub tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl VirtualDevice {
    pub fn new(mtu: u16) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu: usize::from(mtu),
        }
    }
}

pub(crate) struct RxToken(Vec<u8>);

impl phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

pub(crate) struct TxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; len];
        let r = f(&mut packet);
        self.0.push_back(packet);
        r
    }
}

impl Device for VirtualDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn receive(&mut self, _: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((RxToken(packet), TxToken(&mut self.tx)))
    }

    fn transmit(&mut self, _: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}
