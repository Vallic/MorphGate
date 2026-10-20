//! OpenVPN's reliability layer for control packets: message ids, acknowledgements,
//! retransmission with backoff, and in-order delivery.

use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use tokio::time::Instant;

/// Unacknowledged packets in flight. OpenVPN servers accept at least 8 ahead.
const SEND_WINDOW: usize = 6;
/// How far ahead of the next expected id we buffer.
const RECV_WINDOW: u32 = 8;
const MAX_RTO: Duration = Duration::from_secs(8);

struct InFlight {
    opcode: u8,
    payload: Vec<u8>,
    due: Instant,
    rto: Duration,
}

pub struct Reliable {
    next_send: u32,
    in_flight: BTreeMap<u32, InFlight>,
    queue: VecDeque<(u8, Vec<u8>)>,
    next_recv: u32,
    reorder: BTreeMap<u32, (u8, Vec<u8>)>,
    acks: VecDeque<u32>,
    rto: Duration,
}

impl Reliable {
    pub fn new(rto: Duration) -> Self {
        Self {
            next_send: 0,
            in_flight: BTreeMap::new(),
            queue: VecDeque::new(),
            next_recv: 0,
            reorder: BTreeMap::new(),
            acks: VecDeque::new(),
            rto,
        }
    }

    pub fn queue(&mut self, opcode: u8, payload: Vec<u8>) {
        self.queue.push_back((opcode, payload));
    }

    /// Packets to put on the wire now: queued ones the window allows, then retransmissions.
    pub fn due(&mut self, now: Instant) -> Vec<(u32, u8, Vec<u8>)> {
        let mut out = Vec::new();
        while self.in_flight.len() < SEND_WINDOW {
            let Some((opcode, payload)) = self.queue.pop_front() else {
                break;
            };
            let id = self.next_send;
            self.next_send += 1;
            out.push((id, opcode, payload.clone()));
            self.in_flight.insert(
                id,
                InFlight {
                    opcode,
                    payload,
                    due: now + self.rto,
                    rto: self.rto,
                },
            );
        }
        for (id, p) in self.in_flight.iter_mut() {
            if p.due <= now && !out.iter().any(|(i, _, _)| i == id) {
                p.rto = (p.rto * 2).min(MAX_RTO);
                p.due = now + p.rto;
                out.push((*id, p.opcode, p.payload.clone()));
            }
        }
        out
    }

    pub fn acked(&mut self, ids: &[u32]) {
        for id in ids {
            self.in_flight.remove(id);
        }
    }

    /// A received packet with message id `id`. Returns the payloads now deliverable in order.
    pub fn received(&mut self, id: u32, opcode: u8, payload: Vec<u8>) -> Vec<(u8, Vec<u8>)> {
        if id >= self.next_recv.saturating_add(RECV_WINDOW) {
            // Too far ahead: drop without acking so the peer resends later.
            return Vec::new();
        }
        if !self.acks.contains(&id) {
            self.acks.push_back(id);
        }
        if id < self.next_recv {
            return Vec::new();
        }
        self.reorder.entry(id).or_insert((opcode, payload));
        let mut out = Vec::new();
        while let Some(p) = self.reorder.remove(&self.next_recv) {
            out.push(p);
            self.next_recv += 1;
        }
        out
    }

    pub fn take_acks(&mut self, max: usize) -> Vec<u32> {
        let n = self.acks.len().min(max);
        self.acks.drain(..n).collect()
    }

    pub fn has_acks(&self) -> bool {
        !self.acks.is_empty()
    }

    /// Everything we sent was acknowledged.
    #[cfg(test)]
    pub fn settled(&self) -> bool {
        self.in_flight.is_empty() && self.queue.is_empty()
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        self.in_flight.values().map(|p| p.due).min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_retransmit_and_acks() {
        let mut r = Reliable::new(Duration::from_secs(1));
        let t0 = Instant::now();
        for i in 0..8u8 {
            r.queue(4, vec![i]);
        }
        let first = r.due(t0);
        assert_eq!(first.len(), SEND_WINDOW);
        assert_eq!(first[0].0, 0);
        assert!(r.due(t0).is_empty(), "window full, nothing due yet");
        r.acked(&[0, 1]);
        let more = r.due(t0);
        assert_eq!(more.iter().map(|p| p.0).collect::<Vec<_>>(), vec![6, 7]);
        let resent = r.due(t0 + Duration::from_millis(1100));
        assert_eq!(resent.len(), 6, "ids 2..8 unacked and due");
        assert!(r.next_deadline().unwrap() >= t0 + Duration::from_secs(2));
        r.acked(&[2, 3, 4, 5, 6, 7]);
        assert!(r.settled());
    }

    #[test]
    fn in_order_delivery_and_duplicate_acks() {
        let mut r = Reliable::new(Duration::from_secs(1));
        assert!(r.received(1, 4, b"b".to_vec()).is_empty());
        let got = r.received(0, 8, b"a".to_vec());
        assert_eq!(got, vec![(8, b"a".to_vec()), (4, b"b".to_vec())]);
        assert!(r.received(0, 8, b"a".to_vec()).is_empty(), "duplicate");
        assert_eq!(r.take_acks(8), vec![1, 0]);
        assert!(r.received(0, 8, b"a".to_vec()).is_empty());
        assert_eq!(r.take_acks(8), vec![0], "duplicates are acked again");
        assert!(r.received(50, 4, vec![]).is_empty());
        assert!(!r.has_acks(), "far-future ids are not acked");
    }
}
