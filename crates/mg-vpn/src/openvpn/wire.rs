//! OpenVPN packet formats: control packets, and the `tls-auth` / `tls-crypt` / `tls-crypt-v2`
//! wrapping that protects them.
//!
//! tls-crypt-v2 (OpenVPN's `doc/tls-crypt-v2.txt`) wraps like tls-crypt with the client's own
//! key `Kc`, and appends the server-wrapped copy `WKc`, unencrypted, to the client's hard reset
//! (`P_CONTROL_HARD_RESET_CLIENT_V3`). The reset's packet id starts at `0x0f000000` to say the
//! client can send `WKc` once more: a 2.6 server that keeps no state before the three-way
//! handshake asks for it in its reset, and the client's next packet then is a
//! `P_CONTROL_WKC_V1`, a control packet with `WKc` appended.

use aws_lc_rs::cipher::{AES_256, EncryptingKey, EncryptionContext, UnboundCipherKey};
use aws_lc_rs::hmac;
use aws_lc_rs::iv::FixedLength;

use super::config::{Digest, StaticKey, TlsWrap};
use super::replay::ReplayWindow;

pub const CONTROL_SOFT_RESET_V1: u8 = 3;
pub const CONTROL_V1: u8 = 4;
pub const ACK_V1: u8 = 5;
pub const DATA_V1: u8 = 6;
pub const CONTROL_HARD_RESET_CLIENT_V2: u8 = 7;
pub const CONTROL_HARD_RESET_SERVER_V2: u8 = 8;
pub const DATA_V2: u8 = 9;
/// The client's hard reset under tls-crypt-v2, with `WKc` appended.
pub const CONTROL_HARD_RESET_CLIENT_V3: u8 = 10;
/// A control packet with `WKc` appended, when the server asks for it again.
pub const CONTROL_WKC_V1: u8 = 11;

/// tls-crypt-v2 reset packet ids start here: "I can resend WKc" (`EARLY_NEG_START`).
const EARLY_NEG_START: u32 = 0x0f00_0000;
/// Early negotiation in the server's reset: a flags TLV, and its "resend WKc" bit.
const TLV_EARLY_NEG_FLAGS: u16 = 0x0001;
const EARLY_NEG_FLAG_RESEND_WKC: u16 = 0x0001;

pub type SessionId = [u8; 8];

pub fn opcode(byte: u8) -> u8 {
    byte >> 3
}

pub fn key_id(byte: u8) -> u8 {
    byte & 7
}

pub fn header(opcode: u8, key_id: u8) -> u8 {
    (opcode << 3) | (key_id & 7)
}

pub fn is_control(op: u8) -> bool {
    matches!(
        op,
        CONTROL_SOFT_RESET_V1
            | CONTROL_V1
            | ACK_V1
            | CONTROL_HARD_RESET_CLIENT_V2
            | CONTROL_HARD_RESET_SERVER_V2
    )
}

/// A control-channel packet, minus the outer wrapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Control {
    pub opcode: u8,
    pub key_id: u8,
    pub session_id: SessionId,
    pub acks: Vec<u32>,
    /// The peer's view of *our* session id; present when `acks` is not empty.
    pub acked_session: Option<SessionId>,
    /// Reliable-layer message id; `ACK_V1` packets have none.
    pub msg_id: Option<u32>,
    pub payload: Vec<u8>,
}

impl Control {
    /// Everything after opcode and session id (what tls-auth / tls-crypt protect).
    fn body(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(1 + self.acks.len() * 4 + 12 + self.payload.len());
        b.push(self.acks.len() as u8);
        for a in &self.acks {
            b.extend_from_slice(&a.to_be_bytes());
        }
        if !self.acks.is_empty() {
            b.extend_from_slice(&self.acked_session.unwrap_or_default());
        }
        if let Some(id) = self.msg_id {
            b.extend_from_slice(&id.to_be_bytes());
        }
        b.extend_from_slice(&self.payload);
        b
    }

    fn from_body(op_byte: u8, session_id: SessionId, body: &[u8]) -> Option<Self> {
        let op = opcode(op_byte);
        let (&n, mut rest) = body.split_first()?;
        if n > 8 {
            return None;
        }
        let mut acks = Vec::with_capacity(usize::from(n));
        for _ in 0..n {
            let (id, r) = rest.split_first_chunk::<4>()?;
            acks.push(u32::from_be_bytes(*id));
            rest = r;
        }
        let acked_session = if n > 0 {
            let (sid, r) = rest.split_first_chunk::<8>()?;
            rest = r;
            Some(*sid)
        } else {
            None
        };
        let msg_id = if op == ACK_V1 {
            None
        } else {
            let (id, r) = rest.split_first_chunk::<4>()?;
            rest = r;
            Some(u32::from_be_bytes(*id))
        };
        Some(Self {
            opcode: op,
            key_id: key_id(op_byte),
            session_id,
            acks,
            acked_session,
            msg_id,
            payload: rest.to_vec(),
        })
    }
}

/// How control packets are protected on the wire.
pub enum Wrap {
    Plain,
    Auth {
        digest: Digest,
        send: hmac::Key,
        recv: hmac::Key,
        pid: u32,
        time: u32,
        replay: ReplayWindow,
    },
    Crypt {
        send_cipher: Vec<u8>,
        send_hmac: hmac::Key,
        recv_cipher: Vec<u8>,
        recv_hmac: hmac::Key,
        pid: u32,
        time: u32,
        replay: ReplayWindow,
        /// tls-crypt-v2: the wrapped client key, appended to the packets that carry it.
        wkc: Option<Vec<u8>>,
    },
}

const CRYPT_TAG: usize = 32;

/// Whether the server's hard reset (whose payload is early-negotiation TLVs: type, length,
/// value) asks for `WKc` again. Anything malformed asks for nothing.
pub fn wants_wkc_again(reset_payload: &[u8]) -> bool {
    let mut rest = reset_payload;
    while let Some((head, tail)) = rest.split_first_chunk::<4>() {
        let kind = u16::from_be_bytes([head[0], head[1]]);
        let len = usize::from(u16::from_be_bytes([head[2], head[3]]));
        let Some(value) = tail.get(..len) else {
            return false;
        };
        if kind == TLV_EARLY_NEG_FLAGS
            && let [a, b] = value
            && u16::from_be_bytes([*a, *b]) & EARLY_NEG_FLAG_RESEND_WKC != 0
        {
            return true;
        }
        rest = &tail[len..];
    }
    false
}

/// A tls-crypt-v2 packet as the server sees it: the wrapped packet and the `WKc` after it,
/// found by the length in `WKc`'s last two bytes (tests only).
#[cfg(test)]
pub fn split_wkc(packet: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = usize::from(u16::from_be_bytes(*packet.last_chunk::<2>()?));
    packet.split_at_checked(packet.len().checked_sub(len)?)
}

fn unix_time() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as u32)
}

fn aes256_ctr(key: &[u8], iv: &[u8], data: &mut [u8]) -> Option<()> {
    let key = UnboundCipherKey::new(&AES_256, key).ok()?;
    let enc = EncryptingKey::ctr(key).ok()?;
    let iv: [u8; 16] = iv.try_into().ok()?;
    enc.less_safe_encrypt(data, EncryptionContext::Iv128(FixedLength::from(iv)))
        .ok()?;
    Some(())
}

impl Wrap {
    /// Client side of a wrapping (the server uses the opposite key directions).
    pub fn client(cfg: Option<&TlsWrap>, digest: Digest) -> Self {
        match cfg {
            None => Self::Plain,
            Some(TlsWrap::Auth { key, direction }) => {
                // key-direction 1: send with key 1, receive with key 0; none: key 0 both ways.
                let (send, recv) = match direction {
                    Some(1) => (1, 0),
                    Some(_) => (0, 1),
                    None => (0, 0),
                };
                let n = digest.size();
                Self::Auth {
                    digest,
                    send: hmac::Key::new(digest.hmac(), &key.hmac(send)[..n]),
                    recv: hmac::Key::new(digest.hmac(), &key.hmac(recv)[..n]),
                    pid: 0,
                    time: unix_time(),
                    replay: ReplayWindow::default(),
                }
            }
            Some(TlsWrap::Crypt(key)) => Self::crypt(key, 0, None),
            Some(TlsWrap::CryptV2(k)) => {
                Self::crypt(&k.key, EARLY_NEG_START, Some(k.wrapped.clone()))
            }
        }
    }

    /// tls-crypt with `key`: the client uses the inverse direction (send key 1, receive key 0).
    fn crypt(key: &StaticKey, first_pid: u32, wkc: Option<Vec<u8>>) -> Self {
        Self::Crypt {
            send_cipher: key.cipher(1)[..32].to_vec(),
            send_hmac: hmac::Key::new(hmac::HMAC_SHA256, &key.hmac(1)[..32]),
            recv_cipher: key.cipher(0)[..32].to_vec(),
            recv_hmac: hmac::Key::new(hmac::HMAC_SHA256, &key.hmac(0)[..32]),
            pid: first_pid,
            time: unix_time(),
            replay: ReplayWindow::default(),
            wkc,
        }
    }

    /// tls-crypt-v2: our hard reset must be `P_CONTROL_HARD_RESET_CLIENT_V3`.
    pub fn is_v2(&self) -> bool {
        matches!(self, Self::Crypt { wkc: Some(_), .. })
    }

    /// The server's side of the same keys (tests only).
    #[cfg(test)]
    pub fn server(cfg: Option<&TlsWrap>, digest: Digest) -> Self {
        let mut w = Self::client(cfg, digest);
        match &mut w {
            Self::Plain => {}
            Self::Auth { send, recv, .. } => std::mem::swap(send, recv),
            Self::Crypt {
                send_cipher,
                send_hmac,
                recv_cipher,
                recv_hmac,
                wkc,
                ..
            } => {
                std::mem::swap(send_cipher, recv_cipher);
                std::mem::swap(send_hmac, recv_hmac);
                *wkc = None;
            }
        }
        w
    }

    /// Forget the peer's packet ids: OpenVPN 2.6 answers the first reset from a stateless
    /// context with its own counter, then starts the session's counter afresh.
    pub fn reset_replay(&mut self) {
        match self {
            Self::Plain => {}
            Self::Auth { replay, .. } | Self::Crypt { replay, .. } => {
                *replay = ReplayWindow::default()
            }
        }
    }

    pub fn encode(&mut self, c: &Control) -> Vec<u8> {
        let op_byte = header(c.opcode, c.key_id);
        let body = c.body();
        match self {
            Self::Plain => {
                let mut out = Vec::with_capacity(9 + body.len());
                out.push(op_byte);
                out.extend_from_slice(&c.session_id);
                out.extend_from_slice(&body);
                out
            }
            Self::Auth {
                digest,
                send,
                pid,
                time,
                ..
            } => {
                *pid = pid.wrapping_add(1);
                let mut mac = hmac::Context::with_key(send);
                mac.update(&pid.to_be_bytes());
                mac.update(&time.to_be_bytes());
                mac.update(&[op_byte]);
                mac.update(&c.session_id);
                mac.update(&body);
                let tag = mac.sign();
                let mut out = Vec::with_capacity(9 + digest.size() + 8 + body.len());
                out.push(op_byte);
                out.extend_from_slice(&c.session_id);
                out.extend_from_slice(tag.as_ref());
                out.extend_from_slice(&pid.to_be_bytes());
                out.extend_from_slice(&time.to_be_bytes());
                out.extend_from_slice(&body);
                out
            }
            Self::Crypt {
                send_cipher,
                send_hmac,
                pid,
                time,
                wkc,
                ..
            } => {
                *pid = pid.wrapping_add(1);
                let extra = wkc.as_ref().map_or(0, Vec::len);
                let mut out = Vec::with_capacity(17 + CRYPT_TAG + body.len() + extra);
                out.push(op_byte);
                out.extend_from_slice(&c.session_id);
                out.extend_from_slice(&pid.to_be_bytes());
                out.extend_from_slice(&time.to_be_bytes());
                let mut mac = hmac::Context::with_key(send_hmac);
                mac.update(&out);
                mac.update(&body);
                let tag = mac.sign();
                let mut enc = body;
                aes256_ctr(send_cipher, &tag.as_ref()[..16], &mut enc).expect("AES-256-CTR");
                out.extend_from_slice(tag.as_ref());
                out.extend_from_slice(&enc);
                if let Some(wkc) = wkc
                    && matches!(c.opcode, CONTROL_HARD_RESET_CLIENT_V3 | CONTROL_WKC_V1)
                {
                    out.extend_from_slice(wkc);
                }
                out
            }
        }
    }

    /// Checks and strips the wrapping. `None` for anything that fails authentication.
    pub fn decode(&mut self, packet: &[u8]) -> Option<Control> {
        let (&op_byte, rest) = packet.split_first()?;
        let (sid, rest) = rest.split_first_chunk::<8>()?;
        match self {
            Self::Plain => Control::from_body(op_byte, *sid, rest),
            Self::Auth {
                digest,
                recv,
                replay,
                ..
            } => {
                let n = digest.size();
                if rest.len() < n + 8 {
                    return None;
                }
                let (tag, rest) = rest.split_at(n);
                let (pid_time, body) = rest.split_at(8);
                let mut data = Vec::with_capacity(17 + body.len());
                data.extend_from_slice(pid_time);
                data.push(op_byte);
                data.extend_from_slice(sid);
                data.extend_from_slice(body);
                hmac::verify(recv, &data, tag).ok()?;
                let pid = u32::from_be_bytes(pid_time[..4].try_into().ok()?);
                if !replay.check_and_set(pid) {
                    return None;
                }
                Control::from_body(op_byte, *sid, body)
            }
            Self::Crypt {
                recv_cipher,
                recv_hmac,
                replay,
                ..
            } => {
                if rest.len() < 8 + CRYPT_TAG {
                    return None;
                }
                let (pid_time, rest) = rest.split_at(8);
                let (tag, enc) = rest.split_at(CRYPT_TAG);
                let mut body = enc.to_vec();
                aes256_ctr(recv_cipher, &tag[..16], &mut body)?;
                let mut header = Vec::with_capacity(17);
                header.push(op_byte);
                header.extend_from_slice(sid);
                header.extend_from_slice(pid_time);
                let mut data = header;
                data.extend_from_slice(&body);
                hmac::verify(recv_hmac, &data, tag).ok()?;
                let pid = u32::from_be_bytes(pid_time[..4].try_into().ok()?);
                if !replay.check_and_set(pid) {
                    return None;
                }
                Control::from_body(op_byte, *sid, &body)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openvpn::config::tests::{
        STATIC_KEY, TLS_CRYPT_V2_CLIENT_KEY, TLS_CRYPT_V2_SERVER_KEY, unwrap_wkc,
    };
    use crate::openvpn::config::{StaticKey, TlsCryptV2Key};

    fn packet() -> Control {
        Control {
            opcode: CONTROL_V1,
            key_id: 2,
            session_id: [1, 2, 3, 4, 5, 6, 7, 8],
            acks: vec![0, 7],
            acked_session: Some([9; 8]),
            msg_id: Some(3),
            payload: b"\x16\x03\x01 tls record".to_vec(),
        }
    }

    #[test]
    fn plain_round_trip_and_ack_format() {
        let mut w = Wrap::Plain;
        let bytes = w.encode(&packet());
        assert_eq!(bytes[0], (CONTROL_V1 << 3) | 2);
        assert_eq!(&bytes[9..10], &[2]);
        assert_eq!(w.decode(&bytes), Some(packet()));
        let ack = Control {
            opcode: ACK_V1,
            msg_id: None,
            payload: vec![],
            ..packet()
        };
        let bytes = w.encode(&ack);
        assert_eq!(w.decode(&bytes).unwrap(), ack);
    }

    #[test]
    fn tls_auth_and_tls_crypt_round_trip_and_reject_tampering() {
        let key = StaticKey::parse(STATIC_KEY).unwrap();
        for wrap in [
            TlsWrap::Auth {
                key: key.clone(),
                direction: Some(1),
            },
            TlsWrap::Auth {
                key: key.clone(),
                direction: None,
            },
            TlsWrap::Crypt(key.clone()),
        ] {
            let mut client = Wrap::client(Some(&wrap), Digest::Sha256);
            let mut server = Wrap::server(Some(&wrap), Digest::Sha256);
            let bytes = client.encode(&packet());
            assert_eq!(server.decode(&bytes), Some(packet()));
            // Replays and flipped bits are dropped.
            assert_eq!(server.decode(&bytes), None);
            let mut bad = client.encode(&packet());
            let last = bad.len() - 1;
            bad[last] ^= 1;
            assert_eq!(server.decode(&bad), None);
            // The client can't read its own packets (keys are directional) unless bidirectional.
            let back = server.encode(&packet());
            assert_eq!(client.decode(&back), Some(packet()));
        }
    }

    #[test]
    fn tls_crypt_v2_appends_the_wrapped_key_to_resets_and_wkc_packets() {
        let key = TlsCryptV2Key::parse(TLS_CRYPT_V2_CLIENT_KEY).unwrap();
        let wrap = TlsWrap::CryptV2(key.clone());
        let mut client = Wrap::client(Some(&wrap), Digest::Sha256);
        let mut server = Wrap::server(Some(&wrap), Digest::Sha256);
        assert!(client.is_v2() && !server.is_v2());

        let reset = Control {
            opcode: CONTROL_HARD_RESET_CLIENT_V3,
            key_id: 0,
            acks: vec![],
            acked_session: None,
            msg_id: Some(0),
            payload: vec![],
            ..packet()
        };
        let bytes = client.encode(&reset);
        assert_eq!(bytes[0] >> 3, 10);
        // Early negotiation: the reset's packet id is 0x0f000001.
        assert_eq!(bytes[9..13], [0x0f, 0, 0, 1]);
        let (wrapped, wkc) = split_wkc(&bytes).unwrap();
        assert_eq!(wkc, key.wrapped);
        // What the server does: unwrap WKc with its key, then the packet with Kc.
        let kc = unwrap_wkc(TLS_CRYPT_V2_SERVER_KEY, wkc).unwrap();
        assert_eq!(kc[..64], *key.key.cipher(0));
        assert_eq!(server.decode(wrapped), Some(reset));

        // Ordinary control packets go without it; P_CONTROL_WKC_V1 carries it again.
        let plain = client.encode(&packet());
        assert_eq!(server.decode(&plain), Some(packet()));
        let again = Control {
            opcode: CONTROL_WKC_V1,
            payload: vec![],
            ..packet()
        };
        let bytes = client.encode(&again);
        let (wrapped, wkc) = split_wkc(&bytes).unwrap();
        assert_eq!(wkc, key.wrapped);
        assert_eq!(server.decode(wrapped), Some(again));
    }

    #[test]
    fn the_servers_reset_may_ask_for_the_wrapped_key_again() {
        assert!(wants_wkc_again(&[0, 1, 0, 2, 0, 1]));
        assert!(!wants_wkc_again(&[0, 1, 0, 2, 0, 0]), "flag not set");
        assert!(!wants_wkc_again(&[]), "an old server's empty reset");
        // An unknown TLV first is skipped.
        assert!(wants_wkc_again(&[0, 9, 0, 3, 7, 7, 7, 0, 1, 0, 2, 0, 1]));
        // Malformed: a length past the end, a flags TLV of the wrong size.
        assert!(!wants_wkc_again(&[0, 1, 0, 9, 0, 1]));
        assert!(!wants_wkc_again(&[0, 1, 0, 1, 1]));
    }
}
