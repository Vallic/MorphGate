//! The data channel: IP packets encrypted with keys from the TLS session.
//!
//! AEAD (`AES-*-GCM`, `CHACHA20-POLY1305`): `[op][peer-id] [packet id] [tag] [ciphertext]`, with
//! the op header and packet id as associated data and nonce = packet id ‖ implicit IV.
//! CBC (`AES-*-CBC` + `auth` HMAC): `[op][peer-id] [hmac] [iv] [AES-CBC(packet id ‖ payload)]`.

use aws_lc_rs::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::cipher::{
    AES_128, AES_256, DecryptionContext, EncryptionContext, PaddedBlockDecryptingKey,
    PaddedBlockEncryptingKey, UnboundCipherKey,
};
use aws_lc_rs::hmac;
use aws_lc_rs::iv::FixedLength;

use super::config::{Cipher, Digest};
use super::replay::ReplayWindow;

const TAG: usize = 16;

// One of each per key state, so the size difference doesn't matter.
#[allow(clippy::large_enum_variant)]
enum Seal {
    Aead {
        key: LessSafeKey,
        iv: [u8; 8],
    },
    Cbc {
        key: PaddedBlockEncryptingKey,
        mac: hmac::Key,
    },
}

#[allow(clippy::large_enum_variant)]
enum Open {
    Aead {
        key: LessSafeKey,
        iv: [u8; 8],
    },
    Cbc {
        key: PaddedBlockDecryptingKey,
        mac: hmac::Key,
        mac_len: usize,
    },
}

pub struct DataChannel {
    seal: Seal,
    open: Open,
    send_pid: u32,
    replay: ReplayWindow,
}

/// One direction's keys from the 256 bytes of key material: 64 cipher bytes, then 64 HMAC
/// bytes (whose first 8 are the AEAD implicit IV).
fn half(material: &[u8; 256], n: usize) -> (&[u8], &[u8]) {
    let k = &material[n * 128..n * 128 + 128];
    (&k[..64], &k[64..])
}

fn aead_key(cipher: Cipher, key: &[u8]) -> LessSafeKey {
    let alg = match cipher {
        Cipher::Aes128Gcm => &aead::AES_128_GCM,
        Cipher::Aes256Gcm => &aead::AES_256_GCM,
        _ => &aead::CHACHA20_POLY1305,
    };
    LessSafeKey::new(UnboundKey::new(alg, &key[..cipher.key_len()]).expect("key length"))
}

fn cbc_key(cipher: Cipher, key: &[u8]) -> UnboundCipherKey {
    let alg = if cipher == Cipher::Aes128Cbc {
        &AES_128
    } else {
        &AES_256
    };
    UnboundCipherKey::new(alg, &key[..cipher.key_len()]).expect("key length")
}

impl DataChannel {
    /// Client direction: send with key 0, receive with key 1.
    pub fn new(cipher: Cipher, digest: Digest, material: &[u8; 256]) -> Self {
        Self::directional(cipher, digest, material, 0, 1)
    }

    #[cfg(test)]
    pub fn new_server(cipher: Cipher, digest: Digest, material: &[u8; 256]) -> Self {
        Self::directional(cipher, digest, material, 1, 0)
    }

    fn directional(
        cipher: Cipher,
        digest: Digest,
        m: &[u8; 256],
        send: usize,
        recv: usize,
    ) -> Self {
        let (sc, sh) = half(m, send);
        let (rc, rh) = half(m, recv);
        let (seal, open) = if cipher.is_aead() {
            (
                Seal::Aead {
                    key: aead_key(cipher, sc),
                    iv: sh[..8].try_into().expect("8 bytes"),
                },
                Open::Aead {
                    key: aead_key(cipher, rc),
                    iv: rh[..8].try_into().expect("8 bytes"),
                },
            )
        } else {
            let n = digest.size();
            (
                Seal::Cbc {
                    key: PaddedBlockEncryptingKey::cbc_pkcs7(cbc_key(cipher, sc)).expect("cbc"),
                    mac: hmac::Key::new(digest.hmac(), &sh[..n]),
                },
                Open::Cbc {
                    key: PaddedBlockDecryptingKey::cbc_pkcs7(cbc_key(cipher, rc)).expect("cbc"),
                    mac: hmac::Key::new(digest.hmac(), &rh[..n]),
                    mac_len: n,
                },
            )
        };
        Self {
            seal,
            open,
            send_pid: 0,
            replay: ReplayWindow::default(),
        }
    }

    /// `header` is the op byte (`P_DATA_V1`) or op byte + 24-bit peer id (`P_DATA_V2`).
    /// `None` once packet ids run out (4 billion packets; the server renegotiates long before).
    pub fn encrypt(&mut self, header: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
        self.send_pid = self.send_pid.checked_add(1)?;
        let pid = self.send_pid.to_be_bytes();
        match &self.seal {
            Seal::Aead { key, iv } => {
                let mut nonce = [0u8; 12];
                nonce[..4].copy_from_slice(&pid);
                nonce[4..].copy_from_slice(iv);
                let mut aad = Vec::with_capacity(header.len() + 4);
                aad.extend_from_slice(header);
                aad.extend_from_slice(&pid);
                let mut body = payload.to_vec();
                let tag = key
                    .seal_in_place_separate_tag(
                        Nonce::assume_unique_for_key(nonce),
                        Aad::from(&aad),
                        &mut body,
                    )
                    .ok()?;
                let mut out = Vec::with_capacity(aad.len() + TAG + body.len());
                out.extend_from_slice(&aad);
                out.extend_from_slice(tag.as_ref());
                out.extend_from_slice(&body);
                Some(out)
            }
            Seal::Cbc { key, mac } => {
                let mut iv = [0u8; 16];
                getrandom::fill(&mut iv).ok()?;
                let mut body = Vec::with_capacity(4 + payload.len() + 16);
                body.extend_from_slice(&pid);
                body.extend_from_slice(payload);
                key.less_safe_encrypt(&mut body, EncryptionContext::Iv128(FixedLength::from(iv)))
                    .ok()?;
                let mut m = hmac::Context::with_key(mac);
                m.update(&iv);
                m.update(&body);
                let tag = m.sign();
                let mut out =
                    Vec::with_capacity(header.len() + tag.as_ref().len() + 16 + body.len());
                out.extend_from_slice(header);
                out.extend_from_slice(tag.as_ref());
                out.extend_from_slice(&iv);
                out.extend_from_slice(&body);
                Some(out)
            }
        }
    }

    /// Authenticates, decrypts and replay-checks one packet. `None` = drop it.
    pub fn decrypt(&mut self, packet: &[u8], header_len: usize) -> Option<Vec<u8>> {
        let (header, rest) = packet.split_at_checked(header_len)?;
        let (pid, payload) = match &self.open {
            Open::Aead { key, iv } => {
                if rest.len() < 4 + TAG {
                    return None;
                }
                let pid: [u8; 4] = rest[..4].try_into().ok()?;
                let tag = &rest[4..4 + TAG];
                let ct = &rest[4 + TAG..];
                let mut nonce = [0u8; 12];
                nonce[..4].copy_from_slice(&pid);
                nonce[4..].copy_from_slice(iv);
                let mut aad = Vec::with_capacity(header_len + 4);
                aad.extend_from_slice(header);
                aad.extend_from_slice(&pid);
                let mut out = vec![0u8; ct.len()];
                key.open_separate_gather(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(&aad),
                    ct,
                    tag,
                    &mut out,
                )
                .ok()?;
                (u32::from_be_bytes(pid), out)
            }
            Open::Cbc { key, mac, mac_len } => {
                if rest.len() < mac_len + 16 + 16 {
                    return None;
                }
                let (tag, rest) = rest.split_at(*mac_len);
                hmac::verify(mac, rest, tag).ok()?;
                let iv: [u8; 16] = rest[..16].try_into().ok()?;
                let mut body = rest[16..].to_vec();
                let plain = key
                    .decrypt(&mut body, DecryptionContext::Iv128(FixedLength::from(iv)))
                    .ok()?;
                let (pid, payload) = plain.split_first_chunk::<4>()?;
                (u32::from_be_bytes(*pid), payload.to_vec())
            }
        };
        self.replay.check_and_set(pid).then_some(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn material() -> [u8; 256] {
        let mut m = [0u8; 256];
        for (i, b) in m.iter_mut().enumerate() {
            *b = (i * 7 + 3) as u8;
        }
        m
    }

    #[test]
    fn every_cipher_round_trips_both_ways_and_rejects_replays() {
        for cipher in [
            Cipher::Aes128Gcm,
            Cipher::Aes256Gcm,
            Cipher::ChaCha20Poly1305,
            Cipher::Aes128Cbc,
            Cipher::Aes256Cbc,
        ] {
            let m = material();
            let mut client = DataChannel::new(cipher, Digest::Sha256, &m);
            let mut server = DataChannel::new_server(cipher, Digest::Sha256, &m);
            let header = [0x48, 0, 0, 7];
            let p = client.encrypt(&header, b"an IP packet").unwrap();
            assert_eq!(&p[..4], &header);
            assert_eq!(
                server.decrypt(&p, 4).as_deref(),
                Some(&b"an IP packet"[..]),
                "{cipher:?}"
            );
            assert_eq!(server.decrypt(&p, 4), None, "replay {cipher:?}");
            let mut bad = client.encrypt(&header, b"x").unwrap();
            if cipher.is_aead() {
                bad[1] ^= 1; // the header is authenticated
            } else {
                let n = bad.len() - 1;
                bad[n] ^= 1;
            }
            assert_eq!(server.decrypt(&bad, 4), None, "tamper {cipher:?}");
            let back = server.encrypt(&[0x30], b"reply").unwrap();
            assert_eq!(client.decrypt(&back, 1).as_deref(), Some(&b"reply"[..]));
        }
    }

    /// Layout: op, packet id (starting at 1), tag, ciphertext.
    #[test]
    fn aead_layout() {
        let m = material();
        let mut c = DataChannel::new(Cipher::Aes256Gcm, Digest::Sha1, &m);
        let p = c.encrypt(&[0x30], b"").unwrap();
        assert_eq!(p.len(), 1 + 4 + 16);
        assert_eq!(&p[1..5], &[0, 0, 0, 1]);
    }
}
