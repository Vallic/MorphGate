//! Item envelopes: the only thing the sync server stores per item.
//!
//! Layout (v1): `version(1) ‖ key_id(16) ‖ nonce(24) ‖ ciphertext ‖ sig(64)`.
//!
//! * Plaintext is padded (ISO/IEC 7816-4) to 256-byte buckets so exact sizes don't leak.
//! * AEAD associated data binds the envelope to its vault, item id and schema version,
//!   so the server cannot swap blobs between items or vaults.
//! * The author's Ed25519 signature covers the associated data and every byte before it.

use ed25519_dalek::{Signature, VerifyingKey};
use zeroize::Zeroizing;

use crate::{AccountKeys, Error, Result, VaultKey, aead, random};

pub const VERSION: u8 = 1;
pub const PAD_BUCKET: usize = 256;
/// Matches `capabilities.limits.max_envelope_bytes` default.
pub const MAX_ENVELOPE_LEN: usize = 64 * 1024;

const HEADER_LEN: usize = 1 + 16 + aead::NONCE_LEN;
const SIG_LEN: usize = 64;
const SIG_DOMAIN: &[u8] = b"morphgate/v1/envelope-sig";

/// Where an item lives; bound into every envelope.
#[derive(Clone, Copy, Debug)]
pub struct ItemContext<'a> {
    pub vault_id: &'a str,
    pub item_id: &'a str,
    pub schema_version: u16,
}

impl ItemContext<'_> {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.vault_id.len() + self.item_id.len());
        for part in [self.vault_id.as_bytes(), self.item_id.as_bytes()] {
            out.extend_from_slice(&u16::try_from(part.len()).unwrap_or(u16::MAX).to_be_bytes());
            out.extend_from_slice(part);
        }
        out.extend_from_slice(&self.schema_version.to_be_bytes());
        out
    }
}

pub fn seal(
    vk: &VaultKey,
    author: &AccountKeys,
    ctx: &ItemContext<'_>,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let padded = pad(plaintext);
    let total = HEADER_LEN + padded.len() + aead::TAG_LEN + SIG_LEN;
    if total > MAX_ENVELOPE_LEN {
        return Err(Error::TooLarge(plaintext.len()));
    }
    let nonce = random::bytes::<{ aead::NONCE_LEN }>()?;

    let mut out = Vec::with_capacity(total);
    out.push(VERSION);
    out.extend_from_slice(vk.id());
    out.extend_from_slice(&nonce);
    let aad = aad(ctx, &out[..17]);
    let ct = aead::encrypt(vk.key(), &nonce, &aad, &padded)?;
    out.extend_from_slice(&ct);
    let sig = author.sign(&signed_message(&aad, &out));
    out.extend_from_slice(&sig);
    Ok(out)
}

/// Verifies the author's signature, then decrypts. `author_sign_pub` is the Ed25519 public key
/// of the account that wrote the item.
pub fn open(
    vk: &VaultKey,
    author_sign_pub: &[u8; 32],
    ctx: &ItemContext<'_>,
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if envelope.len() < HEADER_LEN + aead::TAG_LEN + SIG_LEN {
        return Err(Error::Malformed("envelope too short"));
    }
    if envelope[0] != VERSION {
        return Err(Error::Version(envelope[0]));
    }
    let (body, sig) = envelope.split_at(envelope.len() - SIG_LEN);
    let aad = aad(ctx, &body[..17]);

    let vk_pub = VerifyingKey::from_bytes(author_sign_pub).map_err(|_| Error::Signature)?;
    let sig = Signature::from_bytes(sig.try_into().expect("split at SIG_LEN"));
    vk_pub
        .verify_strict(&signed_message(&aad, body), &sig)
        .map_err(|_| Error::Signature)?;

    if body[1..17] != vk.id()[..] {
        return Err(Error::KeyIdMismatch);
    }
    let nonce: &[u8; aead::NONCE_LEN] = body[17..HEADER_LEN].try_into().expect("fixed length");
    let padded = aead::decrypt(vk.key(), nonce, &aad, &body[HEADER_LEN..])?;
    unpad(&padded)
}

fn aad(ctx: &ItemContext<'_>, version_and_key_id: &[u8]) -> Vec<u8> {
    let mut aad = ctx.encode();
    aad.extend_from_slice(version_and_key_id);
    aad
}

fn signed_message(aad: &[u8], body: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(SIG_DOMAIN.len() + 4 + aad.len() + body.len());
    msg.extend_from_slice(SIG_DOMAIN);
    msg.extend_from_slice(&u32::try_from(aad.len()).unwrap_or(u32::MAX).to_be_bytes());
    msg.extend_from_slice(aad);
    msg.extend_from_slice(body);
    msg
}

fn pad(plain: &[u8]) -> Zeroizing<Vec<u8>> {
    pad_to(plain, PAD_BUCKET)
}

/// ISO/IEC 7816-4 padding (`0x80` then zeros) to a multiple of `bucket` bytes.
pub(crate) fn pad_to(plain: &[u8], bucket: usize) -> Zeroizing<Vec<u8>> {
    let len = (plain.len() + 1).div_ceil(bucket) * bucket;
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    out.extend_from_slice(plain);
    out.push(0x80);
    out.resize(len, 0);
    out
}

pub(crate) fn unpad(padded: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let end = padded
        .iter()
        .rposition(|&b| b != 0)
        .ok_or(Error::Malformed("bad padding"))?;
    if padded[end] != 0x80 {
        return Err(Error::Malformed("bad padding"));
    }
    Ok(Zeroizing::new(padded[..end].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CTX: ItemContext<'static> = ItemContext {
        vault_id: "01JVAULT0000000000000000000",
        item_id: "01JITEM00000000000000000000",
        schema_version: 1,
    };

    fn setup() -> (VaultKey, AccountKeys) {
        (
            VaultKey::generate().unwrap(),
            AccountKeys::generate().unwrap(),
        )
    }

    #[test]
    fn roundtrip() {
        let (vk, me) = setup();
        let msg = br#"{"type":"host","hostname":"db1.internal","port":22}"#;
        let env = seal(&vk, &me, &CTX, msg).unwrap();
        assert_eq!(&*open(&vk, &me.public().sign, &CTX, &env).unwrap(), msg);
    }

    #[test]
    fn sizes_are_bucketed() {
        let (vk, me) = setup();
        let overhead = HEADER_LEN + aead::TAG_LEN + SIG_LEN;
        for (len, buckets) in [(0, 1), (1, 1), (255, 1), (256, 2), (600, 3)] {
            let env = seal(&vk, &me, &CTX, &vec![b'x'; len]).unwrap();
            assert_eq!(env.len() - overhead, buckets * PAD_BUCKET, "len {len}");
            assert_eq!(open(&vk, &me.public().sign, &CTX, &env).unwrap().len(), len);
        }
    }

    #[test]
    fn trailing_zero_bytes_survive_padding() {
        let (vk, me) = setup();
        let msg = [1, 2, 0, 0, 0x80, 0];
        let env = seal(&vk, &me, &CTX, &msg).unwrap();
        assert_eq!(&*open(&vk, &me.public().sign, &CTX, &env).unwrap(), &msg);
    }

    #[test]
    fn moved_to_another_item_fails() {
        let (vk, me) = setup();
        let env = seal(&vk, &me, &CTX, b"secret").unwrap();
        let moved = ItemContext {
            item_id: "01JOTHER0000000000000000000",
            ..CTX
        };
        assert_eq!(
            open(&vk, &me.public().sign, &moved, &env).err(),
            Some(Error::Signature)
        );
        let other_schema = ItemContext {
            schema_version: 2,
            ..CTX
        };
        assert_eq!(
            open(&vk, &me.public().sign, &other_schema, &env).err(),
            Some(Error::Signature)
        );
    }

    #[test]
    fn any_bit_flip_fails() {
        let (vk, me) = setup();
        let env = seal(&vk, &me, &CTX, b"secret").unwrap();
        for i in [0, 5, 20, HEADER_LEN + 3, env.len() - 1] {
            let mut bad = env.clone();
            bad[i] ^= 0x01;
            assert!(
                open(&vk, &me.public().sign, &CTX, &bad).is_err(),
                "flip at {i}"
            );
        }
    }

    #[test]
    fn wrong_author_fails() {
        let (vk, me) = setup();
        let mallory = AccountKeys::generate().unwrap();
        let env = seal(&vk, &mallory, &CTX, b"evil").unwrap();
        assert_eq!(
            open(&vk, &me.public().sign, &CTX, &env).err(),
            Some(Error::Signature)
        );
    }

    #[test]
    fn wrong_vault_key_is_reported() {
        let (vk, me) = setup();
        let env = seal(&vk, &me, &CTX, b"secret").unwrap();
        let other = VaultKey::generate().unwrap();
        assert_eq!(
            open(&other, &me.public().sign, &CTX, &env).err(),
            Some(Error::KeyIdMismatch)
        );
    }

    #[test]
    fn oversized_plaintext_is_rejected() {
        let (vk, me) = setup();
        assert!(matches!(
            seal(&vk, &me, &CTX, &vec![0; MAX_ENVELOPE_LEN]),
            Err(Error::TooLarge(_))
        ));
    }
}
