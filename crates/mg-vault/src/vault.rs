//! Per-vault data keys, sealed to an account's X25519 public key.
//!
//! Sealed format (v1): `0x01 ‖ ephemeral_pk(32) ‖ nonce(24) ‖ ct(key_id(16) ‖ key(32)) ‖ tag(16)`.
//! The AEAD key is HKDF(X25519(eph, recipient), salt = eph_pk ‖ recipient_pk).

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{AccountKeys, Error, Result, aead, random};

const VERSION: u8 = 1;
const INFO_SEAL: &[u8] = b"morphgate/v1/vault-key-seal";
const SEALED_LEN: usize = 1 + 32 + aead::NONCE_LEN + 16 + 32 + aead::TAG_LEN;

pub struct VaultKey {
    id: [u8; 16],
    key: Zeroizing<[u8; 32]>,
}

impl VaultKey {
    pub fn generate() -> Result<Self> {
        Ok(Self {
            id: random::bytes()?,
            key: Zeroizing::new(random::bytes()?),
        })
    }

    /// Identifies the key generation; travels in every envelope so rotation is possible.
    pub fn id(&self) -> &[u8; 16] {
        &self.id
    }

    pub(crate) fn key(&self) -> &[u8; 32] {
        &self.key
    }

    /// `wrapped_vault_key` for a member with the given X25519 public key.
    pub fn seal_to(&self, recipient_enc_pub: &[u8; 32]) -> Result<Vec<u8>> {
        let recipient = PublicKey::from(*recipient_enc_pub);
        let eph = StaticSecret::from(random::bytes::<32>()?);
        let eph_pub = PublicKey::from(&eph);
        let shared = eph.diffie_hellman(&recipient);
        if !shared.was_contributory() {
            return Err(Error::Malformed("low-order recipient public key"));
        }
        let (k, aad) = seal_key(shared.as_bytes(), eph_pub.as_bytes(), recipient.as_bytes());

        let mut plain = Zeroizing::new([0u8; 48]);
        plain[..16].copy_from_slice(&self.id);
        plain[16..].copy_from_slice(&*self.key);

        let mut out = Vec::with_capacity(SEALED_LEN);
        out.push(VERSION);
        out.extend_from_slice(eph_pub.as_bytes());
        out.extend_from_slice(&aead::seal(&k, &aad, plain.as_slice())?);
        Ok(out)
    }

    pub fn open(account: &AccountKeys, sealed: &[u8]) -> Result<Self> {
        if sealed.len() != SEALED_LEN {
            return Err(Error::Malformed("sealed vault key has wrong length"));
        }
        if sealed[0] != VERSION {
            return Err(Error::Version(sealed[0]));
        }
        let eph_pub: [u8; 32] = sealed[1..33].try_into().expect("len checked");
        let me = account.enc_secret();
        let shared = me.diffie_hellman(&PublicKey::from(eph_pub));
        if !shared.was_contributory() {
            return Err(Error::Decrypt);
        }
        let (k, aad) = seal_key(shared.as_bytes(), &eph_pub, PublicKey::from(me).as_bytes());
        let plain = aead::open(&k, &aad, &sealed[33..])?;
        Ok(Self {
            id: plain[..16].try_into().expect("fixed length"),
            key: Zeroizing::new(plain[16..48].try_into().expect("fixed length")),
        })
    }
}

fn seal_key(
    shared: &[u8; 32],
    eph_pub: &[u8; 32],
    recipient_pub: &[u8; 32],
) -> (Zeroizing<[u8; 32]>, Vec<u8>) {
    let mut ctx = Vec::with_capacity(1 + 64);
    ctx.push(VERSION);
    ctx.extend_from_slice(eph_pub);
    ctx.extend_from_slice(recipient_pub);
    (aead::hkdf32(shared, Some(&ctx[1..]), INFO_SEAL), ctx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let account = AccountKeys::generate().unwrap();
        let vk = VaultKey::generate().unwrap();
        let sealed = vk.seal_to(&account.public().enc).unwrap();
        assert_eq!(sealed.len(), SEALED_LEN);
        let back = VaultKey::open(&account, &sealed).unwrap();
        assert_eq!(back.id(), vk.id());
        assert_eq!(back.key(), vk.key());
    }

    #[test]
    fn other_account_cannot_open() {
        let alice = AccountKeys::generate().unwrap();
        let mallory = AccountKeys::generate().unwrap();
        let sealed = VaultKey::generate()
            .unwrap()
            .seal_to(&alice.public().enc)
            .unwrap();
        assert_eq!(
            VaultKey::open(&mallory, &sealed).err(),
            Some(Error::Decrypt)
        );
    }

    #[test]
    fn tampering_is_detected() {
        let account = AccountKeys::generate().unwrap();
        let mut sealed = VaultKey::generate()
            .unwrap()
            .seal_to(&account.public().enc)
            .unwrap();
        *sealed.last_mut().unwrap() ^= 1;
        assert_eq!(
            VaultKey::open(&account, &sealed).err(),
            Some(Error::Decrypt)
        );
    }

    #[test]
    fn low_order_recipient_is_rejected() {
        let vk = VaultKey::generate().unwrap();
        assert!(matches!(vk.seal_to(&[0u8; 32]), Err(Error::Malformed(_))));
    }
}
