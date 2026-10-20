//! Blobs: what is too big for an item (session logs, attachments). The sync server stores each
//! one under the SHA-256 of its bytes and can check that name, but not read it.
//!
//! Layout (v1): `version(1) ‖ key_id(16) ‖ nonce(24) ‖ ciphertext`.
//!
//! * Plaintext is padded (ISO/IEC 7816-4) to 4 KiB buckets so exact sizes don't leak.
//! * AEAD associated data binds the blob to its vault and kind, so the server cannot move it.
//! * A blob carries no signature: the signed item that refers to it holds its hash.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::envelope::{pad_to, unpad};
use crate::{Error, Result, VaultKey, aead, random};

pub const VERSION: u8 = 1;
pub const PAD_BUCKET: usize = 4096;
/// The protocol's largest blob (servers may advertise less in `features.blobs.max_blob_bytes`).
pub const MAX_BLOB_LEN: usize = 25 * 1024 * 1024;

const HEADER_LEN: usize = 1 + 16 + aead::NONCE_LEN;
const AAD_DOMAIN: &[u8] = b"morphgate/v1/blob";

/// What a blob holds; the server sees it too (retention and plan rules differ).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BlobKind {
    Attachment,
    SessionLog,
}

impl BlobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            BlobKind::Attachment => "attachment",
            BlobKind::SessionLog => "session_log",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "attachment" => Some(BlobKind::Attachment),
            "session_log" => Some(BlobKind::SessionLog),
            _ => None,
        }
    }
}

/// `domain ‖ u16 len ‖ vault_id ‖ u16 len ‖ kind ‖ version ‖ key_id`
fn aad(vault_id: &str, kind: BlobKind, version_and_key_id: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_DOMAIN.len() + 4 + vault_id.len() + 16 + 17);
    out.extend_from_slice(AAD_DOMAIN);
    for part in [vault_id.as_bytes(), kind.as_str().as_bytes()] {
        out.extend_from_slice(&u16::try_from(part.len()).unwrap_or(u16::MAX).to_be_bytes());
        out.extend_from_slice(part);
    }
    out.extend_from_slice(version_and_key_id);
    out
}

/// Encrypts `plaintext` for `vault_id` under the vault key.
pub fn seal(vk: &VaultKey, vault_id: &str, kind: BlobKind, plaintext: &[u8]) -> Result<Vec<u8>> {
    let padded = pad_to(plaintext, PAD_BUCKET);
    let total = HEADER_LEN + padded.len() + aead::TAG_LEN;
    if total > MAX_BLOB_LEN {
        return Err(Error::TooLarge(plaintext.len()));
    }
    let nonce = random::bytes::<{ aead::NONCE_LEN }>()?;
    let mut out = Vec::with_capacity(total);
    out.push(VERSION);
    out.extend_from_slice(vk.id());
    out.extend_from_slice(&nonce);
    let aad = aad(vault_id, kind, &out[..17]);
    out.extend_from_slice(&aead::encrypt(vk.key(), &nonce, &aad, &padded)?);
    Ok(out)
}

/// Decrypts a blob of `vault_id`. Check its [`hash`] against the item that refers to it first.
pub fn open(
    vk: &VaultKey,
    vault_id: &str,
    kind: BlobKind,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < HEADER_LEN + aead::TAG_LEN {
        return Err(Error::Malformed("blob too short"));
    }
    if blob[0] != VERSION {
        return Err(Error::Version(blob[0]));
    }
    if blob[1..17] != vk.id()[..] {
        return Err(Error::KeyIdMismatch);
    }
    let aad = aad(vault_id, kind, &blob[..17]);
    let nonce: &[u8; aead::NONCE_LEN] = blob[17..HEADER_LEN].try_into().expect("fixed length");
    let padded = aead::decrypt(vk.key(), nonce, &aad, &blob[HEADER_LEN..])?;
    unpad(&padded)
}

/// The id of the vault key generation a blob was sealed with, to pick the key that opens it.
pub fn key_id(blob: &[u8]) -> Result<[u8; 16]> {
    if blob.len() < 17 {
        return Err(Error::Malformed("blob too short"));
    }
    if blob[0] != VERSION {
        return Err(Error::Version(blob[0]));
    }
    Ok(blob[1..17].try_into().expect("16 bytes"))
}

/// The blob's name on the server: lowercase hex SHA-256 of its bytes.
pub fn hash(blob: &[u8]) -> String {
    Sha256::digest(blob)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAULT: &str = "01JVAULT0000000000000000000";

    #[test]
    fn round_trip_padded_and_named() {
        let vk = VaultKey::generate().unwrap();
        let blob = seal(&vk, VAULT, BlobKind::SessionLog, b"{\"version\":2}").unwrap();
        assert_eq!(
            blob.len(),
            HEADER_LEN + PAD_BUCKET + aead::TAG_LEN,
            "padded to a bucket"
        );
        assert_eq!(
            &open(&vk, VAULT, BlobKind::SessionLog, &blob).unwrap()[..],
            b"{\"version\":2}"
        );
        assert_eq!(key_id(&blob).unwrap(), *vk.id());
        let h = hash(&blob);
        assert_eq!(h.len(), 64);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn bound_to_vault_kind_and_key() {
        let vk = VaultKey::generate().unwrap();
        let blob = seal(&vk, VAULT, BlobKind::Attachment, b"secret").unwrap();
        assert_eq!(
            open(&vk, "01JOTHER", BlobKind::Attachment, &blob),
            Err(Error::Decrypt)
        );
        assert_eq!(
            open(&vk, VAULT, BlobKind::SessionLog, &blob),
            Err(Error::Decrypt)
        );
        let other = VaultKey::generate().unwrap();
        assert_eq!(
            open(&other, VAULT, BlobKind::Attachment, &blob),
            Err(Error::KeyIdMismatch)
        );
        let mut tampered = blob.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            open(&vk, VAULT, BlobKind::Attachment, &tampered),
            Err(Error::Decrypt)
        );
    }

    #[test]
    fn hash_matches_a_known_vector() {
        // SHA-256("abc"), FIPS 180-2.
        assert_eq!(
            hash(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn too_large_is_refused() {
        let vk = VaultKey::generate().unwrap();
        let big = vec![0u8; MAX_BLOB_LEN];
        assert!(matches!(
            seal(&vk, VAULT, BlobKind::Attachment, &big),
            Err(Error::TooLarge(_))
        ));
    }
}
