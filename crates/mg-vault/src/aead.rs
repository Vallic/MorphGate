//! XChaCha20-Poly1305 and HKDF helpers shared by the other modules.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Error, Result, random};

pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const TAG_LEN: usize = 16;

/// HKDF-SHA256 to a 32-byte key.
pub(crate) fn hkdf32(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(info, out.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

pub(crate) fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    msg: &[u8],
) -> Result<Vec<u8>> {
    XChaCha20Poly1305::new(&Key::from(*key))
        .encrypt(&XNonce::from(*nonce), Payload { msg, aad })
        .map_err(|_| Error::Decrypt)
}

pub(crate) fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    XChaCha20Poly1305::new(&Key::from(*key))
        .decrypt(&XNonce::from(*nonce), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::Decrypt)
}

/// `nonce || ciphertext` with a fresh random nonce.
pub(crate) fn seal(key: &[u8; 32], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let nonce = random::bytes::<NONCE_LEN>()?;
    let ct = encrypt(key, &nonce, aad, msg)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub(crate) fn open(key: &[u8; 32], aad: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::Malformed("ciphertext too short"));
    }
    let (nonce, ct) = data.split_at(NONCE_LEN);
    decrypt(key, nonce.try_into().expect("split at NONCE_LEN"), aad, ct)
}
