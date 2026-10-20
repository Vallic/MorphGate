//! Account keypairs (X25519 for key wrapping, Ed25519 for item signatures) and the recovery key.

use ed25519_dalek::{Signer, SigningKey};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{Error, MasterKey, Result, aead, random};

const AAD_ACCOUNT_KEYS: &[u8] = b"morphgate/v1/account-keys";
const INFO_RECOVERY_KEK: &[u8] = b"morphgate/v1/recovery-kek";
const INFO_RECOVERY_AUTH: &[u8] = b"morphgate/v1/recovery-auth";
const INFO_DEVICE_KEK: &[u8] = b"morphgate/v1/device-kek";
const SECRETS_LEN: usize = 64;

pub struct AccountKeys {
    enc: StaticSecret,
    sign: SigningKey,
}

/// Public halves, stored in plain on the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKeys {
    pub enc: [u8; 32],
    pub sign: [u8; 32],
}

impl AccountKeys {
    pub fn generate() -> Result<Self> {
        let enc = random::bytes::<32>()?;
        let sign = random::bytes::<32>()?;
        Ok(Self::from_secrets(&enc, &sign))
    }

    pub(crate) fn from_secrets(enc: &[u8; 32], sign: &[u8; 32]) -> Self {
        Self {
            enc: StaticSecret::from(*enc),
            sign: SigningKey::from_bytes(sign),
        }
    }

    pub fn public(&self) -> PublicKeys {
        PublicKeys {
            enc: PublicKey::from(&self.enc).to_bytes(),
            sign: self.sign.verifying_key().to_bytes(),
        }
    }

    /// `wrapped_private_keys` for the server: XChaCha20-Poly1305(KEK, x25519 ‖ ed25519).
    pub fn wrap(&self, mk: &MasterKey) -> Result<Vec<u8>> {
        aead::seal(&mk.kek(), AAD_ACCOUNT_KEYS, self.secrets().as_slice())
    }

    pub fn unwrap(mk: &MasterKey, wrapped: &[u8]) -> Result<Self> {
        Self::from_plain(&aead::open(&mk.kek(), AAD_ACCOUNT_KEYS, wrapped)?)
    }

    /// `wrapped_private_keys_rk`: the same secrets under the recovery key.
    pub fn wrap_with_recovery(&self, rk: &RecoveryKey) -> Result<Vec<u8>> {
        aead::seal(&rk.kek(), AAD_ACCOUNT_KEYS, self.secrets().as_slice())
    }

    pub fn unwrap_with_recovery(rk: &RecoveryKey, wrapped: &[u8]) -> Result<Self> {
        Self::from_plain(&aead::open(&rk.kek(), AAD_ACCOUNT_KEYS, wrapped)?)
    }

    /// The same secrets under a device key (kept in the OS keychain; never leaves the device).
    pub fn wrap_with_device(&self, dk: &DeviceKey) -> Result<Vec<u8>> {
        aead::seal(&dk.kek(), AAD_ACCOUNT_KEYS, self.secrets().as_slice())
    }

    pub fn unwrap_with_device(dk: &DeviceKey, wrapped: &[u8]) -> Result<Self> {
        Self::from_plain(&aead::open(&dk.kek(), AAD_ACCOUNT_KEYS, wrapped)?)
    }

    pub(crate) fn enc_secret(&self) -> &StaticSecret {
        &self.enc
    }

    pub(crate) fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.sign.sign(msg).to_bytes()
    }

    fn secrets(&self) -> Zeroizing<[u8; SECRETS_LEN]> {
        let mut out = Zeroizing::new([0u8; SECRETS_LEN]);
        out[..32].copy_from_slice(self.enc.as_bytes());
        out[32..].copy_from_slice(self.sign.as_bytes());
        out
    }

    fn from_plain(plain: &[u8]) -> Result<Self> {
        if plain.len() != SECRETS_LEN {
            return Err(Error::Malformed("account key blob has wrong length"));
        }
        let enc: Zeroizing<[u8; 32]> = Zeroizing::new(plain[..32].try_into().expect("len checked"));
        let sign: Zeroizing<[u8; 32]> =
            Zeroizing::new(plain[32..].try_into().expect("len checked"));
        Ok(Self::from_secrets(&enc, &sign))
    }
}

/// Random 256-bit key shown to the user once at signup.
#[derive(ZeroizeOnDrop)]
pub struct RecoveryKey([u8; 32]);

impl RecoveryKey {
    pub fn generate() -> Result<Self> {
        Ok(Self(random::bytes::<32>()?))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The code shown to the user once: `XXXX-XXXX-…` (56 Crockford base32 symbols, 24-bit check).
    pub fn to_code(&self) -> Zeroizing<String> {
        crate::recovery_code::encode(&self.0)
    }

    /// Parses a code typed back by the user; rejects typos via the embedded check.
    pub fn from_code(code: &str) -> Result<Self> {
        Ok(Self(*crate::recovery_code::decode(code)?))
    }

    /// `recovery_proof` for the server; it stores only a hash of this.
    pub fn proof(&self) -> Zeroizing<[u8; 32]> {
        aead::hkdf32(&self.0, None, INFO_RECOVERY_AUTH)
    }

    fn kek(&self) -> Zeroizing<[u8; 32]> {
        aead::hkdf32(&self.0, None, INFO_RECOVERY_KEK)
    }
}

/// Random 256-bit key that unlocks the vault on one device without the master password. It
/// lives in the OS keychain; the vault keeps only the account keys wrapped under it.
#[derive(ZeroizeOnDrop)]
pub struct DeviceKey([u8; 32]);

impl DeviceKey {
    pub fn generate() -> Result<Self> {
        Ok(Self(random::bytes::<32>()?))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn kek(&self) -> Zeroizing<[u8; 32]> {
        aead::hkdf32(&self.0, None, INFO_DEVICE_KEK)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::tests::fast_params;

    #[test]
    fn device_key_wrap_is_its_own_domain() {
        let keys = AccountKeys::generate().unwrap();
        let dk = DeviceKey::generate().unwrap();
        let wrapped = keys.wrap_with_device(&dk).unwrap();
        let back = AccountKeys::unwrap_with_device(&dk, &wrapped).unwrap();
        assert_eq!(keys.public(), back.public());
        assert!(
            AccountKeys::unwrap_with_device(&DeviceKey::generate().unwrap(), &wrapped).is_err()
        );
        // Same bytes as a recovery key derive a different KEK.
        let rk = RecoveryKey::from_bytes(*dk.as_bytes());
        assert!(AccountKeys::unwrap_with_recovery(&rk, &wrapped).is_err());
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let mk = MasterKey::derive(b"pw", &fast_params()).unwrap();
        let keys = AccountKeys::generate().unwrap();
        let back = AccountKeys::unwrap(&mk, &keys.wrap(&mk).unwrap()).unwrap();
        assert_eq!(keys.public(), back.public());
    }

    #[test]
    fn wrong_password_cannot_unwrap() {
        let mk = MasterKey::derive(b"pw", &fast_params()).unwrap();
        let wrong = MasterKey::derive(b"pW", &fast_params()).unwrap();
        let wrapped = AccountKeys::generate().unwrap().wrap(&mk).unwrap();
        assert_eq!(
            AccountKeys::unwrap(&wrong, &wrapped).err(),
            Some(Error::Decrypt)
        );
    }

    #[test]
    fn recovery_key_unwraps_and_is_independent_of_password() {
        let mk = MasterKey::derive(b"pw", &fast_params()).unwrap();
        let rk = RecoveryKey::generate().unwrap();
        let keys = AccountKeys::generate().unwrap();
        let wrapped_rk = keys.wrap_with_recovery(&rk).unwrap();
        assert_eq!(
            AccountKeys::unwrap_with_recovery(&rk, &wrapped_rk)
                .unwrap()
                .public(),
            keys.public()
        );
        assert!(AccountKeys::unwrap(&mk, &wrapped_rk).is_err());
        assert_ne!(*rk.proof(), *rk.kek());
        assert_eq!(
            RecoveryKey::from_code(&rk.to_code()).unwrap().as_bytes(),
            rk.as_bytes()
        );
    }

    #[test]
    fn truncated_blob_is_rejected() {
        let mk = MasterKey::derive(b"pw", &fast_params()).unwrap();
        assert!(matches!(
            AccountKeys::unwrap(&mk, &[0u8; 10]),
            Err(Error::Malformed(_))
        ));
    }
}
