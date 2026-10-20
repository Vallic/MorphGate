//! Master password → `MasterKey` → (`AuthKey`, KEK).

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{Error, Result, aead::hkdf32, random};

const INFO_AUTH: &[u8] = b"morphgate/v1/auth";
const INFO_KEK: &[u8] = b"morphgate/v1/kek";

/// Argon2id parameters. Travel with the account (`prelogin`) so they can be raised later.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    pub salt: Vec<u8>,
}

impl KdfParams {
    /// Floors enforced on every derivation. The server supplies these parameters, so a
    /// malicious server must not be able to downgrade them to make `AuthKey` cheap to crack.
    pub const MIN_M_KIB: u32 = 64 * 1024;
    pub const MIN_T: u32 = 2;
    pub const MIN_SALT_LEN: usize = 16;

    /// Defaults for new accounts: 256 MiB, 3 passes, 1 lane.
    pub fn recommended() -> Result<Self> {
        Ok(Self {
            m_kib: 256 * 1024,
            t: 3,
            p: 1,
            salt: random::bytes::<16>()?.to_vec(),
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.m_kib < Self::MIN_M_KIB {
            return Err(Error::WeakKdf("memory cost below 64 MiB"));
        }
        if self.t < Self::MIN_T {
            return Err(Error::WeakKdf("fewer than 2 passes"));
        }
        if self.p == 0 || self.p > 16 {
            return Err(Error::WeakKdf("parallelism must be 1..=16"));
        }
        if self.salt.len() < Self::MIN_SALT_LEN {
            return Err(Error::WeakKdf("salt shorter than 16 bytes"));
        }
        Ok(())
    }
}

/// Root secret derived from the master password. Never stored, never sent.
#[derive(ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    pub fn derive(password: &[u8], params: &KdfParams) -> Result<Self> {
        params.validate()?;
        let argon = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(params.m_kib, params.t, params.p, Some(32)).map_err(|_| Error::Kdf)?,
        );
        let mut out = [0u8; 32];
        argon
            .hash_password_into(password, &params.salt, &mut out)
            .map_err(|_| Error::Kdf)?;
        Ok(Self(out))
    }

    /// Proof of password knowledge for `/auth/login`.
    pub fn auth_key(&self) -> AuthKey {
        AuthKey(*hkdf32(&self.0, None, INFO_AUTH))
    }

    /// Key-encryption key for the account private keys.
    pub(crate) fn kek(&self) -> Zeroizing<[u8; 32]> {
        hkdf32(&self.0, None, INFO_KEK)
    }
}

/// Sent to the server on register/login. The server must store only a slow hash of it.
#[derive(ZeroizeOnDrop, PartialEq, Eq)]
pub struct AuthKey([u8; 32]);

impl AuthKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AuthKey(<redacted>)")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn fast_params() -> KdfParams {
        KdfParams {
            m_kib: KdfParams::MIN_M_KIB,
            t: KdfParams::MIN_T,
            p: 1,
            salt: vec![7; 16],
        }
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = MasterKey::derive(b"correct horse", &fast_params()).unwrap();
        let b = MasterKey::derive(b"correct horse", &fast_params()).unwrap();
        assert_eq!(a.auth_key(), b.auth_key());
    }

    #[test]
    fn different_password_or_salt_changes_keys() {
        let base = MasterKey::derive(b"correct horse", &fast_params()).unwrap();
        let other_pw = MasterKey::derive(b"correct horsf", &fast_params()).unwrap();
        let mut salted = fast_params();
        salted.salt = vec![8; 16];
        let other_salt = MasterKey::derive(b"correct horse", &salted).unwrap();
        assert_ne!(base.auth_key(), other_pw.auth_key());
        assert_ne!(base.auth_key(), other_salt.auth_key());
    }

    #[test]
    fn auth_key_and_kek_are_domain_separated() {
        let mk = MasterKey::derive(b"pw", &fast_params()).unwrap();
        assert_ne!(mk.auth_key().as_bytes(), &*mk.kek());
    }

    #[test]
    fn weak_parameters_are_rejected() {
        let cases = [
            KdfParams {
                m_kib: 1024,
                ..fast_params()
            },
            KdfParams {
                t: 1,
                ..fast_params()
            },
            KdfParams {
                p: 0,
                ..fast_params()
            },
            KdfParams {
                salt: vec![0; 8],
                ..fast_params()
            },
        ];
        for params in cases {
            assert!(
                matches!(MasterKey::derive(b"pw", &params), Err(Error::WeakKdf(_))),
                "{params:?}"
            );
        }
    }

    #[test]
    fn recommended_params_validate() {
        let p = KdfParams::recommended().unwrap();
        p.validate().unwrap();
        assert_ne!(p.salt, KdfParams::recommended().unwrap().salt);
    }
}
