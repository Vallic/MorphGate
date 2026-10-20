//! MorphGate vault crypto, as specified by `vault-sync/v1`.
//!
//! Key hierarchy:
//!
//! ```text
//! master password ──Argon2id──▶ MasterKey ──HKDF──▶ AuthKey  (sent to server, which stores a slow hash)
//!                                          └─HKDF──▶ KEK      (never leaves the device)
//! KEK / RecoveryKey ──wraps──▶ AccountKeys (X25519 + Ed25519)
//! AccountKeys (X25519) ──sealed box──▶ VaultKey ──XChaCha20-Poly1305──▶ item envelopes
//! ```
//!
//! The server only ever sees `AuthKey`, public keys, wrapped keys and envelopes. Shared vaults
//! seal the same vault key to every member; [`sharing`] holds what makes that safe.

pub mod account;
mod aead;
pub mod blob;
pub mod envelope;
mod error;
pub mod kdf;
mod random;
mod recovery_code;
pub mod sharing;
pub mod vault;

pub use account::{AccountKeys, DeviceKey, PublicKeys, RecoveryKey};
pub use blob::BlobKind;
pub use envelope::ItemContext;
pub use error::Error;
pub use kdf::{AuthKey, KdfParams, MasterKey};
pub use vault::VaultKey;

pub type Result<T> = core::result::Result<T, Error>;
