//! MorphGate local vault.
//!
//! Every item (host, SSH key, snippet) is stored in SQLite as a `vault-sync/v1` envelope, so the
//! database file holds only ciphertext plus the metadata the sync server would see anyway
//! (ids, timestamps, revisions). The same rows are what `mg-sync` will push and pull.

#[cfg(feature = "http")]
pub mod account;
mod blobs;
mod device;
mod error;
pub mod export;
mod history;
pub mod model;
pub mod moving;
mod schema;
#[cfg(feature = "http")]
pub mod sharing;
pub mod sync;
#[cfg(feature = "http")]
pub mod sync_http;
mod vault;

pub use blobs::{BlobRef, BlobState, Refusal};
pub use error::Error;
pub use mg_vault::BlobKind;
pub use model::{
    Attachment, CertRenewal, CloudReach, CloudSource, ForwardRule, Host, HostAuth, HostCa,
    HostGroup, HostSource, Identity, Item, ItemData, LogChunk, MAX_ATTACHMENT_BYTES, MemberKey,
    PortForward, SessionLog, Snippet, SshKey, TerminalTheme, VpnKind, VpnProfile, is_hex_color,
};
pub use moving::{Carry, MovePlan, Moved, Planned, Why};
pub use vault::{Access, LocalVault, MIN_PASSWORD_CHARS, NewCredentials, Status, VaultInfo};

pub type Result<T> = core::result::Result<T, Error>;
