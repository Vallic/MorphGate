//! `vault-sync/v1`: the open protocol MorphGate clients use to sync encrypted vaults.
//!
//! [`types`] mirrors `spec/openapi.yaml` and is shared by clients and servers. With the default
//! `client` feature, [`SyncClient`] speaks the protocol over HTTPS. Nothing here ever sees
//! plaintext: envelopes and wrapped keys are opaque bytes produced by `mg-vault`.

pub mod types;

#[cfg(feature = "client")]
mod client;

#[cfg(feature = "client")]
pub use client::{Error, Payment, SyncClient};
pub use types::*;
