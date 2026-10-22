//! Hosts from cloud providers, for MorphGate's cloud sources: what a provider's API lists, as hosts
//! before they are vault items. The calls go from the device to the provider: its credentials
//! never reach MorphGate's server.
//!
//! One module per provider (docs/features/cloud-sources.md): Vallic Cloud through its API; AWS,
//! Google Cloud, Azure, Hetzner Cloud and DigitalOcean through their CLIs, as [`Machine`]s; and
//! feeds, documents a team publishes at a URL.

pub mod aws;
pub mod azure;
pub mod cli;
pub mod digitalocean;
pub mod feed;
pub mod gcp;
pub mod hetzner;
pub mod shape;
pub mod vallic;

use std::collections::BTreeMap;

use serde::Serialize;

/// A host as a provider describes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryHost {
    /// Stable within its source: what a refresh matches the vault's host on.
    pub external_id: String,
    /// The group it goes in (a project, an account).
    pub group: String,
    pub label: String,
    /// Its address, or for a host reached through `jump` by a command, the name its host key is
    /// kept under.
    pub hostname: String,
    pub port: u16,
    pub user: String,
    /// Run at login, with a terminal, instead of the shell.
    pub login_command: Option<String>,
    /// The host it is reached through (an `external_id` of the same source).
    pub jump: Option<String>,
    /// How `jump` carries it: a command the jump host runs.
    pub jump_command: Option<String>,
    /// The provider's hosts offer no SFTP, and no port or agent forwarding.
    pub no_sftp: bool,
    pub no_forwarding: bool,
    /// The machine's state where it isn't running (`stopped`); its `hostname` may be empty then,
    /// and the vault keeps the last one.
    pub state: Option<String>,
    /// The key it was started with (an EC2 key pair's name): a vault key by that label signs in.
    pub key_name: Option<String>,
    /// Reached through its cloud (Session Manager, an Instance Connect Endpoint, IAP) rather
    /// than an address; `hostname` is then the instance's id or name.
    pub via: Option<Via>,
    /// The server's host keys (`ssh-ed25519 AAAA…`), as its publisher knows them (feeds):
    /// trusted for it without asking.
    pub host_keys: Vec<String>,
    /// Tags it comes with (feeds), added to the person's.
    pub tags: Vec<String>,
}

/// How a machine is reached through its cloud: what the command needs (the app builds it).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Via {
    /// `aws-ssm`, `aws-eice` or `gcp-iap`.
    pub kind: String,
    /// The EC2 instance id, or the Compute Engine instance's name.
    pub instance: String,
    /// The AWS region, or the Compute Engine zone.
    pub place: String,
    pub project: Option<String>,
}

/// A virtual machine as a cloud's CLI lists it, before a source's choices (how to reach it, who
/// to log in as, how to group) make it a host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Machine {
    /// Stable within its source: `aws:<region>/<instance id>`, `gcp:<project>/<zone>/<name>`,
    /// `azure:<resource id, lowercase>`.
    pub external_id: String,
    pub name: String,
    /// The region (AWS), project (Google Cloud) or resource group (Azure): its default group.
    pub place: String,
    /// Its public DNS name or address, while it has one.
    pub public_address: Option<String>,
    pub private_address: Option<String>,
    /// Who it says to log in as: Azure's admin user, or the `morphgate:user` tag (AWS) or
    /// `morphgate-user` label or tag (Google Cloud, Azure).
    pub user: Option<String>,
    /// The EC2 key pair it was started with.
    pub key_name: Option<String>,
    pub running: bool,
    /// The cloud's word for its state: `running`, `stopped`, `TERMINATED`, `VM deallocated`…
    pub state: String,
    pub tags: BTreeMap<String, String>,
    /// What a proxy needs to reach it without an address.
    pub reach: Reach,
}

/// Where a machine is, for a proxy (Session Manager, Instance Connect Endpoint, IAP).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "provider", rename_all = "camelCase")]
pub enum Reach {
    Aws {
        instance_id: String,
        region: String,
    },
    Gcp {
        project: String,
        zone: String,
        name: String,
    },
    /// By its address only (Azure, Hetzner Cloud, DigitalOcean).
    Address,
}

/// What a listing found, and what it couldn't list (a region or project it was refused, said
/// rather than failing the rest).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Listing {
    pub machines: Vec<Machine>,
    pub skipped: Vec<String>,
}

/// An empty string as none: the CLIs print `""` for an address a machine doesn't have.
fn some(s: Option<String>) -> Option<String> {
    s.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("can't reach {0}: {1}")]
    Unreachable(String, String),
    /// The sign-in ended (refused, revoked, or used on another device): sign in again.
    #[error("signed out of {0}: sign in again")]
    SignedOut(String),
    #[error("{0}")]
    Api(String),
    /// A feed answered 401 or 403 to its token.
    #[error("{0} refused the token")]
    TokenRefused(String),
    /// A provider's CLI isn't on this device.
    #[error(
        "{0} isn't installed on this computer, or MorphGate can't find it: install it, or give its path in the source"
    )]
    NotInstalled(String),
    /// What a provider's CLI said when it failed (an expired session says what to run).
    #[error("{0}")]
    Cli(String),
}

pub type Result<T> = std::result::Result<T, Error>;
