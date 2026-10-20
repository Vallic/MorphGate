//! Reference `vault-sync/v1` server.
//!
//! Zero-knowledge by construction: it stores ciphertext envelopes, wrapped keys, public keys and
//! a slow hash of each account's `AuthKey`. It never receives a master password or plaintext.
//! Run it behind a TLS-terminating reverse proxy.

mod api;
mod approvals;
mod auth;
mod blobs;
mod db;
mod events;
mod export;
mod scim;
mod sharing;
mod sso;
mod util;

use std::path::Path;
use std::sync::{Arc, Mutex};

pub use api::router;

#[derive(Clone)]
pub struct Config {
    pub registration_open: bool,
    /// The largest blob accepted (`features.blobs.max_blob_bytes`).
    pub max_blob_bytes: u64,
    /// Blob storage per owner: an account's personal vaults, or an organization's vaults.
    pub blob_quota_bytes: u64,
    /// Where browsers reach this server (behind its proxy), for single sign-on's redirect URI.
    pub public_url: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            registration_open: true,
            max_blob_bytes: 25 * 1024 * 1024,
            blob_quota_bytes: 1024 * 1024 * 1024,
            public_url: "http://127.0.0.1:8443".into(),
        }
    }
}

/// Shared handler state: one SQLite connection behind a mutex (plenty for a self-hosted server).
#[derive(Clone)]
pub struct AppState {
    pub(crate) db: Arc<Mutex<rusqlite::Connection>>,
    pub(crate) secret: [u8; 32],
    pub(crate) config: Config,
    /// Talks to identity providers.
    pub(crate) http: reqwest::Client,
}

/// An organization's OpenID Connect provider (set with `vault-sync-server sso`).
pub use sso::Provider as SsoProvider;

impl AppState {
    pub fn open(path: &Path, config: Config) -> Result<Self, String> {
        let conn = rusqlite::Connection::open(path).map_err(|e| e.to_string())?;
        Self::from_conn(conn, config)
    }

    pub fn in_memory(config: Config) -> Result<Self, String> {
        Self::from_conn(
            rusqlite::Connection::open_in_memory().map_err(|e| e.to_string())?,
            config,
        )
    }

    fn from_conn(mut conn: rusqlite::Connection, config: Config) -> Result<Self, String> {
        let secret = db::init(&mut conn).map_err(|e| e.to_string())?;
        let http = reqwest::Client::builder()
            .user_agent(concat!("vault-sync-reference/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            db: Arc::new(Mutex::new(conn)),
            secret,
            config,
            http,
        })
    }

    pub(crate) fn redirect_uri(&self) -> String {
        format!(
            "{}/sso/callback",
            self.config.public_url.trim_end_matches('/')
        )
    }

    /// The organization by id or by name.
    fn org_id(&self, org: &str) -> Result<String, String> {
        let db = self
            .db
            .lock()
            .map_err(|_| "database lock poisoned".to_string())?;
        let mut stmt = db
            .prepare("SELECT id FROM orgs WHERE id = ?1 OR name = ?1")
            .map_err(|e| e.to_string())?;
        let ids: Vec<String> = stmt
            .query_map([org], |r| r.get(0))
            .and_then(Iterator::collect)
            .map_err(|e| e.to_string())?;
        match ids.as_slice() {
            [id] => Ok(id.clone()),
            [] => Err(format!("no organization {org}")),
            _ => Err(format!(
                "several organizations are called {org}; use its id"
            )),
        }
    }

    /// Puts an organization (id or name) behind an identity provider; `require` also turns
    /// `require_sso` on. Returns the organization's id.
    pub fn set_sso(
        &self,
        org: &str,
        provider: &SsoProvider,
        require: bool,
    ) -> Result<String, String> {
        let id = self.org_id(org)?;
        let db = self
            .db
            .lock()
            .map_err(|_| "database lock poisoned".to_string())?;
        sso::configure(&db, &id, provider).map_err(|e| e.to_string())?;
        if require {
            let mut p = sharing::org_policies(&db, &id).map_err(|e| e.to_string())?;
            p.require_sso = true;
            db.execute(
                "UPDATE orgs SET policies = ?2 WHERE id = ?1",
                rusqlite::params![id, serde_json::to_string(&p).expect("serializable")],
            )
            .map_err(|e| e.to_string())?;
        }
        Ok(id)
    }

    /// Removes an organization's identity provider (and its sessions; `require_sso` goes off).
    pub fn remove_sso(&self, org: &str) -> Result<String, String> {
        let id = self.org_id(org)?;
        let db = self
            .db
            .lock()
            .map_err(|_| "database lock poisoned".to_string())?;
        sso::remove(&db, &id).map_err(|e| e.to_string())?;
        Ok(id)
    }

    /// A new SCIM bearer token for an organization (id or name), replacing its old one. It is
    /// stored as a hash, so this is the only time it is shown. Returns the organization's id
    /// and the token.
    pub fn scim_token(&self, org: &str) -> Result<(String, String), String> {
        let id = self.org_id(org)?;
        let db = self
            .db
            .lock()
            .map_err(|_| "database lock poisoned".to_string())?;
        let token = scim::issue_token(&db, &id).map_err(|e| e.to_string())?;
        Ok((id, token))
    }

    /// Revokes an organization's SCIM token: provisioning stops. Returns the organization's id.
    pub fn revoke_scim(&self, org: &str) -> Result<String, String> {
        let id = self.org_id(org)?;
        let db = self
            .db
            .lock()
            .map_err(|_| "database lock poisoned".to_string())?;
        scim::revoke_token(&db, &id).map_err(|e| e.to_string())?;
        Ok(id)
    }
}
