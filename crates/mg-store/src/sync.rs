//! Sync between the local vault and a `vault-sync/v1` server.
//!
//! The engine ([`sync_once`]) is transport-agnostic: anything implementing [`Remote`] works
//! (the HTTP client behind the `http` feature, or an in-memory fake in tests).
//!
//! Conflict policy: the server copy always wins for an item id, and a local edit that lost is
//! kept as a new "(conflict)" item, so nothing is ever silently discarded.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::Mutex;

use mg_vault::{
    AccountKeys, AuthKey, KdfParams, MasterKey, PublicKeys, RecoveryKey, VaultKey, envelope,
};
use rusqlite::{OptionalExtension, params};
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::vault::{
    Access, Unlocked, context, decrypt, envelope_key_id, now, open_envelope, version_in,
};
use crate::{BlobKind, Error, ItemData, LocalVault, Result, history};

/// Pseudo item id under which the refresh token is sealed (never a valid ULID, so no clash).
const TOKEN_ID: &str = "sync:refresh-token";
pub const MAX_PUSH: usize = 500;

#[derive(Clone, Debug)]
pub struct VaultMaterial {
    pub id: String,
    pub key_id: [u8; 16],
    pub wrapped_vault_key: Vec<u8>,
}

/// Everything a server needs to create the account. Contains no secrets except `auth_key`,
/// which the server stores only as a slow hash.
pub struct AccountExport {
    pub kdf: KdfParams,
    pub auth_key: AuthKey,
    pub public: PublicKeys,
    pub wrapped: Vec<u8>,
    pub wrapped_rk: Vec<u8>,
    pub recovery_proof: Vec<u8>,
    pub vault: VaultMaterial,
}

/// What a fresh device downloads to join an account.
pub struct AccountImport {
    pub kdf: KdfParams,
    pub public: PublicKeys,
    pub wrapped: Vec<u8>,
    pub wrapped_rk: Option<Vec<u8>>,
    pub vault: VaultMaterial,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncConfig {
    pub server_url: String,
    pub email: String,
    pub account_id: String,
    pub device_id: String,
    pub device_public_key: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncInfo {
    pub config: SyncConfig,
    pub last_sync_at: Option<i64>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteItem {
    pub id: String,
    pub rev: i64,
    pub deleted: bool,
    pub envelope: Option<Vec<u8>>,
    /// Who pushed this revision (`None`: an older server, meaning the vault's owner).
    pub author_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemotePage {
    pub items: Vec<RemoteItem>,
    pub head_rev: i64,
    pub has_more: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outgoing {
    pub id: String,
    pub base_rev: i64,
    pub deleted: bool,
    /// The item, or a deletion's signed envelope (`None`: a deletion from before item history).
    pub envelope: Option<Vec<u8>>,
    /// Local `updated_at` when read; an edit during the push keeps the row dirty.
    pub updated_at: i64,
    /// The version in `envelope` (`None`: not known).
    pub version: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PushOutcome {
    Accepted {
        id: String,
        rev: i64,
    },
    Conflict {
        current: RemoteItem,
    },
    Rejected {
        id: String,
        /// The server's error code (`stale_key`: re-seal under the current key and retry).
        code: String,
        reason: String,
    },
}

#[derive(Debug)]
pub enum RemoteError {
    /// History needed by this device was purged: full resync.
    Gone,
    Unauthorized,
    /// The account signed this device out (`401 device_revoked`).
    DeviceRevoked,
    /// The account was deleted (`401 account_deleted`).
    AccountDeleted,
    /// `402`: the plan behind the vault (the account's, or its organization's) doesn't cover it
    /// now; the reason, for the user.
    PlanRequired(String),
    /// It isn't there (a blob deleted already, say).
    NotFound,
    /// The server won't take this one (no plan for it, storage full, too large): the reason,
    /// for the user. Other uploads go on.
    Refused(crate::Refusal),
    /// The organization's vaults wait on this device (single sign-on, approval).
    Held(String, Hold),
    Other(String),
}

/// Why an organization's vaults wait on this device. They stay here, unsynced edits included,
/// and sync once it's settled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Hold {
    /// Turn on two-step verification for the account: the organization requires it.
    Totp,
    /// Sign in at the organization's identity provider.
    Sso,
    /// An owner or admin, or one of the member's approved devices, has to approve this device.
    Approval,
    /// The organization denied this device.
    Denied,
}

/// Notes an organization's vaults as held (once per organization).
pub(crate) fn note_held(list: &mut Vec<(String, Hold)>, org: String, why: Hold) {
    if !list.iter().any(|(o, _)| *o == org) {
        list.push((org, why));
    }
}

/// A `vault-sync/v1` server, as far as the engine is concerned.
pub trait Remote: Sync {
    fn pull(
        &self,
        vault_id: &str,
        since: i64,
    ) -> impl Future<Output = core::result::Result<RemotePage, RemoteError>> + Send;
    fn push(
        &self,
        vault_id: &str,
        items: Vec<Outgoing>,
    ) -> impl Future<Output = core::result::Result<Vec<PushOutcome>, RemoteError>> + Send;

    /// Uploads a blob (the same bytes again are fine). Servers without blobs refuse.
    fn put_blob(
        &self,
        _vault_id: &str,
        _hash: &str,
        _kind: &str,
        _bytes: Vec<u8>,
    ) -> impl Future<Output = core::result::Result<(), RemoteError>> + Send {
        async {
            Err(RemoteError::Refused(
                "the sync server doesn't store session logs".into(),
            ))
        }
    }

    fn delete_blob(
        &self,
        _vault_id: &str,
        _hash: &str,
    ) -> impl Future<Output = core::result::Result<(), RemoteError>> + Send {
        async { Err(RemoteError::NotFound) }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("sync server: {0}")]
    Remote(String),
    #[error("the sync server no longer accepts this device's session; sign in again")]
    Unauthorized,
    /// The account signed this device out: the app forgets what it keeps from it.
    #[error("this device was signed out of its sync account")]
    DeviceRevoked,
    /// The account was deleted elsewhere: sync goes off, the personal vault stays.
    #[error("the sync account was deleted")]
    AccountDeleted,
    /// No plan covers the vault now (`402`): it stays here, readable, and syncs once one does.
    #[error("sync server: {0}")]
    PlanRequired(String),
    #[error(
        "the sync server sent older data (revision {remote}) than this device already has ({local}); refusing to roll back"
    )]
    Rollback { local: i64, remote: i64 },
    #[error(transparent)]
    Store(#[from] Error),
    #[error("vault state is poisoned; restart MorphGate")]
    Poisoned,
    #[error("the organization's vaults wait on this device")]
    Held(String, Hold),
}

impl From<RemoteError> for SyncError {
    fn from(e: RemoteError) -> Self {
        match e {
            RemoteError::Unauthorized => SyncError::Unauthorized,
            RemoteError::DeviceRevoked => SyncError::DeviceRevoked,
            RemoteError::AccountDeleted => SyncError::AccountDeleted,
            RemoteError::PlanRequired(m) => SyncError::PlanRequired(m),
            RemoteError::Gone => SyncError::Remote("history gone".into()),
            RemoteError::NotFound => SyncError::Remote("not found".into()),
            RemoteError::Held(org, why) => SyncError::Held(org, why),
            RemoteError::Refused(r) => SyncError::Remote(r.reason),
            RemoteError::Other(m) => SyncError::Remote(m),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub pulled: usize,
    pub pushed: usize,
    pub conflicts: usize,
    pub rejected: Vec<String>,
    /// Shared vaults that couldn't sync this round (the personal vault fails the whole round).
    pub vault_errors: Vec<(String, String)>,
    /// Of those, the ones refused for want of a plan (their organization's lapsed or ended).
    pub plan_refused: Vec<String>,
    /// Items re-sealed under a vault's newer key (finishing a rotation).
    pub resealed: usize,
    /// Blobs (session logs) uploaded.
    pub blobs_uploaded: usize,
    /// Blobs the server refused: `(vault, reason)`.
    pub blob_errors: Vec<(String, String)>,
    /// Organizations whose vaults wait on this device, and why.
    pub held: Vec<(String, Hold)>,
}

impl SyncReport {
    /// Whether anything visible changed locally.
    pub fn changed_locally(&self) -> bool {
        self.pulled > 0 || self.conflicts > 0
    }
}

// ------------------------------------------------------------------ account & config

impl LocalVault {
    /// Material for `POST /auth/register`. Verifies `password`. Vaults created before recovery
    /// proofs were stored get a fresh recovery key, returned so the UI can show it once.
    pub fn export_for_registration(
        &mut self,
        password: &str,
    ) -> Result<(AccountExport, Option<RecoveryKey>)> {
        self.unlocked()?;
        let row = self.account_row()?.ok_or(Error::NotInitialized)?;
        let mk = MasterKey::derive(password.as_bytes(), &row.kdf)?;
        let account = AccountKeys::unwrap(&mk, &row.wrapped).map_err(|e| match e {
            mg_vault::Error::Decrypt => Error::WrongPassword,
            other => other.into(),
        })?;
        if account.public() != row.public {
            return Err(Error::Corrupt(
                "account keys do not match their public halves".into(),
            ));
        }
        let stored: Option<Vec<u8>> =
            self.conn
                .query_row("SELECT recovery_proof FROM account WHERE id = 1", [], |r| {
                    r.get(0)
                })?;
        let (rotated, wrapped_rk, recovery_proof) = match stored {
            Some(proof) => (None, row.wrapped_rk.clone(), proof),
            None => {
                let rk = self.rotate_recovery_key()?;
                let wrapped_rk = self.account_row()?.ok_or(Error::NotInitialized)?.wrapped_rk;
                let proof = rk.proof().to_vec();
                (Some(rk), wrapped_rk, proof)
            }
        };
        let export = AccountExport {
            kdf: row.kdf,
            auth_key: mk.auth_key(),
            public: row.public,
            wrapped: row.wrapped,
            wrapped_rk,
            recovery_proof,
            vault: self.vault_material()?,
        };
        Ok((export, rotated))
    }

    /// Replaces the recovery key (the old one stops working). Returns the new one, to show once.
    pub fn rotate_recovery_key(&mut self) -> Result<RecoveryKey> {
        let rk = RecoveryKey::generate()?;
        let wrapped = self.unlocked()?.account.wrap_with_recovery(&rk)?;
        self.conn.execute(
            "UPDATE account SET wrapped_private_keys_rk = ?1, recovery_proof = ?2 WHERE id = 1",
            params![wrapped, rk.proof().as_slice()],
        )?;
        Ok(rk)
    }

    fn vault_material(&self) -> Result<VaultMaterial> {
        let (id, key_id, wrapped_vault_key): (String, Vec<u8>, Vec<u8>) = self.conn.query_row(
            "SELECT id, key_id, wrapped_vault_key FROM vaults WHERE personal = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let key_id = key_id
            .try_into()
            .map_err(|_| Error::Corrupt("vault key id has wrong length".into()))?;
        Ok(VaultMaterial {
            id,
            key_id,
            wrapped_vault_key,
        })
    }

    /// First sign-in on a device with no local vault: adopts the account's keys and vault and
    /// unlocks. Items arrive with the first sync.
    pub fn adopt_account(&mut self, password: &str, import: AccountImport) -> Result<()> {
        if self.account_row()?.is_some() {
            return Err(Error::AlreadyInitialized);
        }
        let opened = open_import(password, &import)?;
        let tx = self.conn.transaction()?;
        insert_import(&tx, &import)?;
        tx.commit()?;
        self.keys = Some(unlocked_from(opened, import));
        Ok(())
    }

    /// Signing in on a device that has a vault of its own, never synced: the device takes the
    /// account's keys and vault (it opens with the account's master password from now on, and
    /// the account's recovery key), and what its own vault held goes into the account's, files
    /// included, with the same ids, for the first sync to upload. Nothing changes on a wrong
    /// password. Returns how many items moved over.
    pub fn join_account(&mut self, password: &str, import: AccountImport) -> Result<usize> {
        let keys = self.unlocked()?;
        if self.sync_info()?.is_some() {
            return Err(Error::Invalid("this device syncs already".into()));
        }
        if !keys.shared.is_empty() {
            return Err(Error::Invalid(
                "this device has team vaults: it synced before".into(),
            ));
        }
        let old = keys.vault_id.clone();
        let opened = open_import(password, &import)?;
        // What this vault holds, in the clear (in memory only), with its files.
        let items: Vec<crate::Item> = self
            .items()?
            .into_iter()
            .filter(|i| i.vault_id == old)
            .collect();
        let mut files: HashMap<String, (BlobKind, Zeroizing<Vec<u8>>)> = HashMap::new();
        for item in &items {
            let kind = match item.data {
                ItemData::SessionLog(_) => BlobKind::SessionLog,
                _ => BlobKind::Attachment,
            };
            for hash in item.data.blob_refs() {
                if let Some(plain) = self.open_blob(&old, kind, hash)? {
                    files.insert(hash.to_owned(), (kind, plain));
                }
            }
        }

        let previous = self.keys.take();
        self.conn.execute_batch("SAVEPOINT join_account")?;
        let new = import.vault.id.clone();
        let done = (|| -> Result<usize> {
            self.conn.execute_batch(
                "DELETE FROM items; DELETE FROM blobs; DELETE FROM blob_deletes;
                 DELETE FROM device_unlock; DELETE FROM vaults; DELETE FROM account;",
            )?;
            insert_import(&self.conn, &import)?;
            self.keys = Some(unlocked_from(opened, import));
            let count = items.len();
            for item in items {
                let mut data = item.data;
                match &mut data {
                    ItemData::Attachment(a) => {
                        if let Some((kind, plain)) = files.get(&a.blob) {
                            a.blob = self.add_blob(&new, *kind, plain)?.hash;
                        }
                    }
                    ItemData::SessionLog(l) => {
                        for chunk in &mut l.chunks {
                            if let Some((kind, plain)) = files.get(&chunk.hash) {
                                let sealed = self.add_blob(&new, *kind, plain)?;
                                chunk.hash = sealed.hash;
                                chunk.size = sealed.size;
                            }
                        }
                    }
                    _ => {}
                }
                self.write(&new, &item.id, &data)?;
            }
            Ok(count)
        })();
        match done {
            Ok(count) => {
                self.conn.execute_batch("RELEASE join_account")?;
                Ok(count)
            }
            Err(e) => {
                self.conn
                    .execute_batch("ROLLBACK TO join_account; RELEASE join_account")?;
                self.keys = previous;
                Err(e)
            }
        }
    }

    pub fn sync_info(&self) -> Result<Option<SyncInfo>> {
        Ok(self
            .conn
            .query_row(
                "SELECT server_url, email, account_id, device_id, device_public_key, last_sync_at, last_error
                 FROM sync_state WHERE id = 1",
                [],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, Vec<u8>>(4)?,
                        r.get::<_, Option<i64>>(5)?,
                        r.get::<_, Option<String>>(6)?,
                    ))
                },
            )
            .optional()?
            .map(|(server_url, email, account_id, device_id, pk, last_sync_at, last_error)| SyncInfo {
                config: SyncConfig {
                    server_url,
                    email,
                    account_id,
                    device_id,
                    device_public_key: pk.try_into().unwrap_or([0; 32]),
                },
                last_sync_at,
                last_error,
            }))
    }

    pub fn enable_sync(&mut self, cfg: &SyncConfig) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO sync_state (id, server_url, email, account_id, device_id, device_public_key)
             VALUES (1, ?1, ?2, ?3, ?4, ?5)",
            params![cfg.server_url, cfg.email, cfg.account_id, cfg.device_id, cfg.device_public_key.as_slice()],
        )?;
        if let Some(keys) = self.keys.as_mut() {
            keys.account_id = Some(cfg.account_id.clone());
        }
        Ok(())
    }

    /// The sync account moved to another address (the server already agreed).
    pub fn set_sync_email(&self, email: &str) -> Result<()> {
        self.conn
            .execute("UPDATE sync_state SET email = ?1 WHERE id = 1", [email])?;
        Ok(())
    }

    /// Stops syncing but keeps every personal item; re-enabling (possibly elsewhere) uploads
    /// everything again. Shared vaults live on the server, so their copies go.
    pub fn disable_sync(&mut self) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM sync_state", [])?;
        tx.execute("DELETE FROM vaults WHERE personal = 0", [])?;
        tx.execute("DELETE FROM orgs", [])?;
        tx.execute("DELETE FROM items WHERE deleted = 1", [])?;
        tx.execute("UPDATE items SET rev = 0, dirty = 1, author_id = NULL", [])?;
        tx.execute("UPDATE vaults SET head_rev = 0", [])?;
        tx.commit()?;
        if let Some(keys) = self.keys.as_mut() {
            keys.shared.clear();
            keys.account_id = None;
        }
        Ok(())
    }

    /// Stores the refresh token sealed under the vault key (only readable while unlocked).
    pub fn set_sync_token(&self, token: &str) -> Result<()> {
        let keys = self.unlocked()?;
        let env = envelope::seal(
            &keys.vault_key,
            &keys.account,
            &context(&keys.vault_id, TOKEN_ID),
            token.as_bytes(),
        )?;
        self.conn
            .execute("UPDATE sync_state SET token = ?1 WHERE id = 1", [env])?;
        Ok(())
    }

    /// Whether this device holds a sync session (readable while locked: nothing is decrypted).
    pub fn has_sync_token(&self) -> Result<bool> {
        Ok(self
            .conn
            .query_row(
                "SELECT token IS NOT NULL FROM sync_state WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(false))
    }

    /// The server ended this device's session; sync waits for a new sign-in.
    pub fn clear_sync_token(&self) -> Result<()> {
        self.conn
            .execute("UPDATE sync_state SET token = NULL WHERE id = 1", [])?;
        Ok(())
    }

    pub fn sync_token(&self) -> Result<Option<Zeroizing<String>>> {
        let keys = self.unlocked()?;
        let env: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT token FROM sync_state WHERE id = 1", [], |r| {
                r.get(0)
            })
            .optional()?
            .flatten();
        let Some(env) = env else { return Ok(None) };
        let plain = envelope::open(
            &keys.vault_key,
            &keys.sign_pub,
            &context(&keys.vault_id, TOKEN_ID),
            &env,
        )?;
        let token =
            String::from_utf8(plain.to_vec()).map_err(|_| Error::Corrupt("sync token".into()))?;
        Ok(Some(Zeroizing::new(token)))
    }

    pub fn record_sync(&self, error: Option<&str>) -> Result<()> {
        match error {
            None => self.conn.execute(
                "UPDATE sync_state SET last_sync_at = ?1, last_error = NULL WHERE id = 1",
                [now()],
            )?,
            Some(e) => self
                .conn
                .execute("UPDATE sync_state SET last_error = ?1 WHERE id = 1", [e])?,
        };
        Ok(())
    }

    // -------------------------------------------------------------- engine primitives

    /// The vaults to sync, with each one's revision cursor and what this account may do there:
    /// the personal vault first.
    fn sync_targets(&self) -> Result<Vec<(String, i64, Access)>> {
        let keys = self.unlocked()?;
        let mut stmt = self
            .conn
            .prepare("SELECT id, head_rev FROM vaults ORDER BY personal DESC, created_at, id")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (id, head) = row?;
            // A vault without keys on this device (shouldn't happen) is skipped, not fatal.
            if let Ok(access) = keys.access(&id) {
                out.push((id, head, access));
            }
        }
        Ok(out)
    }

    fn reset_cursor(&mut self, vault: &str) -> Result<()> {
        self.conn
            .execute("UPDATE vaults SET head_rev = 0 WHERE id = ?1", [vault])?;
        Ok(())
    }

    /// Local changes to push. Tombstones of items the server never saw are dropped instead.
    fn outgoing(
        &mut self,
        vault: &str,
        limit: usize,
        skip: &HashSet<String>,
    ) -> Result<Vec<Outgoing>> {
        self.conn.execute(
            "DELETE FROM items WHERE vault_id = ?1 AND deleted = 1 AND rev = 0",
            [vault],
        )?;
        let mut stmt = self.conn.prepare(
            "SELECT id, rev, deleted, envelope, updated_at, version FROM items
             WHERE vault_id = ?1 AND dirty = 1 ORDER BY updated_at, id LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![vault, (limit + skip.len()) as i64], |r| {
            Ok(Outgoing {
                id: r.get(0)?,
                base_rev: r.get(1)?,
                deleted: r.get(2)?,
                envelope: r.get(3)?,
                updated_at: r.get(4)?,
                version: r.get(5)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            let row = row?;
            if !skip.contains(&row.id) {
                out.push(row);
            }
            if out.len() == limit {
                break;
            }
        }
        Ok(out)
    }

    /// Applies server items in one transaction; every envelope is verified (author and vault
    /// key) before anything is written, and no item goes back to an older version than this
    /// device has seen of it. Returns (items applied, conflicts). `cursor` advances `head_rev`
    /// when given.
    fn apply_remote(
        &mut self,
        vault: &str,
        items: &[RemoteItem],
        cursor: Option<i64>,
    ) -> Result<(usize, usize)> {
        let strict = self.strict_history;
        let keys = self.keys.as_ref().ok_or(Error::Locked)?;
        let mut copies = Vec::with_capacity(items.len());
        for r in items {
            let copy = match (&r.envelope, r.deleted) {
                (Some(env), false) => {
                    let plain = open_envelope(keys, vault, &r.id, env, r.author_id.as_deref())?;
                    history::read(&r.id, &plain)?
                }
                (None, false) => {
                    return Err(Error::Corrupt(format!("item {} has no envelope", r.id)));
                }
                // A deletion is signed when it carries its author's deletion envelope; anything
                // else counts as unsigned (as from an app before item history).
                (Some(env), true) => open_envelope(keys, vault, &r.id, env, r.author_id.as_deref())
                    .and_then(|plain| history::read(&r.id, &plain))
                    .ok()
                    .filter(|copy| copy.data.is_none())
                    .unwrap_or(history::Copy {
                        data: None,
                        version: None,
                    }),
                (None, true) => history::Copy {
                    data: None,
                    version: None,
                },
            };
            // Items are looked up by id: a shared vault must not bring in a new one that would
            // stand in for a live item of the personal vault. Moving between vaults keeps ids (the
            // old copy becomes a tombstone, and the personal vault syncs first in every round),
            // and an id this vault already had here is no newcomer (an item moved back and forth).
            if copy.data.is_some() && vault != keys.vault_id {
                let clash = self
                    .conn
                    .query_row(
                        "SELECT 1 FROM items p WHERE p.id = ?1 AND p.vault_id = ?2 AND p.deleted = 0
                         AND NOT EXISTS (SELECT 1 FROM items s WHERE s.id = ?1 AND s.vault_id = ?3)",
                        params![r.id, keys.vault_id, vault],
                        |_| Ok(()),
                    )
                    .optional()?;
                if clash.is_some() {
                    return Err(Error::Corrupt(format!(
                        "item {} of a shared vault has the id of one in your personal vault",
                        r.id
                    )));
                }
            }
            copies.push(copy);
        }
        let (mut applied, mut conflicts) = (0, 0);
        let stamp = now();
        let tx = self.conn.transaction()?;
        for (r, copy) in items.iter().zip(copies) {
            let deleted = copy.data.is_none();
            let local: Option<LocalRow> = tx
                .query_row(
                    "SELECT rev, dirty, deleted, envelope, author_id, seen_version FROM items WHERE vault_id = ?1 AND id = ?2",
                    params![vault, r.id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                        ))
                    },
                )
                .optional()?;
            match &local {
                None if deleted => continue,
                Some((rev, ..)) if *rev >= r.rev => continue,
                _ => {}
            }
            if let Some((_, dirty, _, local_env, local_author, seen)) = &local {
                // The version of the last copy the server confirmed; for a copy from before
                // item history, the one its envelope holds (unless it has a change on top).
                let seen = match (seen, dirty, local_env) {
                    (Some(seen), ..) => *seen,
                    (None, false, Some(env)) => {
                        version_in(keys, vault, &r.id, env, local_author.as_deref())
                    }
                    _ => 0,
                };
                match copy.version {
                    Some(v) if v < seen => {
                        return Err(Error::OlderItem {
                            item: r.id.clone(),
                            seen,
                            remote: v,
                        });
                    }
                    None if strict && seen > 0 => {
                        return Err(Error::UnversionedItem { item: r.id.clone() });
                    }
                    _ => {}
                }
            }
            if let Some((_, true, local_deleted, local_env, local_author, _)) = local {
                let local_data = match (local_deleted, local_env) {
                    (false, Some(env)) => {
                        Some(decrypt(keys, vault, &r.id, &env, local_author.as_deref())?)
                    }
                    _ => None,
                };
                // The same content on both sides (say, both re-sealed it), or what a cloud
                // source decides on each (two refreshes): nothing of the person's lost.
                let same = local_data == copy.data
                    || source_decides(local_data.as_ref(), copy.data.as_ref());
                if !same {
                    conflicts += 1;
                }
                // Local edit lost against the server: keep it as a separate item.
                if let (false, Some(mut data)) = (same, local_data) {
                    mark_conflict(&mut data);
                    let copy_id = Ulid::generate().to_string();
                    let version = history::next(0);
                    let plain = history::plaintext(&data, version)?;
                    let sealed = envelope::seal(
                        keys.current(vault)?,
                        &keys.account,
                        &context(vault, &copy_id),
                        &plain,
                    )?;
                    tx.execute(
                        "INSERT INTO items (id, vault_id, envelope, deleted, rev, dirty, updated_at, version, seen_version)
                         VALUES (?1, ?2, ?3, 0, 0, 1, ?4, ?5, 0)",
                        params![copy_id, vault, sealed, stamp, version],
                    )?;
                }
            }
            // Without a version (an app before item history), the next versioned copy may be
            // from a device that never saw the earlier ones: it starts over.
            let version = copy.version.unwrap_or(0);
            tx.execute(
                "INSERT INTO items (id, vault_id, envelope, deleted, rev, dirty, updated_at, author_id, version, seen_version)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7, ?8, ?8)
                 ON CONFLICT (vault_id, id) DO UPDATE SET envelope = excluded.envelope, deleted = excluded.deleted,
                     rev = excluded.rev, dirty = 0, updated_at = excluded.updated_at, author_id = excluded.author_id,
                     version = excluded.version, seen_version = excluded.seen_version",
                params![r.id, vault, if deleted { None } else { r.envelope.as_deref() }, deleted, r.rev, stamp,
                        r.author_id.as_deref().filter(|a| vault != keys.vault_id && Some(*a) != keys.account_id.as_deref()),
                        version],
            )?;
            applied += 1;
        }
        if let Some(head) = cursor {
            tx.execute(
                "UPDATE vaults SET head_rev = ?1 WHERE id = ?2",
                params![head, vault],
            )?;
        }
        tx.commit()?;
        Ok((applied, conflicts))
    }

    fn mark_pushed(&mut self, vault: &str, sent: &Outgoing, rev: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE items SET rev = ?3, author_id = NULL, seen_version = ?5,
                 dirty = CASE WHEN updated_at = ?4 THEN 0 ELSE 1 END
             WHERE vault_id = ?1 AND id = ?2",
            params![vault, sent.id, rev, sent.updated_at, sent.version],
        )?;
        Ok(())
    }

    /// Re-seals a local item under the vault's current key (after the server said `stale_key`).
    /// Returns whether there was a newer key to use.
    fn reseal(&mut self, vault: &str, id: &str) -> Result<bool> {
        let keys = self.unlocked()?;
        let row: Option<(Option<Vec<u8>>, Option<String>)> = self
            .conn
            .query_row(
                "SELECT envelope, author_id FROM items WHERE vault_id = ?1 AND id = ?2",
                params![vault, id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((Some(env), author)) = row else {
            return Ok(false);
        };
        let current = keys.current(vault)?;
        if envelope_key_id(&env)? == current.id() {
            return Ok(false);
        }
        let plain = crate::vault::open_envelope(keys, vault, id, &env, author.as_deref())?;
        // A new version, whatever app wrote it and whatever kind it is.
        let version = self.next_version(vault, id)?;
        let plain = history::with_version(&plain, version)?;
        let env = envelope::seal(current, &keys.account, &context(vault, id), &plain)?;
        self.conn.execute(
            "UPDATE items SET envelope = ?3, author_id = NULL, dirty = 1, version = ?4 WHERE vault_id = ?1 AND id = ?2",
            params![vault, id, env, version],
        )?;
        Ok(true)
    }

    /// Re-seals every live item still under an older key generation (finishing a rotation,
    /// whoever started it). Returns how many.
    pub(crate) fn reseal_old_items(&mut self, vault: &str) -> Result<usize> {
        let current = *self.unlocked()?.current(vault)?.id();
        let ids: Vec<String> = self
            .conn
            .prepare(
                "SELECT id FROM items WHERE vault_id = ?1 AND deleted = 0
                 AND substr(envelope, 2, 16) != ?2",
            )?
            .query_map(params![vault, current.as_slice()], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let mut n = 0;
        for id in ids {
            if self.reseal(vault, &id)? {
                n += 1;
            }
        }
        Ok(n)
    }

    /// After a full resync, clean items the server no longer has are gone everywhere else too.
    fn drop_unseen(&mut self, vault: &str, seen: &HashSet<String>) -> Result<()> {
        let ids: Vec<String> = self
            .conn
            .prepare("SELECT id FROM items WHERE vault_id = ?1 AND dirty = 0 AND rev > 0")?
            .query_map([vault], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        for id in ids.iter().filter(|id| !seen.contains(*id)) {
            self.conn.execute(
                "DELETE FROM items WHERE vault_id = ?1 AND id = ?2",
                params![vault, id],
            )?;
        }
        Ok(())
    }
}

/// The account's keys and vault key from an import, opened with `password` and checked.
fn open_import(password: &str, import: &AccountImport) -> Result<(AccountKeys, VaultKey)> {
    let mk = MasterKey::derive(password.as_bytes(), &import.kdf)?;
    let account = AccountKeys::unwrap(&mk, &import.wrapped).map_err(|e| match e {
        mg_vault::Error::Decrypt => Error::WrongPassword,
        other => other.into(),
    })?;
    if account.public() != import.public {
        return Err(Error::Corrupt(
            "the server's account keys do not match their public halves".into(),
        ));
    }
    let vault_key = VaultKey::open(&account, &import.vault.wrapped_vault_key)?;
    if vault_key.id() != &import.vault.key_id {
        return Err(Error::Corrupt(
            "the server's vault key id does not match".into(),
        ));
    }
    Ok((account, vault_key))
}

/// Stores an imported account and its vault (the tables are empty).
fn insert_import(conn: &rusqlite::Connection, import: &AccountImport) -> Result<()> {
    let now = now();
    conn.execute(
        "INSERT INTO account (id, kdf_m_kib, kdf_t, kdf_p, kdf_salt, enc_public_key, sign_public_key,
                              wrapped_private_keys, wrapped_private_keys_rk, created_at)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            import.kdf.m_kib,
            import.kdf.t,
            import.kdf.p,
            import.kdf.salt,
            import.public.enc.as_slice(),
            import.public.sign.as_slice(),
            import.wrapped,
            import.wrapped_rk.clone().unwrap_or_default(),
            now
        ],
    )?;
    conn.execute(
        "INSERT INTO vaults (id, key_id, wrapped_vault_key, created_at, personal) VALUES (?1, ?2, ?3, ?4, 1)",
        params![import.vault.id, import.vault.key_id.as_slice(), import.vault.wrapped_vault_key, now],
    )?;
    Ok(())
}

fn unlocked_from((account, vault_key): (AccountKeys, VaultKey), import: AccountImport) -> Unlocked {
    Unlocked {
        account,
        sign_pub: import.public.sign,
        vault_id: import.vault.id,
        vault_key,
        shared: HashMap::new(),
        pins: HashMap::new(),
        account_id: None,
    }
}

/// `(rev, dirty, deleted, envelope, author_id, seen_version)` of a local item.
type LocalRow = (
    i64,
    bool,
    bool,
    Option<Vec<u8>>,
    Option<String>,
    Option<i64>,
);

/// Whether the local copy differs from the server's only in what a cloud source decides (each
/// device refreshed it): no copy is kept, and the next refresh sets it again. A person's edit
/// (a rename, a note, a tag, a key) still makes one.
fn source_decides(local: Option<&ItemData>, remote: Option<&ItemData>) -> bool {
    match (local, remote) {
        (Some(ItemData::CloudSource(a)), Some(ItemData::CloudSource(b))) => a.same_but_refreshed(b),
        // A feed's snippets are the feed's: nobody edits them here.
        (
            Some(ItemData::Snippet(crate::Snippet {
                source: Some(_), ..
            })),
            _,
        ) => true,
        (Some(ItemData::Host(a)), Some(ItemData::Host(b))) => match (&a.source, &b.source) {
            (Some(x), Some(y))
                if x.source_ref == y.source_ref && x.external_id == y.external_id =>
            {
                persons(a) == persons(b)
            }
            _ => false,
        },
        _ => false,
    }
}

/// What of a source's host is the person's; the rest follows the source.
fn persons(h: &crate::Host) -> crate::Host {
    let source = h.source.as_deref();
    let following = source.is_some_and(|s| s.label == h.label);
    let from_source = source.map(|s| s.tags.as_slice()).unwrap_or_default();
    crate::Host {
        label: if following {
            String::new()
        } else {
            h.label.clone()
        },
        hostname: String::new(),
        port: 0,
        user: String::new(),
        jump_ref: None,
        login_command: None,
        jump_command: None,
        tags: h
            .tags
            .iter()
            .filter(|t| !from_source.contains(t))
            .cloned()
            .collect(),
        source: None,
        ..h.clone()
    }
}

fn mark_conflict(data: &mut ItemData) {
    const SUFFIX: &str = " (conflict)";
    match data {
        ItemData::Host(h) => h.label.push_str(SUFFIX),
        ItemData::SshKey(k) => k.label.push_str(SUFFIX),
        ItemData::Snippet(s) => s.name.push_str(SUFFIX),
        ItemData::PortForward(f) => f.label.push_str(SUFFIX),
        ItemData::Vpn(v) => v.label.push_str(SUFFIX),
        ItemData::MemberKey(k) => k.label.push_str(SUFFIX),
        ItemData::TerminalTheme(t) => t.name.push_str(SUFFIX),
        ItemData::SessionLog(l) => l.title.push_str(SUFFIX),
        ItemData::Identity(i) => i.label.push_str(SUFFIX),
        ItemData::HostGroup(g) => g.name.push_str(SUFFIX),
        ItemData::CloudSource(c) => c.label.push_str(SUFFIX),
        ItemData::HostCa(c) => c.label.push_str(SUFFIX),
        // Before the extension, so the file still opens.
        ItemData::Attachment(a) => {
            a.name = match a.name.rsplit_once('.') {
                Some((stem, ext)) if !stem.is_empty() => format!("{stem}{SUFFIX}.{ext}"),
                _ => format!("{}{SUFFIX}", a.name),
            }
        }
        ItemData::Unknown => {}
    }
}

// ------------------------------------------------------------------ engine

fn with<T>(
    vault: &Mutex<LocalVault>,
    f: impl FnOnce(&mut LocalVault) -> Result<T>,
) -> core::result::Result<T, SyncError> {
    let mut v = vault.lock().map_err(|_| SyncError::Poisoned)?;
    Ok(f(&mut v)?)
}

/// One pull-then-push round over every vault. The vault lock is only held between network
/// calls. A shared vault that fails is reported in [`SyncReport::vault_errors`] and the others
/// go on; the personal vault failing fails the round.
pub async fn sync_once<R: Remote>(
    vault: &Mutex<LocalVault>,
    remote: &R,
) -> core::result::Result<SyncReport, SyncError> {
    sync_once_with(vault, remote, &HashMap::new()).await
}

/// [`sync_once`], given each vault's latest revision on the server (`GET /vaults`, which the
/// sharing round lists anyway): a vault this device has up to there isn't pulled.
pub async fn sync_once_with<R: Remote>(
    vault: &Mutex<LocalVault>,
    remote: &R,
    heads: &HashMap<String, i64>,
) -> core::result::Result<SyncReport, SyncError> {
    let mut report = SyncReport::default();
    let targets = with(vault, |v| v.sync_targets())?;
    for (i, (id, start, access)) in targets.into_iter().enumerate() {
        let current = heads.get(&id) == Some(&start);
        match sync_vault(vault, remote, &id, start, access, current, &mut report).await {
            Ok(()) => {}
            Err(SyncError::Held(org, why)) => note_held(&mut report.held, org, why),
            Err(e)
                if i == 0
                    || matches!(
                        e,
                        SyncError::Unauthorized
                            | SyncError::DeviceRevoked
                            | SyncError::AccountDeleted
                            | SyncError::Poisoned
                    ) =>
            {
                return Err(e);
            }
            Err(SyncError::PlanRequired(why)) => {
                report.plan_refused.push(id.clone());
                report
                    .vault_errors
                    .push((id, format!("sync server: {why}")));
            }
            Err(e) => report.vault_errors.push((id, e.to_string())),
        }
    }
    Ok(report)
}

async fn sync_vault<R: Remote>(
    vault: &Mutex<LocalVault>,
    remote: &R,
    vault_id: &str,
    start: i64,
    access: Access,
    current: bool,
    report: &mut SyncReport,
) -> core::result::Result<(), SyncError> {
    // Pull, unless this device has everything there is.
    let mut since = start;
    let mut full: Option<HashSet<String>> = None;
    loop {
        if current {
            break;
        }
        let page = match remote.pull(vault_id, since).await {
            Ok(page) => page,
            Err(RemoteError::Gone) if full.is_none() => {
                with(vault, |v| v.reset_cursor(vault_id))?;
                full = Some(HashSet::new());
                since = 0;
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        if full.is_none() && page.head_rev < start {
            return Err(SyncError::Rollback {
                local: start,
                remote: page.head_rev,
            });
        }
        if let Some(seen) = full.as_mut() {
            seen.extend(page.items.iter().map(|i| i.id.clone()));
        }
        let cursor = if page.has_more {
            page.items.last().map_or(since, |i| i.rev)
        } else {
            page.head_rev
        };
        let (applied, conflicts) = with(vault, |v| {
            v.apply_remote(vault_id, &page.items, Some(cursor))
        })?;
        report.pulled += applied;
        report.conflicts += conflicts;
        since = cursor;
        if !page.has_more {
            break;
        }
    }
    if let Some(seen) = full {
        with(vault, |v| v.drop_unseen(vault_id, &seen))?;
    }
    // Recordings whose session log was deleted elsewhere.
    with(vault, |v| v.drop_unreferenced_blobs(vault_id))?;
    if access < Access::Write {
        return Ok(());
    }
    // Blobs before the items that refer to them.
    for (hash, kind) in with(vault, |v| v.pending_blobs(vault_id))? {
        let bytes = with(vault, |v| v.blob_bytes(vault_id, &hash))?;
        match remote.put_blob(vault_id, &hash, &kind, bytes).await {
            Ok(()) => {
                with(vault, |v| v.mark_blob(vault_id, &hash, Ok(())))?;
                report.blobs_uploaded += 1;
            }
            Err(RemoteError::Refused(refusal)) => {
                let reason = refusal.reason.clone();
                with(vault, |v| v.mark_blob(vault_id, &hash, Err(refusal)))?;
                if !report
                    .blob_errors
                    .iter()
                    .any(|(id, r)| id == vault_id && *r == reason)
                {
                    report.blob_errors.push((vault_id.into(), reason));
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    for hash in with(vault, |v| v.pending_blob_deletes(vault_id))? {
        match remote.delete_blob(vault_id, &hash).await {
            Ok(()) | Err(RemoteError::NotFound) => {
                with(vault, |v| v.blob_deleted(vault_id, &hash))?
            }
            Err(RemoteError::Refused(_)) => with(vault, |v| v.blob_deleted(vault_id, &hash))?,
            Err(e) => return Err(e.into()),
        }
    }
    // Whatever is still under an older key after pulling: re-seal it (finishing a rotation,
    // whoever started it).
    if vault_id != with(vault, |v| Ok(v.unlocked()?.vault_id.clone()))? {
        report.resealed += with(vault, |v| v.reseal_old_items(vault_id))?;
    }

    // Push; a conflict applies the server copy, and the conflict copy goes out next round.
    let mut rejected: HashSet<String> = HashSet::new();
    for _ in 0..4 {
        let batch = with(vault, |v| v.outgoing(vault_id, MAX_PUSH, &rejected))?;
        if batch.is_empty() {
            break;
        }
        let outcomes = remote.push(vault_id, batch.clone()).await?;
        with(vault, |v| {
            for outcome in outcomes {
                match outcome {
                    PushOutcome::Accepted { id, rev } => {
                        if let Some(sent) = batch.iter().find(|b| b.id == id) {
                            v.mark_pushed(vault_id, sent, rev)?;
                            report.pushed += 1;
                        }
                    }
                    PushOutcome::Conflict { current } => {
                        let (_, conflicts) =
                            v.apply_remote(vault_id, std::slice::from_ref(&current), None)?;
                        report.conflicts += conflicts;
                    }
                    // The vault has a newer key than this copy: re-seal and send it again.
                    PushOutcome::Rejected { id, code, .. }
                        if code == "stale_key" && v.reseal(vault_id, &id)? => {}
                    PushOutcome::Rejected { id, reason, .. } => {
                        report.rejected.push(format!("{id}: {reason}"));
                        rejected.insert(id);
                    }
                }
            }
            Ok(())
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicI64, Ordering};

    use super::*;
    use crate::{Host, HostAuth, Item, Snippet};

    const PW: &str = "correct horse battery";

    /// In-memory server with vault-sync/v1 push/pull semantics and a tiny page size.
    #[derive(Default)]
    struct Fake {
        items: Mutex<BTreeMap<String, RemoteItem>>,
        head: AtomicI64,
        /// Pretend the server lost everything after this revision.
        rolled_back_to: Mutex<Option<i64>>,
        blobs: Mutex<BTreeMap<String, Vec<u8>>>,
        /// Refuse blob uploads with this reason (no plan for them, say).
        refuse_blobs: Mutex<Option<crate::Refusal>>,
        /// Pull requests answered.
        pulls: AtomicI64,
        /// Drop the envelope a deletion carries, as servers from before signed deletions do.
        drops_deletion_envelopes: std::sync::atomic::AtomicBool,
    }

    impl Fake {
        fn pull_now(&self, since: i64) -> core::result::Result<RemotePage, RemoteError> {
            self.pulls.fetch_add(1, Ordering::SeqCst);
            let head = self
                .rolled_back_to
                .lock()
                .unwrap()
                .unwrap_or(self.head.load(Ordering::SeqCst));
            let mut all: Vec<RemoteItem> = self
                .items
                .lock()
                .unwrap()
                .values()
                .filter(|i| i.rev > since && i.rev <= head)
                .cloned()
                .collect();
            all.sort_by_key(|i| i.rev);
            let has_more = all.len() > 2;
            all.truncate(2);
            Ok(RemotePage {
                items: all,
                head_rev: head,
                has_more,
            })
        }

        fn push_now(&self, items: Vec<Outgoing>) -> Vec<PushOutcome> {
            let mut store = self.items.lock().unwrap();
            items
                .into_iter()
                .map(|o| match store.get(&o.id) {
                    Some(cur) if cur.rev != o.base_rev => PushOutcome::Conflict {
                        current: cur.clone(),
                    },
                    _ => {
                        let rev = self.head.fetch_add(1, Ordering::SeqCst) + 1;
                        let envelope =
                            if o.deleted && self.drops_deletion_envelopes.load(Ordering::SeqCst) {
                                None
                            } else {
                                o.envelope
                            };
                        store.insert(
                            o.id.clone(),
                            RemoteItem {
                                id: o.id.clone(),
                                rev,
                                deleted: o.deleted,
                                envelope,
                                author_id: None,
                            },
                        );
                        PushOutcome::Accepted { id: o.id, rev }
                    }
                })
                .collect()
        }

        /// The server's copy of item `id`.
        fn copy(&self, id: &str) -> RemoteItem {
            self.items.lock().unwrap()[id].clone()
        }

        /// Makes `copy` the newest revision of its item: a server serving what it kept, or a
        /// change another app pushed.
        fn serve(&self, mut copy: RemoteItem) {
            copy.rev = self.head.fetch_add(1, Ordering::SeqCst) + 1;
            self.items.lock().unwrap().insert(copy.id.clone(), copy);
        }
    }

    impl Remote for Fake {
        fn pull(
            &self,
            _: &str,
            since: i64,
        ) -> impl Future<Output = core::result::Result<RemotePage, RemoteError>> + Send {
            let r = self.pull_now(since);
            async move { r }
        }
        fn push(
            &self,
            _: &str,
            items: Vec<Outgoing>,
        ) -> impl Future<Output = core::result::Result<Vec<PushOutcome>, RemoteError>> + Send
        {
            let r = self.push_now(items);
            async move { Ok(r) }
        }
        fn put_blob(
            &self,
            _: &str,
            hash: &str,
            _: &str,
            bytes: Vec<u8>,
        ) -> impl Future<Output = core::result::Result<(), RemoteError>> + Send {
            let r = match self.refuse_blobs.lock().unwrap().clone() {
                Some(reason) => Err(RemoteError::Refused(reason)),
                None => {
                    assert_eq!(mg_vault::blob::hash(&bytes), hash);
                    self.blobs.lock().unwrap().insert(hash.into(), bytes);
                    Ok(())
                }
            };
            async move { r }
        }
        fn delete_blob(
            &self,
            _: &str,
            hash: &str,
        ) -> impl Future<Output = core::result::Result<(), RemoteError>> + Send {
            let r = match self.blobs.lock().unwrap().remove(hash) {
                Some(_) => Ok(()),
                None => Err(RemoteError::NotFound),
            };
            async move { r }
        }
    }

    fn fast(v: LocalVault) -> LocalVault {
        v.with_kdf_cost(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1)
    }

    /// A shared vault can't bring in a new item with the id of a live personal one (lookups go by
    /// id); over a tombstone it can (an item moved out of the personal vault), and the personal
    /// vault takes back an item still live in a shared one (moved back, before that vault syncs),
    /// which then still brings its own copy (pulled before the move back was pushed).
    #[test]
    fn a_shared_vault_cant_shadow_a_personal_item() {
        let mut v = fast(LocalVault::open_in_memory().unwrap());
        v.create(PW).unwrap();
        let key = VaultKey::generate().unwrap();
        v.conn
            .execute(
                "INSERT INTO vaults (id, key_id, wrapped_vault_key, created_at, personal, org_id, permission, name)
                 VALUES ('TEAM', ?1, x'02', 1, 0, 'ORG', 'write', 'Team')",
                [key.id().as_slice()],
            )
            .unwrap();
        v.keys.as_mut().unwrap().shared.insert(
            "TEAM".into(),
            crate::vault::Ring {
                current: *key.id(),
                keys: vec![key],
                access: Access::Write,
            },
        );
        let personal = v.unlocked().unwrap().vault_id.clone();
        let mine = v.upsert(None, host("mine")).unwrap().id;
        let remote = |v: &LocalVault, vault: &str, id: &str| {
            let keys = v.unlocked().unwrap();
            let plain = serde_json::to_vec(&host("from the server")).unwrap();
            let env = envelope::seal(
                keys.current(vault).unwrap(),
                &keys.account,
                &context(vault, id),
                &plain,
            )
            .unwrap();
            RemoteItem {
                id: id.to_owned(),
                rev: 1,
                deleted: false,
                envelope: Some(env),
                author_id: None,
            }
        };

        let clash = remote(&v, "TEAM", &mine);
        assert!(matches!(
            v.apply_remote("TEAM", std::slice::from_ref(&clash), None),
            Err(Error::Corrupt(_))
        ));
        v.delete(&mine).unwrap();
        v.apply_remote("TEAM", &[clash], None).unwrap();
        assert_eq!(v.item(&mine).unwrap().vault_id, "TEAM");

        let back = remote(&v, &personal, &mine);
        v.apply_remote(&personal, &[back], None).unwrap();
        let again = RemoteItem {
            rev: 2,
            ..remote(&v, "TEAM", &mine)
        };
        v.apply_remote("TEAM", &[again], None).unwrap();
    }

    /// Device A creates the vault; device B joins the same account.
    fn two_devices() -> (Mutex<LocalVault>, Mutex<LocalVault>) {
        let mut a = fast(LocalVault::open_in_memory().unwrap());
        a.create(PW).unwrap();
        let (export, rotated) = a.export_for_registration(PW).unwrap();
        assert!(
            rotated.is_none(),
            "new vaults already store a recovery proof"
        );
        let mut b = fast(LocalVault::open_in_memory().unwrap());
        b.adopt_account(
            PW,
            AccountImport {
                kdf: export.kdf,
                public: export.public,
                wrapped: export.wrapped,
                wrapped_rk: Some(export.wrapped_rk),
                vault: export.vault,
            },
        )
        .unwrap();
        (Mutex::new(a), Mutex::new(b))
    }

    fn host(label: &str) -> ItemData {
        ItemData::Host(Host {
            label: label.into(),
            hostname: format!("{label}.example.com"),
            port: 22,
            user: "root".into(),
            auth: HostAuth::system_agent(),
            jump_ref: None,
            vpn_ref: None,
            theme_ref: None,
            record_sessions: false,
            tags: vec![],
            notes: String::new(),
            group_ref: None,
            identity_ref: None,
            keep_session: false,
            forward_agent: false,
            login_command: None,
            jump_command: None,
            proxy_command: None,
            source: None,
        })
    }

    fn labels(v: &Mutex<LocalVault>) -> Vec<String> {
        let mut l: Vec<String> = v
            .lock()
            .unwrap()
            .items()
            .unwrap()
            .into_iter()
            .map(|Item { data, .. }| match data {
                ItemData::Host(h) => h.label,
                ItemData::Snippet(s) => s.name,
                other => format!("{other:?}"),
            })
            .collect();
        l.sort();
        l
    }

    async fn sync(v: &Mutex<LocalVault>, server: &Fake) -> SyncReport {
        sync_once(v, server).await.unwrap()
    }

    /// A vault the server lists at the revision this device has isn't pulled; one that moved on
    /// is.
    #[tokio::test]
    async fn up_to_date_vaults_arent_pulled() {
        let (a, b) = two_devices();
        let server = Fake::default();
        a.lock().unwrap().upsert(None, host("one")).unwrap();
        sync(&a, &server).await;
        sync(&b, &server).await;
        let id = b.lock().unwrap().sync_targets().unwrap()[0].0.clone();
        let heads = || HashMap::from([(id.clone(), server.head.load(Ordering::SeqCst))]);

        let before = server.pulls.load(Ordering::SeqCst);
        let r = sync_once_with(&b, &server, &heads()).await.unwrap();
        assert_eq!(server.pulls.load(Ordering::SeqCst), before, "nothing new");
        assert_eq!(r.pulled, 0);

        a.lock().unwrap().upsert(None, host("two")).unwrap();
        sync(&a, &server).await;
        let r = sync_once_with(&b, &server, &heads()).await.unwrap();
        assert_eq!(r.pulled, 1);
        assert_eq!(labels(&b), ["one", "two"]);
        // A local edit still goes out when there's nothing to pull.
        b.lock().unwrap().upsert(None, host("three")).unwrap();
        let r = sync_once_with(&b, &server, &heads()).await.unwrap();
        assert_eq!(r.pushed, 1);
    }

    /// A device that made a vault of its own joins an account: a wrong password changes nothing;
    /// the right one moves its items (and their files) into the account's vault, the device opens
    /// with the account's password from then on, and both devices end up with everything.
    #[tokio::test]
    async fn a_device_with_its_own_vault_joins_an_account() {
        let (desktop, _) = two_devices();
        let server = Fake::default();
        desktop
            .lock()
            .unwrap()
            .upsert(None, host("desktop"))
            .unwrap();
        sync(&desktop, &server).await;
        let (export, _) = desktop.lock().unwrap().export_for_registration(PW).unwrap();
        let import = || AccountImport {
            kdf: export.kdf.clone(),
            public: export.public,
            wrapped: export.wrapped.clone(),
            wrapped_rk: Some(export.wrapped_rk.clone()),
            vault: export.vault.clone(),
        };

        let mut phone = fast(LocalVault::open_in_memory().unwrap());
        phone.create("the phone's own password").unwrap();
        let own = phone.unlocked().unwrap().vault_id.clone();
        let h = phone.upsert(None, host("phone")).unwrap().id;
        let file = phone.attach(&own, Some(&h), "notes.txt", b"hello").unwrap();
        phone.enable_device_unlock().unwrap();

        assert!(matches!(
            phone.join_account("not the account's", import()),
            Err(Error::WrongPassword)
        ));
        assert_eq!(phone.item(&h).unwrap().vault_id, own, "nothing changed");

        assert_eq!(phone.join_account(PW, import()).unwrap(), 2);
        let account_vault = phone.unlocked().unwrap().vault_id.clone();
        assert_eq!(account_vault, export.vault.id);
        assert_eq!(
            phone.item(&h).unwrap().vault_id,
            account_vault,
            "same id, the account's vault"
        );
        let ItemData::Attachment(a) = phone.item(&file).unwrap().data else {
            unreachable!()
        };
        let plain = phone
            .open_blob(&account_vault, BlobKind::Attachment, &a.blob)
            .unwrap()
            .unwrap();
        assert_eq!(&plain[..], b"hello");
        assert_eq!(
            phone.device_unlock_id().unwrap(),
            None,
            "the keychain key opened the old keys"
        );
        phone.lock();
        assert!(phone.unlock("the phone's own password").is_err());
        phone.unlock(PW).unwrap();

        let phone = Mutex::new(phone);
        sync(&phone, &server).await;
        sync(&desktop, &server).await;
        for device in [&phone, &desktop] {
            let all = labels(device);
            assert!(
                ["desktop", "phone"]
                    .iter()
                    .all(|l| all.contains(&l.to_string())),
                "{all:?}"
            );
        }
    }

    fn log(title: &str, chunks: Vec<crate::LogChunk>) -> ItemData {
        ItemData::SessionLog(crate::SessionLog {
            host_ref: None,
            title: title.into(),
            address: "root@db1.example.com:22".into(),
            started_at: 1,
            ended_at: Some(2),
            cols: 80,
            rows: 24,
            chunks,
            output_bytes: 3,
            device: "laptop".into(),
        })
    }

    #[tokio::test]
    async fn session_log_blobs_upload_fetch_and_delete() {
        let (a, b) = two_devices();
        let server = Fake::default();
        let personal = a.lock().unwrap().unlocked().unwrap().vault_id.clone();

        // A records: the blob first (kept here), then the item that names it.
        let chunk = a
            .lock()
            .unwrap()
            .add_blob(
                &personal,
                mg_vault::BlobKind::SessionLog,
                b"[0.1,\"o\",\"$ \"]\n",
            )
            .unwrap();
        let item = a
            .lock()
            .unwrap()
            .upsert(
                None,
                log(
                    "db1",
                    vec![crate::LogChunk {
                        hash: chunk.hash.clone(),
                        size: chunk.size,
                    }],
                ),
            )
            .unwrap();
        assert_eq!(
            a.lock()
                .unwrap()
                .blob_state(&personal, &chunk.hash)
                .unwrap(),
            Some(crate::BlobState::Pending)
        );
        let r = sync(&a, &server).await;
        assert_eq!((r.blobs_uploaded, r.pushed), (1, 1));
        assert!(server.blobs.lock().unwrap().contains_key(&chunk.hash));
        assert_eq!(
            a.lock()
                .unwrap()
                .blob_state(&personal, &chunk.hash)
                .unwrap(),
            Some(crate::BlobState::Uploaded)
        );
        // Uploaded once: the next round sends nothing.
        assert_eq!(sync(&a, &server).await.blobs_uploaded, 0);

        // B gets the item, not the bytes; fetched, they open to what A recorded.
        sync(&b, &server).await;
        {
            let mut bv = b.lock().unwrap();
            assert!(
                bv.open_blob(&personal, mg_vault::BlobKind::SessionLog, &chunk.hash)
                    .unwrap()
                    .is_none()
            );
            let bytes = server.blobs.lock().unwrap()[&chunk.hash].clone();
            assert!(
                bv.store_blob(
                    &personal,
                    mg_vault::BlobKind::SessionLog,
                    &chunk.hash,
                    b"tampered"
                )
                .is_err()
            );
            bv.store_blob(
                &personal,
                mg_vault::BlobKind::SessionLog,
                &chunk.hash,
                &bytes,
            )
            .unwrap();
            assert_eq!(
                &bv.open_blob(&personal, mg_vault::BlobKind::SessionLog, &chunk.hash)
                    .unwrap()
                    .unwrap()[..],
                b"[0.1,\"o\",\"$ \"]\n"
            );
        }

        // A deletes the log: its recording goes from A, the server, then B.
        a.lock().unwrap().delete(&item.id).unwrap();
        assert!(
            a.lock()
                .unwrap()
                .blob_state(&personal, &chunk.hash)
                .unwrap()
                .is_none()
        );
        sync(&a, &server).await;
        assert!(server.blobs.lock().unwrap().is_empty());
        sync(&b, &server).await;
        assert!(
            b.lock()
                .unwrap()
                .blob_state(&personal, &chunk.hash)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn refused_blobs_are_reported_and_retried() {
        let (a, _) = two_devices();
        let server = Fake::default();
        let refusal = crate::Refusal {
            reason: "this needs the Business plan".into(),
            upgrade_url: Some("https://morphgate.example/team/1".into()),
        };
        *server.refuse_blobs.lock().unwrap() = Some(refusal.clone());
        let personal = a.lock().unwrap().unlocked().unwrap().vault_id.clone();
        let chunk = a
            .lock()
            .unwrap()
            .add_blob(&personal, mg_vault::BlobKind::SessionLog, b"x")
            .unwrap();
        a.lock()
            .unwrap()
            .upsert(
                None,
                log(
                    "db1",
                    vec![crate::LogChunk {
                        hash: chunk.hash.clone(),
                        size: chunk.size,
                    }],
                ),
            )
            .unwrap();
        // The refusal doesn't fail the round: the item still goes up.
        let r = sync(&a, &server).await;
        assert_eq!(r.pushed, 1);
        assert_eq!(
            r.blob_errors,
            [(personal.clone(), "this needs the Business plan".to_string())]
        );
        assert_eq!(
            a.lock()
                .unwrap()
                .blob_state(&personal, &chunk.hash)
                .unwrap(),
            Some(crate::BlobState::Failed(refusal))
        );
        // Refused stays refused until asked again (after an upgrade, say).
        assert_eq!(sync(&a, &server).await.blob_errors.len(), 0);
        *server.refuse_blobs.lock().unwrap() = None;
        assert_eq!(a.lock().unwrap().retry_failed_blobs().unwrap(), 1);
        assert_eq!(sync(&a, &server).await.blobs_uploaded, 1);
    }

    #[tokio::test]
    async fn attachments_sync_and_go_with_their_host() {
        let (a, b) = two_devices();
        let server = Fake::default();
        let (vault, host_id, att) = {
            let mut v = a.lock().unwrap();
            let vault = v.unlocked().unwrap().vault_id.clone();
            let host_id = v.upsert(None, host("db1")).unwrap().id;
            let att = v
                .attach(&vault, Some(&host_id), "runbook.md", b"# restart the db")
                .unwrap();
            (vault, host_id, att)
        };
        let r = sync(&a, &server).await;
        assert_eq!((r.pushed, r.blobs_uploaded), (2, 1));
        // The other device has the item; the file comes from the server when opened.
        sync(&b, &server).await;
        let item = b.lock().unwrap().item(&att).unwrap();
        let ItemData::Attachment(meta) = item.data else {
            panic!("not an attachment");
        };
        assert_eq!((meta.name.as_str(), meta.size), ("runbook.md", 16));
        assert_eq!(meta.host_ref.as_deref(), Some(host_id.as_str()));
        {
            let mut bv = b.lock().unwrap();
            let kind = mg_vault::BlobKind::Attachment;
            assert!(bv.open_blob(&vault, kind, &meta.blob).unwrap().is_none());
            let sealed = server.blobs.lock().unwrap()[&meta.blob].clone();
            bv.store_blob(&vault, kind, &meta.blob, &sealed).unwrap();
            let plain = bv.open_blob(&vault, kind, &meta.blob).unwrap().unwrap();
            assert_eq!(plain.as_slice(), b"# restart the db");
        }
        // Deleting the host deletes its attachment, here and (after sync) on the server.
        a.lock().unwrap().delete(&host_id).unwrap();
        assert!(a.lock().unwrap().item(&att).is_err());
        sync(&a, &server).await;
        assert!(!server.blobs.lock().unwrap().contains_key(&meta.blob));
        // Too large is refused before anything is stored.
        let big = vec![0u8; crate::MAX_ATTACHMENT_BYTES as usize + 1];
        let refused = a.lock().unwrap().attach(&vault, None, "big.bin", &big);
        assert!(refused.is_err());
    }

    #[tokio::test]
    async fn kinds_from_newer_apps_are_kept_but_not_listed() {
        let (a, b) = two_devices();
        let server = Fake::default();
        a.lock().unwrap().upsert(None, host("db1")).unwrap();
        // A newer app's item: a kind this version doesn't know.
        {
            let v = a.lock().unwrap();
            let keys = v.unlocked().unwrap();
            let vault = keys.vault_id.clone();
            let id = Ulid::generate().to_string();
            let env = mg_vault::envelope::seal(
                keys.current(&vault).unwrap(),
                &keys.account,
                &context(&vault, &id),
                br#"{"type":"future_thing","colour":"teal"}"#,
            )
            .unwrap();
            v.conn
                .execute(
                    "INSERT INTO items (id, vault_id, envelope, deleted, rev, dirty, updated_at)
                     VALUES (?1, ?2, ?3, 0, 0, 1, 1)",
                    params![id, vault, env],
                )
                .unwrap();
        }
        assert_eq!(labels(&a), ["db1"]);
        assert_eq!(sync(&a, &server).await.pushed, 2);
        // The other device takes it in without failing, and lists only what it knows.
        sync(&b, &server).await;
        assert_eq!(labels(&b), ["db1"]);
        assert_eq!(
            b.lock()
                .unwrap()
                .conn
                .query_row("SELECT COUNT(*) FROM items", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            2
        );
    }

    #[tokio::test]
    async fn items_flow_between_devices() {
        let (a, b) = two_devices();
        let server = Fake::default();
        for name in ["web", "db", "cache"] {
            a.lock().unwrap().upsert(None, host(name)).unwrap();
        }
        let r = sync(&a, &server).await;
        assert_eq!((r.pushed, r.pulled), (3, 0));
        let r = sync(&b, &server).await;
        assert_eq!(r.pulled, 3, "paginated pull (page size 2)");
        assert_eq!(labels(&b), ["cache", "db", "web"]);

        // Edit + delete on B travel back to A.
        let db_id = b
            .lock()
            .unwrap()
            .items()
            .unwrap()
            .into_iter()
            .find(|i| matches!(&i.data, ItemData::Host(h) if h.label == "db"))
            .unwrap()
            .id;
        let web_id = b
            .lock()
            .unwrap()
            .items()
            .unwrap()
            .into_iter()
            .find(|i| matches!(&i.data, ItemData::Host(h) if h.label == "web"))
            .unwrap()
            .id;
        b.lock()
            .unwrap()
            .upsert(Some(&db_id), host("db-primary"))
            .unwrap();
        b.lock().unwrap().delete(&web_id).unwrap();
        assert_eq!(sync(&b, &server).await.pushed, 2);
        let r = sync(&a, &server).await;
        assert_eq!((r.pulled, r.conflicts), (2, 0));
        assert_eq!(labels(&a), ["cache", "db-primary"]);

        // Nothing left to do: idempotent.
        assert_eq!(sync(&a, &server).await, SyncReport::default());
        assert_eq!(sync(&b, &server).await, SyncReport::default());
    }

    #[tokio::test]
    async fn concurrent_edits_keep_both_versions() {
        let (a, b) = two_devices();
        let server = Fake::default();
        let id = a.lock().unwrap().upsert(None, host("db")).unwrap().id;
        sync(&a, &server).await;
        sync(&b, &server).await;

        a.lock()
            .unwrap()
            .upsert(Some(&id), host("db-from-a"))
            .unwrap();
        b.lock()
            .unwrap()
            .upsert(Some(&id), host("db-from-b"))
            .unwrap();
        sync(&a, &server).await;
        let r = sync(&b, &server).await;
        assert_eq!(r.conflicts, 1);
        assert_eq!(labels(&b), ["db-from-a", "db-from-b (conflict)"]);
        sync(&a, &server).await;
        assert_eq!(labels(&a), labels(&b), "both devices converge");
    }

    /// Two devices refreshing the same cloud source: the hosts and snippets it made have the
    /// same ids on both, and copies that differ only in what the source decides make no
    /// "(conflict)" copy. A person's edit still does.
    #[tokio::test]
    async fn refreshes_on_two_devices_make_no_copies() {
        use crate::{CloudSource, HostSource, SnippetSource};
        let (a, b) = two_devices();
        let server = Fake::default();
        let source = CloudSource {
            label: "Ops".into(),
            provider: "feed".into(),
            url: Some("https://ops.example/feed".into()),
            token: Some("T".into()),
            ..CloudSource::default()
        };
        let sid = a
            .lock()
            .unwrap()
            .upsert(None, ItemData::CloudSource(source.clone()))
            .unwrap()
            .id;
        sync(&a, &server).await;
        sync(&b, &server).await;
        let vault = a.lock().unwrap().items().unwrap()[0].vault_id.clone();
        let kept = |hostname: &str, state: Option<&str>| {
            let ItemData::Host(mut h) = host("web") else {
                unreachable!()
            };
            h.hostname = hostname.into();
            h.tags = vec!["prod".into()];
            h.source = Some(Box::new(HostSource {
                source_ref: sid.clone(),
                external_id: "feed:web".into(),
                label: "web".into(),
                gone: false,
                no_sftp: false,
                no_forwarding: false,
                state: state.map(str::to_owned),
                reach: None,
                host_keys: vec![],
                tags: vec!["prod".into()],
            }));
            ItemData::Host(h)
        };
        let snippet = |body: &str| {
            ItemData::Snippet(Snippet {
                name: "Uptime".into(),
                body: body.into(),
                tags: vec![],
                source: Some(SnippetSource {
                    source_ref: sid.clone(),
                    external_id: "feed:up".into(),
                }),
            })
        };
        let refreshed = |at: i64| {
            ItemData::CloudSource(CloudSource {
                refreshed_at: at,
                ..source.clone()
            })
        };
        let host_id = crate::derived_id(&[&vault, &sid, "host", "feed:web"]);
        let snippet_id = crate::derived_id(&[&vault, &sid, "snippet", "feed:up"]);
        // Both make them, a moment apart: the feed moved the host and changed the snippet.
        for (v, hostname, body, at) in [
            (&a, "10.0.0.1", "uptime", 100),
            (&b, "10.0.0.2", "uptime -p", 101),
        ] {
            let mut v = v.lock().unwrap();
            v.insert_in(&vault, &host_id, kept(hostname, None)).unwrap();
            v.insert_in(&vault, &snippet_id, snippet(body)).unwrap();
            v.upsert(Some(&sid), refreshed(at)).unwrap();
        }
        sync(&a, &server).await;
        let r = sync(&b, &server).await;
        assert_eq!(r.conflicts, 0);
        sync(&a, &server).await;
        let count = |v: &Mutex<LocalVault>| v.lock().unwrap().items().unwrap().len();
        assert_eq!(
            (count(&a), count(&b)),
            (3, 3),
            "no copies: {:?}",
            labels(&b)
        );

        // A's person adds a note while B's refresh marks the host stopped: the note is kept.
        let ItemData::Host(mut noted) = kept("10.0.0.1", None) else {
            unreachable!()
        };
        noted.notes = "ask Ana first".into();
        a.lock()
            .unwrap()
            .upsert(Some(&host_id), ItemData::Host(noted))
            .unwrap();
        b.lock()
            .unwrap()
            .upsert(Some(&host_id), kept("10.0.0.1", Some("stopped")))
            .unwrap();
        sync(&b, &server).await;
        let r = sync(&a, &server).await;
        assert_eq!(r.conflicts, 1);
        assert!(
            labels(&a).contains(&"web (conflict)".to_owned()),
            "{:?}",
            labels(&a)
        );
    }

    #[tokio::test]
    async fn edit_beats_delete_as_a_copy_and_delete_loses_to_edit() {
        let (a, b) = two_devices();
        let server = Fake::default();
        let id = a.lock().unwrap().upsert(None, host("db")).unwrap().id;
        sync(&a, &server).await;
        sync(&b, &server).await;

        // A deletes, B edits: the delete reaches the server first; B's edit survives as a copy.
        a.lock().unwrap().delete(&id).unwrap();
        b.lock()
            .unwrap()
            .upsert(Some(&id), host("db-edited"))
            .unwrap();
        sync(&a, &server).await;
        sync(&b, &server).await;
        sync(&a, &server).await;
        assert_eq!(labels(&a), ["db-edited (conflict)"]);
        assert_eq!(labels(&b), labels(&a));

        // B edits first, A deleted offline: the edit on the server resurrects the item on A.
        let snip = ItemData::Snippet(Snippet {
            name: "s".into(),
            body: "uptime".into(),
            tags: vec![],
            source: None,
        });
        let sid = a.lock().unwrap().upsert(None, snip).unwrap().id;
        sync(&a, &server).await;
        sync(&b, &server).await;
        b.lock()
            .unwrap()
            .upsert(
                Some(&sid),
                ItemData::Snippet(Snippet {
                    name: "s2".into(),
                    body: "w".into(),
                    tags: vec![],
                    source: None,
                }),
            )
            .unwrap();
        a.lock().unwrap().delete(&sid).unwrap();
        sync(&b, &server).await;
        sync(&a, &server).await;
        assert!(labels(&a).contains(&"s2".to_owned()));
    }

    #[tokio::test]
    async fn never_synced_deletes_are_not_uploaded() {
        let (a, _) = two_devices();
        let server = Fake::default();
        let id = a.lock().unwrap().upsert(None, host("tmp")).unwrap().id;
        a.lock().unwrap().delete(&id).unwrap();
        assert_eq!(sync(&a, &server).await.pushed, 0);
        assert!(server.items.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn tampered_server_data_is_rejected_whole() {
        let (a, b) = two_devices();
        let server = Fake::default();
        a.lock().unwrap().upsert(None, host("one")).unwrap();
        a.lock().unwrap().upsert(None, host("two")).unwrap();
        sync(&a, &server).await;
        for item in server.items.lock().unwrap().values_mut().take(1) {
            item.envelope.as_mut().unwrap()[50] ^= 1;
        }
        let err = sync_once(&b, &server).await.unwrap_err();
        assert!(matches!(err, SyncError::Store(Error::Crypto(_))), "{err}");
        assert!(
            labels(&b).is_empty(),
            "nothing from the bad page was applied"
        );
    }

    #[tokio::test]
    async fn rollback_is_refused() {
        let (a, _) = two_devices();
        let server = Fake::default();
        a.lock().unwrap().upsert(None, host("one")).unwrap();
        a.lock().unwrap().upsert(None, host("two")).unwrap();
        sync(&a, &server).await;
        sync(&a, &server).await; // pulls its own items: cursor = 2
        *server.rolled_back_to.lock().unwrap() = Some(1);
        let err = sync_once(&a, &server).await.unwrap_err();
        assert!(
            matches!(
                err,
                SyncError::Rollback {
                    local: 2,
                    remote: 1
                }
            ),
            "{err}"
        );
    }

    #[tokio::test]
    async fn token_and_config_roundtrip_and_disable() {
        let (a, _) = two_devices();
        let cfg = SyncConfig {
            server_url: "https://sync.example.com".into(),
            email: "v@example.com".into(),
            account_id: "01ACC".into(),
            device_id: "01DEV".into(),
            device_public_key: [7; 32],
        };
        let mut v = a.lock().unwrap();
        assert!(v.sync_info().unwrap().is_none());
        v.enable_sync(&cfg).unwrap();
        v.set_sync_token("refresh-123").unwrap();
        assert_eq!(v.sync_token().unwrap().unwrap().as_str(), "refresh-123");
        v.record_sync(Some("boom")).unwrap();
        assert_eq!(
            v.sync_info().unwrap().unwrap().last_error.as_deref(),
            Some("boom")
        );
        v.lock();
        assert!(
            matches!(v.sync_token(), Err(Error::Locked)),
            "token needs the vault key"
        );
        v.unlock(PW).unwrap();
        v.disable_sync().unwrap();
        assert!(v.sync_info().unwrap().is_none());
    }

    #[test]
    fn vaults_without_a_stored_recovery_proof_rotate_on_registration() {
        let mut a = fast(LocalVault::open_in_memory().unwrap());
        let old = a.create(PW).unwrap();
        a.conn
            .execute("UPDATE account SET recovery_proof = NULL", [])
            .unwrap();
        let (export, rotated) = a.export_for_registration(PW).unwrap();
        let new = rotated.expect("rotated");
        assert_eq!(export.recovery_proof, new.proof().to_vec());
        a.lock();
        assert!(matches!(
            a.recover(&old.to_code(), "new password!"),
            Err(Error::WrongRecoveryKey)
        ));
        a.recover(&new.to_code(), "new password!").unwrap();
    }

    #[test]
    fn adopt_requires_the_right_password_and_a_fresh_device() {
        let mut a = fast(LocalVault::open_in_memory().unwrap());
        a.create(PW).unwrap();
        let (export, _) = a.export_for_registration(PW).unwrap();
        assert!(matches!(
            a.export_for_registration("nope nope"),
            Err(Error::WrongPassword)
        ));
        let import = || AccountImport {
            kdf: export.kdf.clone(),
            public: export.public,
            wrapped: export.wrapped.clone(),
            wrapped_rk: None,
            vault: export.vault.clone(),
        };
        let mut b = fast(LocalVault::open_in_memory().unwrap());
        assert!(matches!(
            b.adopt_account("wrong password", import()),
            Err(Error::WrongPassword)
        ));
        b.adopt_account(PW, import()).unwrap();
        assert!(matches!(
            b.adopt_account(PW, import()),
            Err(Error::AlreadyInitialized)
        ));
        b.lock();
        b.unlock(PW).unwrap();
    }

    /// What a device pushes for item `id` of its personal vault: `data` with `version`, or
    /// without one (`None`: an app before item history), or a deletion (`data: None`), unsigned
    /// without a version the way those apps send it.
    fn pushed_by(
        v: &Mutex<LocalVault>,
        id: &str,
        data: Option<&ItemData>,
        version: Option<i64>,
    ) -> RemoteItem {
        let v = v.lock().unwrap();
        let keys = v.unlocked().unwrap();
        let vault = keys.vault_id.clone();
        let plain = match (data, version) {
            (Some(data), Some(n)) => history::plaintext(data, n).unwrap().to_vec(),
            (Some(data), None) => serde_json::to_vec(data).unwrap(),
            (None, Some(n)) => history::deletion(n),
            (None, None) => Vec::new(),
        };
        let envelope = (!plain.is_empty()).then(|| {
            envelope::seal(
                keys.current(&vault).unwrap(),
                &keys.account,
                &context(&vault, id),
                &plain,
            )
            .unwrap()
        });
        RemoteItem {
            id: id.to_owned(),
            rev: 0,
            deleted: data.is_none(),
            envelope,
            author_id: None,
        }
    }

    /// The version in this device's copy of item `id` and the last one the server confirmed.
    fn versions(v: &Mutex<LocalVault>, id: &str) -> (Option<i64>, Option<i64>) {
        v.lock()
            .unwrap()
            .conn
            .query_row(
                "SELECT version, seen_version FROM items WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap()
    }

    fn refused_as_older(r: core::result::Result<SyncReport, SyncError>) -> bool {
        matches!(r, Err(SyncError::Store(Error::OlderItem { .. })))
    }

    /// Every write carries a version; a server serving a device an older copy than it has seen
    /// gets refused, and the device keeps what it has.
    #[tokio::test]
    async fn an_older_copy_of_an_item_is_refused() {
        let (a, b) = two_devices();
        let server = Fake::default();
        let id = a.lock().unwrap().upsert(None, host("db")).unwrap().id;
        sync(&a, &server).await;
        let first = server.copy(&id);
        a.lock().unwrap().upsert(Some(&id), host("db2")).unwrap();
        sync(&a, &server).await;
        sync(&b, &server).await;
        let (version, seen) = versions(&b, &id);
        assert!(version.unwrap() > 1_700_000_000_000);
        assert_eq!(version, seen);
        assert_eq!(versions(&a, &id), (version, version), "pushed is confirmed");

        let second = server.copy(&id);
        server.serve(first);
        assert!(refused_as_older(sync_once(&b, &server).await));
        assert!(
            refused_as_older(sync_once(&b, &server).await),
            "until it stops"
        );
        assert_eq!(labels(&b), ["db2"]);
        // The server serves the right copy again: sync goes on.
        server.serve(second);
        sync(&b, &server).await;
        sync(&a, &server).await;
        a.lock().unwrap().upsert(Some(&id), host("db3")).unwrap();
        sync(&a, &server).await;
        sync(&b, &server).await;
        assert_eq!(labels(&b), ["db3"]);
    }

    /// A deletion is signed, with a version after the item's: replaying the item's last copy
    /// doesn't bring it back, and a deletion the server makes up for a newer copy is refused too.
    #[tokio::test]
    async fn a_deleted_item_cant_be_brought_back() {
        let (a, b) = two_devices();
        let server = Fake::default();
        let id = a.lock().unwrap().upsert(None, host("db")).unwrap().id;
        sync(&a, &server).await;
        sync(&b, &server).await;
        let live = server.copy(&id);
        a.lock().unwrap().delete(&id).unwrap();
        sync(&a, &server).await;
        let gone = server.copy(&id);
        assert!(
            gone.deleted && gone.envelope.is_some(),
            "the deletion is signed"
        );
        sync(&b, &server).await;
        assert!(labels(&b).is_empty());
        assert!(versions(&b, &id).1.unwrap() > versions(&a, &id).1.unwrap() - 1);

        server.serve(live);
        assert!(refused_as_older(sync_once(&b, &server).await));
        assert!(labels(&b).is_empty());

        // The same item back (moved back, say), then the old deletion again.
        let back = pushed_by(
            &a,
            &id,
            Some(&host("db again")),
            Some(history::next(0) + 10),
        );
        server.serve(back);
        sync(&b, &server).await;
        assert_eq!(labels(&b), ["db again"]);
        server.serve(gone);
        assert!(refused_as_older(sync_once(&b, &server).await));
        assert_eq!(labels(&b), ["db again"]);
    }

    /// Apps before item history write items without a version and delete without signing:
    /// their changes still apply, and versions carry on after them.
    #[tokio::test]
    async fn changes_from_apps_before_item_history_still_sync() {
        let (a, b) = two_devices();
        let server = Fake::default();
        let id = a.lock().unwrap().upsert(None, host("db")).unwrap().id;
        sync(&a, &server).await;
        sync(&b, &server).await;

        server.serve(pushed_by(&a, &id, Some(&host("db (old app)")), None));
        sync(&b, &server).await;
        assert_eq!(labels(&b), ["db (old app)"]);
        assert_eq!(versions(&b, &id), (Some(0), Some(0)));

        // After it, a device that never saw the earlier versions may write a lower one (its
        // clock behind, say): it counts from there.
        server.serve(pushed_by(&a, &id, Some(&host("db (slow clock)")), Some(5)));
        sync(&b, &server).await;
        assert_eq!(labels(&b), ["db (slow clock)"]);
        server.serve(pushed_by(&a, &id, Some(&host("db (older)")), Some(4)));
        assert!(refused_as_older(sync_once(&b, &server).await));

        // B's next edit comes after all of it; A takes it.
        server.serve(pushed_by(&a, &id, Some(&host("db (slow clock)")), Some(5)));
        sync(&b, &server).await;
        b.lock()
            .unwrap()
            .upsert(Some(&id), host("db (new app)"))
            .unwrap();
        sync(&b, &server).await;
        sync(&a, &server).await;
        assert_eq!(labels(&a), ["db (new app)"]);

        server.serve(pushed_by(&a, &id, None, None));
        sync(&a, &server).await;
        assert!(labels(&a).is_empty(), "an unsigned deletion applies");
    }

    /// With strict item history, an item that has a version takes no unversioned change and no
    /// unsigned deletion; items that never had a version still do.
    #[tokio::test]
    async fn strict_history_refuses_unversioned_changes() {
        let (a, b) = two_devices();
        let server = Fake::default();
        b.lock().unwrap().set_strict_history(true);
        let id = a.lock().unwrap().upsert(None, host("db")).unwrap().id;
        sync(&a, &server).await;
        sync(&b, &server).await;
        let current = server.copy(&id);
        let unversioned = |r: core::result::Result<SyncReport, SyncError>| {
            matches!(r, Err(SyncError::Store(Error::UnversionedItem { .. })))
        };

        server.serve(pushed_by(&a, &id, Some(&host("db (old app)")), None));
        assert!(unversioned(sync_once(&b, &server).await));
        server.serve(pushed_by(&a, &id, None, None));
        assert!(unversioned(sync_once(&b, &server).await));
        // A deletion envelope that isn't one: a live copy, or another item's.
        let mut fake = current.clone();
        fake.deleted = true;
        server.serve(fake);
        assert!(unversioned(sync_once(&b, &server).await));
        assert_eq!(labels(&b), ["db"]);
        server.serve(current);
        sync(&b, &server).await;

        let old = Ulid::generate().to_string();
        server.serve(pushed_by(&a, &old, Some(&host("from an old app")), None));
        sync(&b, &server).await;
        assert_eq!(labels(&b), ["db", "from an old app"]);
        server.serve(pushed_by(&a, &old, None, None));
        sync(&b, &server).await;
        assert_eq!(labels(&b), ["db"]);
    }

    /// A copy stored before item history (no versions in its row) still counts with the version
    /// its envelope holds: the next write comes after it, and nothing older is taken.
    #[tokio::test]
    async fn copies_from_before_item_history_keep_their_version() {
        let (a, b) = two_devices();
        let server = Fake::default();
        let id = a.lock().unwrap().upsert(None, host("db")).unwrap().id;
        sync(&a, &server).await;
        let ahead = history::next(0) + 86_400_000;
        server.serve(pushed_by(
            &a,
            &id,
            Some(&host("db (clock ahead)")),
            Some(ahead),
        ));
        sync(&b, &server).await;
        b.lock()
            .unwrap()
            .conn
            .execute("UPDATE items SET version = NULL, seen_version = NULL", [])
            .unwrap();

        server.serve(pushed_by(
            &a,
            &id,
            Some(&host("db (older)")),
            Some(ahead - 1),
        ));
        assert!(refused_as_older(sync_once(&b, &server).await));

        server.serve(pushed_by(
            &a,
            &id,
            Some(&host("db (clock ahead)")),
            Some(ahead),
        ));
        sync(&b, &server).await;
        b.lock()
            .unwrap()
            .conn
            .execute("UPDATE items SET version = NULL, seen_version = NULL", [])
            .unwrap();
        b.lock()
            .unwrap()
            .upsert(Some(&id), host("db (edited)"))
            .unwrap();
        assert_eq!(versions(&b, &id).0, Some(ahead + 1));
    }

    /// Re-sealing under a vault's new key (finishing a rotation) is a write: a new version, the
    /// same content.
    #[test]
    fn resealing_gives_a_new_version() {
        let mut v = fast(LocalVault::open_in_memory().unwrap());
        v.create(PW).unwrap();
        let old = VaultKey::generate().unwrap();
        v.conn
            .execute(
                "INSERT INTO vaults (id, key_id, wrapped_vault_key, created_at, personal, org_id, permission, name)
                 VALUES ('TEAM', ?1, x'02', 1, 0, 'ORG', 'write', 'Team')",
                [old.id().as_slice()],
            )
            .unwrap();
        let ring = |keys: Vec<VaultKey>| crate::vault::Ring {
            current: *keys.last().unwrap().id(),
            keys,
            access: Access::Write,
        };
        let new = VaultKey::generate().unwrap();
        let (old_id, new_id) = (*old.id(), *new.id());
        v.keys
            .as_mut()
            .unwrap()
            .shared
            .insert("TEAM".into(), ring(vec![old]));
        let id = v.upsert_in("TEAM", None, host("db")).unwrap().id;
        let before: i64 = v
            .conn
            .query_row("SELECT version FROM items WHERE id = ?1", [&id], |r| {
                r.get(0)
            })
            .unwrap();
        v.keys
            .as_mut()
            .unwrap()
            .shared
            .get_mut("TEAM")
            .unwrap()
            .keys
            .push(new);
        v.keys
            .as_mut()
            .unwrap()
            .shared
            .get_mut("TEAM")
            .unwrap()
            .current = new_id;
        assert_ne!(old_id, new_id);

        assert_eq!(v.reseal_old_items("TEAM").unwrap(), 1);
        let (env, version): (Vec<u8>, i64) = v
            .conn
            .query_row(
                "SELECT envelope, version FROM items WHERE id = ?1",
                [&id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(envelope_key_id(&env).unwrap(), new_id);
        assert!(version > before);
        let keys = v.unlocked().unwrap();
        let copy =
            history::read(&id, &open_envelope(keys, "TEAM", &id, &env, None).unwrap()).unwrap();
        assert_eq!((copy.data, copy.version), (Some(host("db")), Some(version)));
    }

    /// A server from before signed deletions drops their envelope: deletions still sync.
    #[tokio::test]
    async fn deletions_sync_through_servers_that_drop_their_envelope() {
        let (a, b) = two_devices();
        let server = Fake::default();
        server
            .drops_deletion_envelopes
            .store(true, Ordering::SeqCst);
        let id = a.lock().unwrap().upsert(None, host("db")).unwrap().id;
        sync(&a, &server).await;
        sync(&b, &server).await;
        a.lock().unwrap().delete(&id).unwrap();
        sync(&a, &server).await;
        assert!(server.copy(&id).envelope.is_none());
        sync(&b, &server).await;
        assert!(labels(&b).is_empty());
    }
}
