//! Blobs on this device: session logs (and later attachments) sealed under a vault's key. They
//! are kept here first; sync uploads them before the items that refer to them, and fetches the
//! ones other devices recorded when they are opened.

use mg_vault::BlobKind;
use mg_vault::blob;
use rusqlite::{OptionalExtension, params};
use zeroize::Zeroizing;

use crate::vault::now;
use crate::{Access, Error, LocalVault, Result};

/// Where a blob stands with the sync server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlobState {
    /// Waiting for the next sync to upload it.
    Pending,
    Uploaded,
    /// The server refused it (no plan for team session logs, storage full, …).
    Failed(Refusal),
}

/// Why the sync server won't take an upload, for the user.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Refusal {
    pub reason: String,
    /// Where the plan that allows it is bought (`402 upgrade_required`'s `billing_url`).
    pub upgrade_url: Option<String>,
}

impl From<&str> for Refusal {
    fn from(reason: &str) -> Self {
        reason.to_owned().into()
    }
}

impl From<String> for Refusal {
    fn from(reason: String) -> Self {
        Refusal {
            reason,
            upgrade_url: None,
        }
    }
}

/// A blob sealed and kept on this device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobRef {
    pub hash: String,
    pub size: u64,
}

impl LocalVault {
    /// Seals `plaintext` as a blob of `vault` (under its current key) and keeps it for sync to
    /// upload.
    pub fn add_blob(&mut self, vault: &str, kind: BlobKind, plaintext: &[u8]) -> Result<BlobRef> {
        let keys = self.unlocked()?;
        if keys.access(vault)? < Access::Write {
            return Err(Error::ReadOnly);
        }
        let sealed = blob::seal(keys.current(vault)?, vault, kind, plaintext)?;
        let hash = blob::hash(&sealed);
        let size = sealed.len() as u64;
        self.conn.execute(
            "INSERT OR IGNORE INTO blobs (vault_id, hash, kind, data, state, created_at)
             VALUES (?1, ?2, ?3, ?4, 'pending', ?5)",
            params![vault, hash, kind.as_str(), sealed, now()],
        )?;
        Ok(BlobRef { hash, size })
    }

    /// A blob's plaintext; `None` when this device doesn't have its bytes yet (fetch them and
    /// [`store_blob`](Self::store_blob)).
    pub fn open_blob(
        &self,
        vault: &str,
        kind: BlobKind,
        hash: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let keys = self.unlocked()?;
        let data: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT data FROM blobs WHERE vault_id = ?1 AND hash = ?2",
                params![vault, hash],
                |r| r.get(0),
            )
            .optional()?;
        let Some(data) = data else {
            return Ok(None);
        };
        if blob::hash(&data) != hash {
            return Err(Error::Corrupt(format!(
                "blob {hash} does not match its name"
            )));
        }
        let vk = keys.key_for(vault, &blob::key_id(&data)?)?;
        Ok(Some(blob::open(vk, vault, kind, &data)?))
    }

    /// Keeps bytes fetched from the server, after checking them against their name.
    pub fn store_blob(
        &mut self,
        vault: &str,
        kind: BlobKind,
        hash: &str,
        bytes: &[u8],
    ) -> Result<()> {
        if blob::hash(bytes) != hash {
            return Err(Error::Corrupt(format!(
                "blob {hash} does not match its name"
            )));
        }
        self.conn.execute(
            "INSERT OR IGNORE INTO blobs (vault_id, hash, kind, data, state, created_at)
             VALUES (?1, ?2, ?3, ?4, 'uploaded', ?5)",
            params![vault, hash, kind.as_str(), bytes, now()],
        )?;
        Ok(())
    }

    /// Where a blob stands; `None` when this device doesn't have it.
    pub fn blob_state(&self, vault: &str, hash: &str) -> Result<Option<BlobState>> {
        let row: Option<(String, Option<String>, Option<String>)> = self
            .conn
            .query_row(
                "SELECT state, error, upgrade_url FROM blobs WHERE vault_id = ?1 AND hash = ?2",
                params![vault, hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        Ok(row.map(|(state, error, upgrade_url)| match state.as_str() {
            "uploaded" => BlobState::Uploaded,
            "failed" => BlobState::Failed(Refusal {
                reason: error.unwrap_or_default(),
                upgrade_url,
            }),
            _ => BlobState::Pending,
        }))
    }

    /// Forgets blobs here, and on the server at the next sync.
    pub(crate) fn forget_blobs(&mut self, vault: &str, hashes: &[&str]) -> Result<()> {
        for hash in hashes {
            let state: Option<String> = self
                .conn
                .query_row(
                    "DELETE FROM blobs WHERE vault_id = ?1 AND hash = ?2 RETURNING state",
                    params![vault, hash],
                    |r| r.get(0),
                )
                .optional()?;
            // A blob this device never had may still be on the server.
            if state.as_deref() != Some("pending") {
                self.conn.execute(
                    "INSERT OR IGNORE INTO blob_deletes (vault_id, hash) VALUES (?1, ?2)",
                    params![vault, hash],
                )?;
            }
        }
        Ok(())
    }

    /// Blobs to upload, as `(hash, kind)`.
    pub(crate) fn pending_blobs(&self, vault: &str) -> Result<Vec<(String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT hash, kind FROM blobs WHERE vault_id = ?1 AND state = 'pending' ORDER BY created_at",
        )?;
        let rows = stmt
            .query_map([vault], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    pub(crate) fn blob_bytes(&self, vault: &str, hash: &str) -> Result<Vec<u8>> {
        Ok(self.conn.query_row(
            "SELECT data FROM blobs WHERE vault_id = ?1 AND hash = ?2",
            params![vault, hash],
            |r| r.get(0),
        )?)
    }

    /// Records an upload: done, or refused for `Err(reason)`.
    pub(crate) fn mark_blob(
        &self,
        vault: &str,
        hash: &str,
        outcome: core::result::Result<(), Refusal>,
    ) -> Result<()> {
        let (state, refusal) = match outcome {
            Ok(()) => ("uploaded", Refusal::default()),
            Err(r) => ("failed", r),
        };
        self.conn.execute(
            "UPDATE blobs SET state = ?3, error = ?4, upgrade_url = ?5 WHERE vault_id = ?1 AND hash = ?2",
            params![
                vault,
                hash,
                state,
                (state == "failed").then_some(refusal.reason),
                refusal.upgrade_url
            ],
        )?;
        Ok(())
    }

    /// Refused blobs go back in the queue (say, after the plan changed).
    pub fn retry_failed_blobs(&self) -> Result<usize> {
        Ok(self.conn.execute(
            "UPDATE blobs SET state = 'pending', error = NULL, upgrade_url = NULL WHERE state = 'failed'",
            [],
        )?)
    }

    pub(crate) fn pending_blob_deletes(&self, vault: &str) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT hash FROM blob_deletes WHERE vault_id = ?1")?;
        let rows = stmt
            .query_map([vault], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    pub(crate) fn blob_deleted(&self, vault: &str, hash: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM blob_deletes WHERE vault_id = ?1 AND hash = ?2",
            params![vault, hash],
        )?;
        Ok(())
    }

    /// Drops uploaded blobs no item refers to anymore (their item was deleted elsewhere).
    pub(crate) fn drop_unreferenced_blobs(&mut self, vault: &str) -> Result<usize> {
        let referenced: std::collections::HashSet<String> = self
            .items()?
            .into_iter()
            .filter(|i| i.vault_id == vault)
            .flat_map(|i| {
                i.data
                    .blob_refs()
                    .into_iter()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .collect();
        let stored: Vec<String> = self
            .conn
            .prepare("SELECT hash FROM blobs WHERE vault_id = ?1 AND state = 'uploaded'")?
            .query_map([vault], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let mut n = 0;
        for hash in stored.iter().filter(|h| !referenced.contains(*h)) {
            n += self.conn.execute(
                "DELETE FROM blobs WHERE vault_id = ?1 AND hash = ?2",
                params![vault, hash],
            )?;
        }
        Ok(n)
    }
}
