use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use mg_vault::{
    AccountKeys, AuthKey, ItemContext, KdfParams, MasterKey, PublicKeys, RecoveryKey, VaultKey,
    envelope,
};
use rusqlite::{Connection, OptionalExtension, params};
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::model::SCHEMA_VERSION;
use crate::{Error, ForwardRule, Host, HostAuth, Item, ItemData, Result, schema};

pub const MIN_PASSWORD_CHARS: usize = 10;
/// Longest allowed chain of jump hosts in front of a target.
pub const MAX_JUMPS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Uninitialized,
    Locked,
    Unlocked,
}

/// What this account may do in a vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    Read,
    Write,
    Manage,
}

impl Access {
    pub fn as_str(self) -> &'static str {
        match self {
            Access::Read => "read",
            Access::Write => "write",
            Access::Manage => "manage",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "manage" => Access::Manage,
            "write" => Access::Write,
            _ => Access::Read,
        }
    }
}

/// A shared vault, as this device can open it: every key generation sealed to this account.
pub(crate) struct Ring {
    pub(crate) current: [u8; 16],
    pub(crate) keys: Vec<VaultKey>,
    pub(crate) access: Access,
}

/// A vault on this device.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultInfo {
    pub id: String,
    /// The vault's name; `None` for the personal vault.
    pub name: Option<String>,
    pub org_id: Option<String>,
    pub personal: bool,
    pub access: Access,
    /// Someone lost access and the key hasn't been rotated yet.
    pub rotation_due: bool,
    pub items: usize,
    /// The organization's member key directory (members' SSH public keys, every member can add
    /// theirs).
    pub directory: bool,
}

pub(crate) struct Unlocked {
    pub(crate) account: AccountKeys,
    pub(crate) sign_pub: [u8; 32],
    /// The personal vault (and its single key).
    pub(crate) vault_id: String,
    pub(crate) vault_key: VaultKey,
    /// Shared vaults this account has keys for.
    pub(crate) shared: HashMap<String, Ring>,
    /// Signing keys of other accounts this device verified (item authors).
    pub(crate) pins: HashMap<String, [u8; 32]>,
    /// This account's id on the sync server, once synced.
    pub(crate) account_id: Option<String>,
}

impl Unlocked {
    /// The key generation `key_id` of a vault.
    pub(crate) fn key_for(&self, vault: &str, key_id: &[u8]) -> Result<&VaultKey> {
        if vault == self.vault_id {
            return if self.vault_key.id()[..] == *key_id {
                Ok(&self.vault_key)
            } else {
                Err(Error::Crypto(mg_vault::Error::KeyIdMismatch))
            };
        }
        let ring = self.shared.get(vault).ok_or(Error::UnknownVault)?;
        ring.keys
            .iter()
            .find(|k| k.id()[..] == *key_id)
            .ok_or(Error::Crypto(mg_vault::Error::KeyIdMismatch))
    }

    /// The key new envelopes in a vault are sealed with.
    pub(crate) fn current(&self, vault: &str) -> Result<&VaultKey> {
        if vault == self.vault_id {
            return Ok(&self.vault_key);
        }
        let ring = self.shared.get(vault).ok_or(Error::UnknownVault)?;
        self.key_for(vault, &ring.current)
    }

    pub(crate) fn access(&self, vault: &str) -> Result<Access> {
        if vault == self.vault_id {
            return Ok(Access::Manage);
        }
        Ok(self.shared.get(vault).ok_or(Error::UnknownVault)?.access)
    }

    /// The signing key an item by `author` must verify with (`None` = this account). Only this
    /// account writes in its personal vault, whatever author the server names there.
    pub(crate) fn author_key(
        &self,
        vault: &str,
        item: &str,
        author: Option<&str>,
    ) -> Result<[u8; 32]> {
        if vault == self.vault_id {
            return Ok(self.sign_pub);
        }
        match author {
            None => Ok(self.sign_pub),
            Some(a) if Some(a) == self.account_id.as_deref() => Ok(self.sign_pub),
            Some(a) => self
                .pins
                .get(a)
                .copied()
                .ok_or_else(|| Error::UnverifiedAuthor {
                    item: item.to_owned(),
                    author: a.to_owned(),
                }),
        }
    }
}

pub(crate) struct AccountRow {
    pub(crate) kdf: KdfParams,
    pub(crate) public: PublicKeys,
    pub(crate) wrapped: Vec<u8>,
    pub(crate) wrapped_rk: Vec<u8>,
}

/// A master password's material, derived (Argon2id) but not stored yet: a synced vault sends it to
/// the server first and keeps it on the device only once the server took it.
pub struct NewCredentials {
    account: AccountKeys,
    pub kdf: KdfParams,
    /// Proves the new password to the sync server.
    pub auth_key: AuthKey,
    /// The account private keys wrapped under the new password.
    pub wrapped: Vec<u8>,
    /// A replacement recovery key and the private keys wrapped under it, when one is being made.
    pub new_recovery: Option<(RecoveryKey, Vec<u8>)>,
}

/// The on-device vault. Locked until [`unlock`](Self::unlock); while locked only ciphertext is held.
pub struct LocalVault {
    pub(crate) conn: Connection,
    pub(crate) keys: Option<Unlocked>,
    kdf_cost: Option<(u32, u32, u32)>,
}

impl LocalVault {
    /// Opens (creating if needed) the vault database at `path`, readable by the current user only.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        #[cfg(unix)]
        if !path.exists() {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
        }
        Self::init(Connection::open(path)?)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(mut conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "secure_delete", "ON")?;
        schema::migrate(&mut conn)?;
        Ok(Self {
            conn,
            keys: None,
            kdf_cost: None,
        })
    }

    /// Argon2id cost (`m_kib`, `t`, `p`) for passwords set from now on. The `mg-vault` floors still
    /// apply. Defaults to [`KdfParams::recommended`].
    pub fn with_kdf_cost(mut self, m_kib: u32, t: u32, p: u32) -> Self {
        self.kdf_cost = Some((m_kib, t, p));
        self
    }

    pub fn status(&self) -> Result<Status> {
        Ok(if self.keys.is_some() {
            Status::Unlocked
        } else if self.account_row()?.is_some() {
            Status::Locked
        } else {
            Status::Uninitialized
        })
    }

    /// First-run setup. Returns the recovery key, which must be shown to the user exactly once.
    pub fn create(&mut self, password: &str) -> Result<RecoveryKey> {
        if self.account_row()?.is_some() {
            return Err(Error::AlreadyInitialized);
        }
        check_password(password)?;
        let kdf = self.new_kdf()?;
        let mk = MasterKey::derive(password.as_bytes(), &kdf)?;
        let account = AccountKeys::generate()?;
        let rk = RecoveryKey::generate()?;
        let public = account.public();
        let vault_id = Ulid::generate().to_string();
        let vault_key = VaultKey::generate()?;
        let now = now();

        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO account (id, kdf_m_kib, kdf_t, kdf_p, kdf_salt, enc_public_key, sign_public_key,
                                  wrapped_private_keys, wrapped_private_keys_rk, recovery_proof, created_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                kdf.m_kib,
                kdf.t,
                kdf.p,
                kdf.salt,
                public.enc.as_slice(),
                public.sign.as_slice(),
                account.wrap(&mk)?,
                account.wrap_with_recovery(&rk)?,
                rk.proof().as_slice(),
                now
            ],
        )?;
        tx.execute(
            "INSERT INTO vaults (id, key_id, wrapped_vault_key, created_at, personal) VALUES (?1, ?2, ?3, ?4, 1)",
            params![vault_id, vault_key.id().as_slice(), vault_key.seal_to(&public.enc)?, now],
        )?;
        tx.commit()?;

        self.keys = Some(Unlocked {
            account,
            sign_pub: public.sign,
            vault_id,
            vault_key,
            shared: HashMap::new(),
            pins: HashMap::new(),
            account_id: None,
        });
        Ok(rk)
    }

    pub fn unlock(&mut self, password: &str) -> Result<()> {
        let row = self.account_row()?.ok_or(Error::NotInitialized)?;
        let account = unwrap_with_password(&row, password)?;
        self.finish_unlock(account, &row)
    }

    /// Forgets every key; only ciphertext remains in memory.
    pub fn lock(&mut self) {
        self.keys = None;
    }

    /// Forgets everything this device keeps: every table emptied (the account, vaults, items,
    /// keys, settings, pinned host keys, sync state), locked. The device is as on first run, and
    /// the file keeps its schema. For a device its sync account signed out, or one its user
    /// disconnects and clears; the OS keychain entry is the caller's to remove.
    pub fn erase(&mut self) -> Result<()> {
        self.keys = None;
        let tables: Vec<String> = self
            .conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            )?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let tx = self.conn.transaction()?;
        for t in &tables {
            tx.execute(&format!("DELETE FROM \"{t}\""), [])?;
        }
        tx.commit()?;
        // Gone from the file too, not only unlinked from the tables.
        self.conn.execute_batch("VACUUM")?;
        Ok(())
    }

    /// Checks the master password without changing anything (Argon2id: slow by design).
    pub fn verify_password(&self, password: &str) -> Result<()> {
        let row = self.account_row()?.ok_or(Error::NotInitialized)?;
        unwrap_with_password(&row, password).map(drop)
    }

    /// Checks the master password and returns its `AuthKey`, which the sync server wants as
    /// proof before account changes. Changes nothing.
    pub fn auth_key(&self, password: &str) -> Result<AuthKey> {
        let row = self.account_row()?.ok_or(Error::NotInitialized)?;
        let mk = MasterKey::derive(password.as_bytes(), &row.kdf)?;
        AccountKeys::unwrap(&mk, &row.wrapped).map_err(wrong_password)?;
        Ok(mk.auth_key())
    }

    /// Lost password: unwrap the account keys with the recovery code and set a new password
    /// (this device only; a synced vault goes through `account::recover`).
    pub fn recover(&mut self, recovery_code: &str, new_password: &str) -> Result<()> {
        let creds = self.prepare_recovery(recovery_code, new_password)?;
        self.apply_credentials(creds).map(drop)
    }

    /// This device only; a synced vault goes through `account::change_password`.
    pub fn change_password(&mut self, current: &str, new_password: &str) -> Result<()> {
        let (_, creds) = self.prepare_password_change(current, new_password)?;
        self.apply_credentials(creds).map(drop)
    }

    /// Checks `current` and derives the material for `new_password`. Returns the current
    /// password's `AuthKey` too, which the sync server wants as proof. Changes nothing.
    pub fn prepare_password_change(
        &self,
        current: &str,
        new_password: &str,
    ) -> Result<(AuthKey, NewCredentials)> {
        check_password(new_password)?;
        let row = self.account_row()?.ok_or(Error::NotInitialized)?;
        let mk = MasterKey::derive(current.as_bytes(), &row.kdf)?;
        let account = AccountKeys::unwrap(&mk, &row.wrapped).map_err(wrong_password)?;
        Ok((mk.auth_key(), self.credentials_for(account, new_password)?))
    }

    /// Unwraps the account keys with the recovery code and derives the material for
    /// `new_password`. Changes nothing.
    pub fn prepare_recovery(
        &self,
        recovery_code: &str,
        new_password: &str,
    ) -> Result<NewCredentials> {
        let row = self.account_row()?.ok_or(Error::NotInitialized)?;
        self.prepare_recovery_from(recovery_code, &row.wrapped_rk, new_password)
    }

    /// Like [`prepare_recovery`](Self::prepare_recovery), with the recovery-wrapped keys from the
    /// sync server (it may hold a newer recovery key than this device, or this device may have
    /// no vault yet). On a device with a vault the keys must be its own.
    pub fn prepare_recovery_from(
        &self,
        recovery_code: &str,
        wrapped_rk: &[u8],
        new_password: &str,
    ) -> Result<NewCredentials> {
        let rk =
            RecoveryKey::from_code(recovery_code).map_err(|e| Error::Invalid(e.to_string()))?;
        check_password(new_password)?;
        let account = AccountKeys::unwrap_with_recovery(&rk, wrapped_rk).map_err(|e| match e {
            mg_vault::Error::Decrypt => Error::WrongRecoveryKey,
            other => other.into(),
        })?;
        if let Some(row) = self.account_row()?
            && account.public() != row.public
        {
            return Err(Error::WrongRecoveryKey);
        }
        self.credentials_for(account, new_password)
    }

    /// Same password, new recovery key (the old one stops working). Returns the password's
    /// `AuthKey` for the sync server. Changes nothing.
    pub fn prepare_new_recovery_key(&self, password: &str) -> Result<(AuthKey, NewCredentials)> {
        let row = self.account_row()?.ok_or(Error::NotInitialized)?;
        let mk = MasterKey::derive(password.as_bytes(), &row.kdf)?;
        let account = AccountKeys::unwrap(&mk, &row.wrapped).map_err(wrong_password)?;
        let rk = RecoveryKey::generate()?;
        let wrapped_rk = account.wrap_with_recovery(&rk)?;
        Ok((
            mk.auth_key(),
            NewCredentials {
                account,
                kdf: row.kdf,
                auth_key: mk.auth_key(),
                wrapped: row.wrapped,
                new_recovery: Some((rk, wrapped_rk)),
            },
        ))
    }

    fn credentials_for(&self, account: AccountKeys, password: &str) -> Result<NewCredentials> {
        let kdf = self.new_kdf()?;
        let mk = MasterKey::derive(password.as_bytes(), &kdf)?;
        Ok(NewCredentials {
            wrapped: account.wrap(&mk)?,
            auth_key: mk.auth_key(),
            kdf,
            account,
            new_recovery: None,
        })
    }

    /// Stores prepared credentials and unlocks with them. Returns the new recovery key, if the
    /// credentials made one (show it once).
    pub fn apply_credentials(&mut self, c: NewCredentials) -> Result<Option<RecoveryKey>> {
        let row = self.account_row()?.ok_or(Error::NotInitialized)?;
        if c.account.public() != row.public {
            return Err(Error::Corrupt(
                "the new credentials are for different account keys".into(),
            ));
        }
        let tx = self.conn.transaction()?;
        tx.execute(
            "UPDATE account SET kdf_m_kib = ?1, kdf_t = ?2, kdf_p = ?3, kdf_salt = ?4, wrapped_private_keys = ?5
             WHERE id = 1",
            params![c.kdf.m_kib, c.kdf.t, c.kdf.p, c.kdf.salt, c.wrapped],
        )?;
        let rk = match c.new_recovery {
            Some((rk, wrapped_rk)) => {
                tx.execute(
                    "UPDATE account SET wrapped_private_keys_rk = ?1, recovery_proof = ?2 WHERE id = 1",
                    params![wrapped_rk, rk.proof().as_slice()],
                )?;
                Some(rk)
            }
            None => None,
        };
        tx.commit()?;
        let row = self.account_row()?.ok_or(Error::NotInitialized)?;
        self.finish_unlock(c.account, &row)?;
        Ok(rk)
    }

    /// Keeps the sync server's recovery material (a recovery key made on another device).
    pub fn store_recovery(&mut self, wrapped_rk: &[u8], proof: Option<&[u8]>) -> Result<()> {
        self.conn.execute(
            "UPDATE account SET wrapped_private_keys_rk = ?1, recovery_proof = ?2 WHERE id = 1",
            params![wrapped_rk, proof],
        )?;
        Ok(())
    }

    /// The account password changed on another device: take the server's wrapping of this
    /// vault's own account keys, so the vault unlocks with the new password from now on.
    /// `wrapped_rk` is the server's recovery material, if it changed too.
    pub fn adopt_credentials(
        &mut self,
        mk: &MasterKey,
        kdf: &KdfParams,
        wrapped: &[u8],
        wrapped_rk: Option<&[u8]>,
    ) -> Result<()> {
        let row = self.account_row()?.ok_or(Error::NotInitialized)?;
        let account = AccountKeys::unwrap(mk, wrapped).map_err(wrong_password)?;
        if account.public() != row.public {
            return Err(Error::Corrupt(
                "the sync server's account keys are not this vault's".into(),
            ));
        }
        let tx = self.conn.transaction()?;
        tx.execute(
            "UPDATE account SET kdf_m_kib = ?1, kdf_t = ?2, kdf_p = ?3, kdf_salt = ?4, wrapped_private_keys = ?5
             WHERE id = 1",
            params![kdf.m_kib, kdf.t, kdf.p, kdf.salt, wrapped],
        )?;
        if let Some(wrapped_rk) = wrapped_rk.filter(|w| *w != row.wrapped_rk.as_slice()) {
            // A recovery key made elsewhere: its proof isn't known here.
            tx.execute(
                "UPDATE account SET wrapped_private_keys_rk = ?1, recovery_proof = NULL WHERE id = 1",
                [wrapped_rk],
            )?;
        }
        tx.commit()?;
        let row = self.account_row()?.ok_or(Error::NotInitialized)?;
        self.finish_unlock(account, &row)
    }

    /// All live items in every vault, decrypted and signature-checked.
    pub fn items(&self) -> Result<Vec<Item>> {
        let keys = self.unlocked()?;
        let mut stmt = self.conn.prepare(
            "SELECT vault_id, id, envelope, updated_at, author_id FROM items WHERE deleted = 0 ORDER BY id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, Option<String>>(4)?,
            ))
        })?;
        rows.filter_map(|row| {
            let item = (|| {
                let (vault_id, id, env, updated_at, author) = row?;
                let data = decrypt(keys, &vault_id, &id, &env, author.as_deref())?;
                Ok(Item {
                    id,
                    vault_id,
                    updated_at,
                    data,
                })
            })();
            // Kinds a newer app wrote stay stored and synced, but out of the list.
            match item {
                Ok(Item {
                    data: ItemData::Unknown,
                    ..
                }) => None,
                other => Some(other),
            }
        })
        .collect()
    }

    pub fn item(&self, id: &str) -> Result<Item> {
        let keys = self.unlocked()?;
        let row: Option<(String, Vec<u8>, i64, Option<String>)> = self
            .conn
            .query_row(
                "SELECT vault_id, envelope, updated_at, author_id FROM items WHERE id = ?1 AND deleted = 0",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let (vault_id, env, updated_at, author) =
            row.ok_or_else(|| Error::NotFound(id.to_owned()))?;
        let data = decrypt(keys, &vault_id, id, &env, author.as_deref())?;
        Ok(Item {
            id: id.to_owned(),
            vault_id,
            updated_at,
            data,
        })
    }

    /// The account's public keys (readable while locked).
    pub fn public_keys(&self) -> Result<PublicKeys> {
        Ok(self.account_row()?.ok_or(Error::NotInitialized)?.public)
    }

    /// The vaults on this device: the personal one first, then shared ones by name.
    pub fn vaults(&self) -> Result<Vec<VaultInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT v.id, v.name, v.org_id, v.personal, v.permission, v.rotation_due,
                    (SELECT COUNT(*) FROM items i WHERE i.vault_id = v.id AND i.deleted = 0),
                    v.directory
             FROM vaults v ORDER BY v.personal DESC, v.directory, v.name, v.id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(VaultInfo {
                id: r.get(0)?,
                name: r.get(1)?,
                org_id: r.get(2)?,
                personal: r.get(3)?,
                access: Access::parse(&r.get::<_, String>(4)?),
                rotation_due: r.get(5)?,
                items: r.get::<_, i64>(6)? as usize,
                directory: r.get(7)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Creates an item (`id = None`, in the personal vault) or replaces an existing one of the
    /// same type (in its own vault).
    pub fn upsert(&mut self, id: Option<&str>, data: ItemData) -> Result<Item> {
        let vault = match id {
            Some(id) => self.item(id)?.vault_id,
            None => self.unlocked()?.vault_id.clone(),
        };
        self.upsert_in(&vault, id, data)
    }

    /// Like [`upsert`](Self::upsert), creating new items in `vault_id`.
    pub fn upsert_in(&mut self, vault_id: &str, id: Option<&str>, data: ItemData) -> Result<Item> {
        if self.unlocked()?.access(vault_id)? < Access::Write {
            return Err(Error::ReadOnly);
        }
        if data == ItemData::Unknown {
            return Err(Error::Invalid(
                "this app can't edit that kind of item".into(),
            ));
        }
        let id = match id {
            Some(id) => {
                let existing = self.item(id)?;
                if existing.vault_id != vault_id {
                    return Err(Error::Invalid(
                        "to put an item in another vault, copy or move it".into(),
                    ));
                }
                if existing.data.kind() != data.kind() {
                    return Err(Error::TypeMismatch {
                        id: id.to_owned(),
                        existing: existing.data.kind(),
                        requested: data.kind(),
                    });
                }
                id.to_owned()
            }
            None => Ulid::generate().to_string(),
        };
        let now = self.put(vault_id, &id, &data)?;
        Ok(Item {
            id,
            vault_id: vault_id.to_owned(),
            updated_at: now,
            data,
        })
    }

    /// Checks `data` as an item `id` of `vault`, seals it with the vault's current key and stores
    /// it for the next sync (over a tombstone of the same id, too). Returns the time stamped.
    pub(crate) fn put(&mut self, vault_id: &str, id: &str, data: &ItemData) -> Result<i64> {
        self.validate(vault_id, Some(id), data)?;
        self.write(vault_id, id, data)
    }

    /// [`put`](Self::put) without the checks, for writes that are checked together afterwards
    /// (a move, whose items may refer to each other in a circle).
    pub(crate) fn write(&mut self, vault_id: &str, id: &str, data: &ItemData) -> Result<i64> {
        let keys = self.unlocked()?;
        let plain =
            Zeroizing::new(serde_json::to_vec(data).map_err(|e| Error::Invalid(e.to_string()))?);
        let env = envelope::seal(
            keys.current(vault_id)?,
            &keys.account,
            &context(vault_id, id),
            &plain,
        )?;
        let now = now();
        self.conn.execute(
            "INSERT INTO items (id, vault_id, envelope, deleted, dirty, updated_at, author_id) VALUES (?1, ?2, ?3, 0, 1, ?4, NULL)
             ON CONFLICT (vault_id, id) DO UPDATE SET envelope = excluded.envelope, deleted = 0, dirty = 1,
                                                      updated_at = excluded.updated_at, author_id = NULL",
            params![id, vault_id, env, now],
        )?;
        Ok(now)
    }

    /// Replaces the item with a tombstone so the deletion can sync.
    pub fn delete(&mut self, id: &str) -> Result<()> {
        let item = self.item(id)?;
        if self.unlocked()?.access(&item.vault_id)? < Access::Write {
            return Err(Error::ReadOnly);
        }
        let users: Vec<String> = self
            .items()?
            .into_iter()
            .filter(|i| i.vault_id == item.vault_id)
            .filter_map(|i| match i.data {
                ItemData::Host(h)
                    if h.jump_ref.as_deref() == Some(id)
                        || h.vpn_ref.as_deref() == Some(id)
                        || h.theme_ref.as_deref() == Some(id)
                        || matches!(&h.auth, HostAuth::Key { key_ref } if key_ref == id) =>
                {
                    Some(h.label)
                }
                ItemData::Host(h) if h.identity_ref.as_deref() == Some(id) => Some(h.label),
                ItemData::Host(h) if h.source.as_ref().is_some_and(|s| s.source_ref == id) => {
                    Some(h.label)
                }
                ItemData::CloudSource(c)
                    if c.key_ref.as_deref() == Some(id) || c.jump_ref.as_deref() == Some(id) =>
                {
                    Some(format!("cloud source {}", c.label))
                }
                ItemData::PortForward(f) if f.host_ref == id => Some(format!("tunnel {}", f.label)),
                ItemData::Identity(i)
                    if matches!(&i.auth, HostAuth::Key { key_ref } if key_ref == id) =>
                {
                    Some(format!("identity {}", i.label))
                }
                ItemData::HostGroup(g)
                    if [&g.identity_ref, &g.jump_ref, &g.vpn_ref, &g.theme_ref]
                        .iter()
                        .any(|r| r.as_deref() == Some(id)) =>
                {
                    Some(format!("group {}", g.name))
                }
                _ => None,
            })
            .collect();
        if !users.is_empty() {
            let what = match &item.data {
                ItemData::SshKey(k) => format!("key \"{}\"", k.label),
                ItemData::Host(h) => format!("host \"{}\" (as jump host)", h.label),
                ItemData::Snippet(s) => format!("snippet \"{}\"", s.name),
                ItemData::PortForward(f) => format!("tunnel \"{}\"", f.label),
                ItemData::Vpn(v) => format!("VPN \"{}\"", v.label),
                ItemData::MemberKey(k) => format!("member key \"{}\"", k.label),
                ItemData::TerminalTheme(t) => format!("terminal theme \"{}\"", t.name),
                ItemData::SessionLog(l) => format!("session log \"{}\"", l.title),
                ItemData::Attachment(a) => format!("attachment \"{}\"", a.name),
                ItemData::Identity(i) => format!("identity \"{}\"", i.label),
                ItemData::HostGroup(g) => format!("group \"{}\"", g.name),
                ItemData::CloudSource(c) => format!("cloud source \"{}\"", c.label),
                ItemData::HostCa(c) => format!("host CA \"{}\"", c.label),
                ItemData::Unknown => "item".into(),
            };
            return Err(Error::Invalid(format!(
                "{what} is still used by: {}",
                users.join(", ")
            )));
        }
        self.conn.execute(
            "UPDATE items SET envelope = NULL, deleted = 1, dirty = 1, updated_at = ?3
             WHERE vault_id = ?1 AND id = ?2",
            params![item.vault_id, id, now()],
        )?;
        // A session log's recording, or an attachment's file, goes with it.
        let blobs = item.data.blob_refs();
        if !blobs.is_empty() {
            self.forget_blobs(&item.vault_id, &blobs)?;
        }
        // A group's hosts stay, without it, and connect as before: what they took from the
        // group becomes their own.
        if let ItemData::HostGroup(group) = &item.data {
            let grouped: Vec<Item> = self
                .items()?
                .into_iter()
                .filter(|i| {
                    i.vault_id == item.vault_id
                        && matches!(&i.data, ItemData::Host(h) if h.group_ref.as_deref() == Some(id))
                })
                .collect();
            for host in grouped {
                if let ItemData::Host(h) = host.data {
                    self.upsert_in(
                        &host.vault_id,
                        Some(&host.id),
                        ItemData::Host(h.without_group(&host.id, group)),
                    )?;
                }
            }
        }
        // So do a host's attachments.
        if let ItemData::Host(_) = item.data {
            let attached: Vec<String> = self
                .items()?
                .into_iter()
                .filter(|i| {
                    i.vault_id == item.vault_id
                        && matches!(&i.data, ItemData::Attachment(a) if a.host_ref.as_deref() == Some(id))
                })
                .map(|i| i.id)
                .collect();
            for a in attached {
                self.delete(&a)?;
            }
        }
        Ok(())
    }

    /// Keeps a file with a host (or on its own): sealed into a blob that the next sync uploads,
    /// and an attachment item that refers to it. Returns the item's id.
    pub fn attach(
        &mut self,
        vault: &str,
        host_ref: Option<&str>,
        name: &str,
        bytes: &[u8],
    ) -> Result<String> {
        if bytes.len() as u64 > crate::MAX_ATTACHMENT_BYTES {
            return Err(Error::Invalid(format!(
                "attachments are up to {} MB",
                crate::MAX_ATTACHMENT_BYTES / 1024 / 1024
            )));
        }
        let blob = self.add_blob(vault, mg_vault::BlobKind::Attachment, bytes)?;
        self.upsert_in(
            vault,
            None,
            ItemData::Attachment(crate::Attachment {
                name: name.to_owned(),
                host_ref: host_ref.map(str::to_owned),
                blob: blob.hash,
                size: bytes.len() as u64,
            }),
        )
        .map(|item| item.id)
    }

    /// Jump hosts in connection order (nearest first) and the target itself.
    /// The hosts are as they connect ([`Self::effective_host`]): identities and group defaults
    /// applied.
    pub fn route(&self, host_id: &str) -> Result<(Vec<Item>, Item)> {
        let target = self.item(host_id)?;
        let target_host = self.effective_host(&target)?;
        let mut jumps = Vec::new();
        let mut next = target_host.jump_ref.clone();
        while let Some(id) = next {
            if jumps.len() == MAX_JUMPS || id == host_id || jumps.iter().any(|j: &Item| j.id == id)
            {
                return Err(Error::Invalid(
                    "jump hosts form a loop or a chain that is too long".into(),
                ));
            }
            let hop = self.item(&id)?;
            let hop_host = match &hop.data {
                ItemData::Host(_) => self.effective_host(&hop)?,
                _ => return Err(Error::Invalid(format!("jump host {id} is not a host"))),
            };
            next = hop_host.jump_ref.clone();
            jumps.push(Item {
                data: ItemData::Host(hop_host),
                ..hop
            });
        }
        jumps.reverse();
        Ok((
            jumps,
            Item {
                data: ItemData::Host(target_host),
                ..target
            },
        ))
    }

    /// A host as it connects: its identity's user and sign-in (or its group's, when it has no
    /// user of its own), and the jump host, VPN, theme and session keeping it leaves to its
    /// group.
    pub fn effective_host(&self, item: &Item) -> Result<Host> {
        let ItemData::Host(host) = &item.data else {
            return Err(Error::Invalid(format!("item {} is not a host", item.id)));
        };
        let mut h = host.clone();
        let group = match &h.group_ref {
            Some(g) => match self.item(g) {
                Ok(Item {
                    data: ItemData::HostGroup(g),
                    ..
                }) => Some(g),
                Ok(_) | Err(Error::NotFound(_)) => None,
                Err(e) => return Err(e),
            },
            None => None,
        };
        if let Some(g) = &group {
            // A group's jump host doesn't jump through itself.
            let jump = g.jump_ref.clone().filter(|j| *j != item.id);
            h.jump_ref = h.jump_ref.or(jump);
            h.vpn_ref = h.vpn_ref.or_else(|| g.vpn_ref.clone());
            h.theme_ref = h.theme_ref.or_else(|| g.theme_ref.clone());
            h.keep_session |= g.keep_session;
        }
        let identity = h.identity_ref.clone().or_else(|| {
            group
                .as_ref()
                .filter(|_| h.user.trim().is_empty())
                .and_then(|g| g.identity_ref.clone())
        });
        if let Some(id) = identity {
            match self.item(&id) {
                Ok(Item {
                    data: ItemData::Identity(i),
                    ..
                }) => {
                    h.user = i.user;
                    h.auth = i.auth;
                }
                Ok(_) | Err(Error::NotFound(_)) => {
                    return Err(Error::Invalid(format!(
                        "the identity of \"{}\" is missing from the vault",
                        h.label
                    )));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(h)
    }

    /// An item a new or changed item refers to, which must be in the same vault: teammates
    /// would otherwise see hosts whose key they can't open.
    fn referenced(&self, vault: &str, id: &str) -> Result<Item> {
        let item = self.item(id)?;
        if item.vault_id != vault {
            return Err(Error::Invalid(
                "items can only refer to items in the same vault".into(),
            ));
        }
        Ok(item)
    }

    /// `id` is an item of the expected kind in `vault`, else `missing`.
    fn expect(
        &self,
        vault: &str,
        id: &str,
        missing: &str,
        kind: impl Fn(&ItemData) -> bool,
    ) -> Result<()> {
        match self.referenced(vault, id) {
            Ok(item) if kind(&item.data) => Ok(()),
            Ok(_) | Err(Error::NotFound(_)) => Err(Error::Invalid(missing.to_owned())),
            Err(e) => Err(e),
        }
    }

    pub(crate) fn validate(&self, vault: &str, id: Option<&str>, data: &ItemData) -> Result<()> {
        let invalid = |msg: &str| Err(Error::Invalid(msg.to_owned()));
        // Every member can read an organization's directory: it holds public keys only.
        let directory: bool = self
            .conn
            .query_row("SELECT directory FROM vaults WHERE id = ?1", [vault], |r| {
                r.get(0)
            })
            .optional()?
            .unwrap_or(false);
        if directory != matches!(data, ItemData::MemberKey(_)) {
            return invalid(if directory {
                "the member key directory only holds members' public keys"
            } else {
                "member keys go in an organization's member key directory"
            });
        }
        match data {
            ItemData::Host(h) => {
                if h.hostname.trim().is_empty() {
                    return invalid("hostname is required");
                }
                let group = match &h.group_ref {
                    Some(g) => match self.referenced(vault, g) {
                        Ok(Item {
                            data: ItemData::HostGroup(g),
                            ..
                        }) => Some(g),
                        Ok(_) | Err(Error::NotFound(_)) => {
                            return invalid("the selected group does not exist");
                        }
                        Err(e) => return Err(e),
                    },
                    None => None,
                };
                if let Some(identity) = &h.identity_ref {
                    self.expect(
                        vault,
                        identity,
                        "the selected identity does not exist",
                        |d| matches!(d, ItemData::Identity(_)),
                    )?;
                }
                let group_identity = group.as_ref().is_some_and(|g| g.identity_ref.is_some());
                if h.user.trim().is_empty() && h.identity_ref.is_none() && !group_identity {
                    return invalid("user is required (or an identity)");
                }
                if h.port == 0 {
                    return invalid("port must be between 1 and 65535");
                }
                let own_jump = h.jump_ref.clone().or_else(|| {
                    group
                        .as_ref()
                        .and_then(|g| g.jump_ref.clone())
                        .filter(|j| Some(j.as_str()) != id)
                });
                if let Some(reach) = h.source.as_ref().and_then(|s| s.reach.as_ref()) {
                    reach.check().map_err(Error::Invalid)?;
                }
                // A proxy command is the way to the host: there's no other first hop for it.
                if h.proxy_command.is_some()
                    && (own_jump.is_some()
                        || h.vpn_ref.is_some()
                        || group.as_ref().is_some_and(|g| g.vpn_ref.is_some()))
                {
                    return invalid(
                        "a host with a proxy command connects through it, not a jump host or a VPN too",
                    );
                }
                if let Some(jump) = own_jump {
                    let mut seen: Vec<String> = Vec::new();
                    let mut next = Some(jump);
                    while let Some(hop_id) = next {
                        if Some(hop_id.as_str()) == id {
                            return invalid("a host cannot reach itself through its jump hosts");
                        }
                        if seen.len() >= MAX_JUMPS || seen.contains(&hop_id) {
                            return invalid("jump hosts form a loop or a chain that is too long");
                        }
                        next = match self.referenced(vault, &hop_id) {
                            Ok(
                                hop @ Item {
                                    data: ItemData::Host(_),
                                    ..
                                },
                            ) => self.effective_host(&hop)?.jump_ref,
                            Ok(_) | Err(Error::NotFound(_)) => {
                                return invalid("the selected jump host does not exist");
                            }
                            Err(e) => return Err(e),
                        };
                        seen.push(hop_id);
                    }
                }
                if let Some(vpn) = &h.vpn_ref {
                    match self.referenced(vault, vpn) {
                        Ok(Item {
                            data: ItemData::Vpn(_),
                            ..
                        }) => {}
                        Ok(_) | Err(Error::NotFound(_)) => {
                            return invalid("the selected VPN does not exist");
                        }
                        Err(e) => return Err(e),
                    }
                }
                if let Some(theme) = &h.theme_ref
                    && !theme.starts_with(crate::model::TerminalTheme::BUILTIN)
                {
                    match self.referenced(vault, theme) {
                        Ok(Item {
                            data: ItemData::TerminalTheme(_),
                            ..
                        }) => {}
                        Ok(_) | Err(Error::NotFound(_)) => {
                            return invalid("the selected terminal theme does not exist");
                        }
                        Err(e) => return Err(e),
                    }
                }
                if let HostAuth::Key { key_ref } = &h.auth {
                    match self.referenced(vault, key_ref) {
                        Ok(Item {
                            data: ItemData::SshKey(_),
                            ..
                        }) => {}
                        Ok(_) | Err(Error::NotFound(_)) => {
                            return invalid("the selected SSH key does not exist");
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
            ItemData::SshKey(k) => {
                if k.private_key.trim().is_empty() {
                    return invalid("private key is empty");
                }
            }
            ItemData::Snippet(s) => {
                if s.name.trim().is_empty() {
                    return invalid("snippet name is required");
                }
            }
            ItemData::MemberKey(k) => {
                if k.account_id.is_empty() || k.public_key.split_ascii_whitespace().count() != 2 {
                    return invalid("a member key needs an account and an OpenSSH public key");
                }
            }
            ItemData::SessionLog(l) => {
                if l.cols == 0 || l.rows == 0 {
                    return invalid("a session log needs the terminal's size");
                }
                if l.chunks.iter().any(|c| {
                    c.hash.len() != 64
                        || !c
                            .hash
                            .bytes()
                            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                }) {
                    return invalid("a session log's chunks are named by their hex SHA-256");
                }
            }
            ItemData::Attachment(a) => {
                if a.name.trim().is_empty() || a.name.contains(['/', '\\']) {
                    return invalid("an attachment needs a file name");
                }
                if a.blob.len() != 64
                    || !a
                        .blob
                        .bytes()
                        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                {
                    return invalid("an attachment's file is named by its hex SHA-256");
                }
                if a.size > crate::MAX_ATTACHMENT_BYTES {
                    return invalid("that attachment is too large");
                }
            }
            ItemData::Identity(i) => {
                if i.label.trim().is_empty() {
                    return invalid("an identity needs a name");
                }
                if i.user.trim().is_empty() {
                    return invalid("user is required");
                }
                if let HostAuth::Key { key_ref } = &i.auth {
                    self.expect(vault, key_ref, "the selected SSH key does not exist", |d| {
                        matches!(d, ItemData::SshKey(_))
                    })?;
                }
            }
            ItemData::HostGroup(g) => {
                if g.name.trim().is_empty() {
                    return invalid("a group needs a name");
                }
                if let Some(identity) = &g.identity_ref {
                    self.expect(
                        vault,
                        identity,
                        "the selected identity does not exist",
                        |d| matches!(d, ItemData::Identity(_)),
                    )?;
                }
                if let Some(jump) = &g.jump_ref {
                    self.expect(vault, jump, "the selected jump host does not exist", |d| {
                        matches!(d, ItemData::Host(_))
                    })?;
                }
                if let Some(vpn) = &g.vpn_ref {
                    self.expect(vault, vpn, "the selected VPN does not exist", |d| {
                        matches!(d, ItemData::Vpn(_))
                    })?;
                }
                if let Some(theme) = g
                    .theme_ref
                    .as_ref()
                    .filter(|t| !t.starts_with(crate::model::TerminalTheme::BUILTIN))
                {
                    self.expect(
                        vault,
                        theme,
                        "the selected terminal theme does not exist",
                        |d| matches!(d, ItemData::TerminalTheme(_)),
                    )?;
                }
            }
            ItemData::Unknown => return invalid("this app can't edit that kind of item"),
            ItemData::HostCa(c) => {
                if c.label.trim().is_empty() {
                    return invalid("a host CA needs a name");
                }
                let mut words = c.public_key.split_whitespace();
                let shaped = matches!(
                    (words.next(), words.next()),
                    (Some(kind), Some(_)) if kind.starts_with("ssh-") || kind.starts_with("ecdsa-")
                );
                if !shaped || c.public_key.contains("-cert-v01@") {
                    return invalid("a host CA's key is a public key: ssh-ed25519 AAAA…");
                }
                if c.hosts.is_empty()
                    || c.hosts.iter().any(|h| {
                        h.is_empty() || h.contains(|ch: char| ch.is_whitespace() || ch == ',')
                    })
                {
                    return invalid("a host CA names the hosts it vouches for: *.example.com");
                }
            }
            ItemData::CloudSource(c) => {
                if !["vallic", "aws", "gcp", "azure", "hetzner", "digitalocean"]
                    .contains(&c.provider.as_str())
                {
                    return invalid(
                        "a cloud source's provider is vallic, aws, gcp, azure, hetzner or digitalocean",
                    );
                }
                if let Some(key) = &c.key_ref {
                    self.expect(vault, key, "the selected key does not exist", |d| {
                        matches!(d, ItemData::SshKey(_))
                    })?;
                }
                match c.reach.as_deref() {
                    None | Some("public") => {}
                    Some("aws-ssm" | "aws-eice") if c.provider == "aws" => {}
                    Some("gcp-iap") if c.provider == "gcp" => {}
                    Some("private") => match &c.jump_ref {
                        Some(jump) => self.expect(
                            vault,
                            jump,
                            "the selected jump host does not exist",
                            |d| matches!(d, ItemData::Host(_)),
                        )?,
                        None => return invalid("private addresses need a jump host"),
                    },
                    Some(_) => {
                        return invalid(
                            "a cloud source reaches machines by address, or through AWS Session Manager, an Instance Connect Endpoint or IAP",
                        );
                    }
                }
            }
            ItemData::TerminalTheme(t) => {
                if t.name.trim().is_empty() {
                    return invalid("a theme needs a name");
                }
                if t.ansi.len() != 16 || !t.colors().all(crate::model::is_hex_color) {
                    return invalid("a theme needs #rrggbb colors and 16 ANSI colors");
                }
            }
            ItemData::Vpn(v) => {
                if v.label.trim().is_empty() {
                    return invalid("VPN name is required");
                }
                match &v.vpn {
                    crate::VpnKind::Wireguard { config } if config.trim().is_empty() => {
                        return invalid("WireGuard configuration is empty");
                    }
                    crate::VpnKind::Openvpn { config, .. } if config.trim().is_empty() => {
                        return invalid("OpenVPN profile is empty");
                    }
                    crate::VpnKind::Openconnect { server, .. } if server.trim().is_empty() => {
                        return invalid("VPN server is required");
                    }
                    _ => {}
                }
            }
            ItemData::PortForward(f) => {
                if f.label.trim().is_empty() {
                    return invalid("tunnel name is required");
                }
                match self.referenced(vault, &f.host_ref) {
                    Ok(Item {
                        data: ItemData::Host(_),
                        ..
                    }) => {}
                    Ok(_) | Err(Error::NotFound(_)) => {
                        return invalid("the tunnel's host does not exist");
                    }
                    Err(e) => return Err(e),
                }
                let (bind, target) = match &f.rule {
                    ForwardRule::Local {
                        bind_host,
                        target_host,
                        target_port,
                        ..
                    }
                    | ForwardRule::Remote {
                        bind_host,
                        target_host,
                        target_port,
                        ..
                    } => (bind_host, Some((target_host, *target_port))),
                    ForwardRule::Dynamic { bind_host, .. } => (bind_host, None),
                };
                if bind.trim().is_empty() {
                    return invalid("listen address is required");
                }
                if let Some((host, port)) = target
                    && (host.trim().is_empty() || port == 0)
                {
                    return invalid("destination host and port are required");
                }
            }
        }
        Ok(())
    }

    pub(crate) fn unlocked(&self) -> Result<&Unlocked> {
        self.keys.as_ref().ok_or(Error::Locked)
    }

    pub(crate) fn new_kdf(&self) -> Result<KdfParams> {
        let mut kdf = KdfParams::recommended()?;
        if let Some((m_kib, t, p)) = self.kdf_cost {
            (kdf.m_kib, kdf.t, kdf.p) = (m_kib, t, p);
        }
        Ok(kdf)
    }

    pub(crate) fn finish_unlock(&mut self, account: AccountKeys, row: &AccountRow) -> Result<()> {
        if account.public() != row.public {
            return Err(Error::Corrupt(
                "account keys do not match their public halves".into(),
            ));
        }
        let (vault_id, key_id, wrapped): (String, Vec<u8>, Vec<u8>) = self
            .conn
            .query_row(
                "SELECT id, key_id, wrapped_vault_key FROM vaults WHERE personal = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
            .ok_or_else(|| Error::Corrupt("vault row is missing".into()))?;
        let vault_key = VaultKey::open(&account, &wrapped)?;
        if vault_key.id()[..] != key_id[..] {
            return Err(Error::Corrupt("vault key id does not match".into()));
        }
        let shared = self.load_rings(&account)?;
        let pins = self.load_pins()?;
        let account_id: Option<String> = self
            .conn
            .query_row("SELECT account_id FROM sync_state WHERE id = 1", [], |r| {
                r.get(0)
            })
            .optional()?;
        self.keys = Some(Unlocked {
            account,
            sign_pub: row.public.sign,
            vault_id,
            vault_key,
            shared,
            pins,
            account_id,
        });
        Ok(())
    }

    /// Opens every shared vault's key ring.
    pub(crate) fn load_rings(&self, account: &AccountKeys) -> Result<HashMap<String, Ring>> {
        let mut out = HashMap::new();
        let vaults: Vec<(String, Vec<u8>, String)> = self
            .conn
            .prepare("SELECT id, key_id, permission FROM vaults WHERE personal = 0")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        for (id, current, permission) in vaults {
            let wrapped: Vec<Vec<u8>> = self
                .conn
                .prepare("SELECT wrapped FROM vault_keys WHERE vault_id = ?1")?
                .query_map([&id], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            let keys = wrapped
                .iter()
                .map(|w| VaultKey::open(account, w))
                .collect::<core::result::Result<Vec<_>, _>>()?;
            let current: [u8; 16] = current
                .try_into()
                .map_err(|_| Error::Corrupt("vault key id has wrong length".into()))?;
            if !keys.iter().any(|k| *k.id() == current) {
                return Err(Error::Corrupt(format!(
                    "the current key of vault {id} is missing"
                )));
            }
            out.insert(
                id,
                Ring {
                    current,
                    keys,
                    access: Access::parse(&permission),
                },
            );
        }
        Ok(out)
    }

    pub(crate) fn load_pins(&self) -> Result<HashMap<String, [u8; 32]>> {
        let rows: Vec<(String, Vec<u8>)> = self
            .conn
            .prepare("SELECT account_id, sign FROM pinned_keys")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        rows.into_iter()
            .map(|(a, k)| {
                k.try_into()
                    .map(|k| (a, k))
                    .map_err(|_| Error::Corrupt("pinned key has wrong length".into()))
            })
            .collect()
    }

    pub(crate) fn account_row(&self) -> Result<Option<AccountRow>> {
        self.conn
            .query_row(
                "SELECT kdf_m_kib, kdf_t, kdf_p, kdf_salt, enc_public_key, sign_public_key,
                        wrapped_private_keys, wrapped_private_keys_rk
                 FROM account WHERE id = 1",
                [],
                |r| {
                    Ok((
                        KdfParams {
                            m_kib: r.get(0)?,
                            t: r.get(1)?,
                            p: r.get(2)?,
                            salt: r.get(3)?,
                        },
                        r.get::<_, Vec<u8>>(4)?,
                        r.get::<_, Vec<u8>>(5)?,
                        r.get(6)?,
                        r.get(7)?,
                    ))
                },
            )
            .optional()?
            .map(|(kdf, enc, sign, wrapped, wrapped_rk)| {
                let key = |v: Vec<u8>| -> Result<[u8; 32]> {
                    v.try_into()
                        .map_err(|_| Error::Corrupt("public key has wrong length".into()))
                };
                Ok::<_, Error>(AccountRow {
                    kdf,
                    public: PublicKeys {
                        enc: key(enc)?,
                        sign: key(sign)?,
                    },
                    wrapped,
                    wrapped_rk,
                })
            })
            .transpose()
    }
}

fn wrong_password(e: mg_vault::Error) -> Error {
    match e {
        mg_vault::Error::Decrypt => Error::WrongPassword,
        other => other.into(),
    }
}

pub(crate) fn unwrap_with_password(row: &AccountRow, password: &str) -> Result<AccountKeys> {
    let mk = MasterKey::derive(password.as_bytes(), &row.kdf)?;
    AccountKeys::unwrap(&mk, &row.wrapped).map_err(wrong_password)
}

pub(crate) fn check_password(password: &str) -> Result<()> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(Error::Invalid(format!(
            "master password must be at least {MIN_PASSWORD_CHARS} characters"
        )));
    }
    Ok(())
}

pub(crate) fn context<'a>(vault_id: &'a str, id: &'a str) -> ItemContext<'a> {
    ItemContext {
        vault_id,
        item_id: id,
        schema_version: SCHEMA_VERSION,
    }
}

/// The key generation an envelope names in its clear header.
pub(crate) fn envelope_key_id(env: &[u8]) -> Result<&[u8]> {
    env.get(1..17)
        .ok_or(Error::Crypto(mg_vault::Error::Malformed(
            "envelope too short",
        )))
}

/// Verifies the author's signature (`None` = this account) and decrypts with the vault key the
/// envelope names.
pub(crate) fn open_envelope(
    keys: &Unlocked,
    vault: &str,
    id: &str,
    env: &[u8],
    author: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>> {
    let vk = keys.key_for(vault, envelope_key_id(env)?)?;
    let signer = keys.author_key(vault, id, author)?;
    Ok(envelope::open(vk, &signer, &context(vault, id), env)?)
}

pub(crate) fn decrypt(
    keys: &Unlocked,
    vault: &str,
    id: &str,
    env: &[u8],
    author: Option<&str>,
) -> Result<ItemData> {
    let plain = open_envelope(keys, vault, id, env, author)?;
    serde_json::from_slice(&plain).map_err(|e| Error::Corrupt(format!("item {id}: {e}")))
}

pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Host, HostGroup, Identity, Snippet, SshKey};

    const PW: &str = "correct horse battery";

    fn fast(v: LocalVault) -> LocalVault {
        v.with_kdf_cost(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1)
    }

    fn new_vault() -> (LocalVault, RecoveryKey) {
        let mut v = fast(LocalVault::open_in_memory().unwrap());
        let rk = v.create(PW).unwrap();
        (v, rk)
    }

    fn host(label: &str, auth: HostAuth) -> ItemData {
        ItemData::Host(Host {
            label: label.into(),
            hostname: format!("{label}.secret-host.internal"),
            port: 22,
            user: "deploy".into(),
            auth,
            jump_ref: None,
            vpn_ref: None,
            theme_ref: None,
            record_sessions: false,
            tags: vec!["prod".into()],
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

    #[test]
    fn a_proxy_command_is_the_only_way_to_its_host() {
        let (mut v, _) = new_vault();
        let pw = || HostAuth::Password { password: None };
        let jump = v.upsert(None, host("bastion", pw())).unwrap().id;
        let ItemData::Host(mut h) = host("private", pw()) else {
            unreachable!()
        };
        h.proxy_command = Some("aws ssm start-session --target %h".into());
        v.upsert(None, ItemData::Host(h.clone())).unwrap();
        h.jump_ref = Some(jump);
        let e = v.upsert(None, ItemData::Host(h)).unwrap_err().to_string();
        assert!(e.contains("not a jump host or a VPN too"), "{e}");
    }

    #[test]
    fn identities_and_groups_fill_in_what_hosts_leave_empty() {
        let (mut v, _) = new_vault();
        let key = v
            .upsert(
                None,
                ItemData::SshKey(SshKey {
                    label: "ops".into(),
                    private_key: "-----BEGIN OPENSSH PRIVATE KEY-----".into(), // gitleaks:allow
                    passphrase: None,
                    public_key: "ssh-ed25519 AAAA ops".into(),
                    algorithm: "ed25519".into(),
                    fingerprint: "SHA256:o".into(),
                    certificate: None,
                    renew: None,
                }),
            )
            .unwrap();
        let ops = v
            .upsert(
                None,
                ItemData::Identity(Identity {
                    label: "ops".into(),
                    user: "ops".into(),
                    auth: HostAuth::Key {
                        key_ref: key.id.clone(),
                    },
                }),
            )
            .unwrap();
        let bastion = v
            .upsert(None, host("bastion", HostAuth::system_agent()))
            .unwrap();
        let prod = v
            .upsert(
                None,
                ItemData::HostGroup(HostGroup {
                    name: "prod".into(),
                    identity_ref: Some(ops.id.clone()),
                    jump_ref: Some(bastion.id.clone()),
                    keep_session: true,
                    ..Default::default()
                }),
            )
            .unwrap();
        // The bastion joins the group without jumping through itself.
        let bastion = v
            .upsert(
                Some(&bastion.id),
                match host("bastion", HostAuth::system_agent()) {
                    ItemData::Host(h) => ItemData::Host(Host {
                        group_ref: Some(prod.id.clone()),
                        ..h
                    }),
                    _ => unreachable!(),
                },
            )
            .unwrap();
        // A host with no user of its own takes the group's identity and jump host.
        let db = v
            .upsert(
                None,
                match host("db", HostAuth::system_agent()) {
                    ItemData::Host(h) => ItemData::Host(Host {
                        user: String::new(),
                        group_ref: Some(prod.id.clone()),
                        ..h
                    }),
                    _ => unreachable!(),
                },
            )
            .unwrap();
        let (jumps, target) = v.route(&db.id).unwrap();
        let ItemData::Host(t) = &target.data else {
            panic!()
        };
        assert_eq!(t.user, "ops");
        assert_eq!(
            t.auth,
            HostAuth::Key {
                key_ref: key.id.clone()
            }
        );
        assert!(t.keep_session);
        assert_eq!(jumps.len(), 1);
        assert_eq!(jumps[0].id, bastion.id);
        let ItemData::Host(b) = &jumps[0].data else {
            panic!()
        };
        assert_eq!(b.user, "deploy", "its own user stands");
        // Without a user, an identity or a group identity, a host is incomplete.
        assert!(matches!(
            v.upsert(
                None,
                match host("bare", HostAuth::system_agent()) {
                    ItemData::Host(h) => ItemData::Host(Host {
                        user: String::new(),
                        ..h
                    }),
                    _ => unreachable!(),
                }
            ),
            Err(Error::Invalid(_))
        ));
        // What's in use can't go; a group can, and its hosts stay.
        assert!(matches!(v.delete(&ops.id), Err(Error::Invalid(_))));
        assert!(matches!(v.delete(&key.id), Err(Error::Invalid(_))));
        v.delete(&prod.id).unwrap();
        // Its hosts connect as before, now on their own.
        let (jumps, target) = v.route(&db.id).unwrap();
        match &target.data {
            ItemData::Host(h) => {
                assert_eq!(h.group_ref, None);
                assert_eq!(h.identity_ref.as_deref(), Some(ops.id.as_str()));
                assert_eq!((h.user.as_str(), h.keep_session), ("ops", true));
            }
            _ => panic!(),
        }
        assert_eq!(jumps[0].id, bastion.id);
    }

    fn with_jump(data: ItemData, jump: &str) -> ItemData {
        match data {
            ItemData::Host(h) => ItemData::Host(Host {
                jump_ref: Some(jump.into()),
                ..h
            }),
            other => other,
        }
    }

    fn key(label: &str) -> ItemData {
        ItemData::SshKey(SshKey {
            label: label.into(),
            private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret-key-material\n".into(),
            passphrase: None,
            public_key: "ssh-ed25519 AAAA".into(),
            algorithm: "ssh-ed25519".into(),
            fingerprint: "SHA256:x".into(),
            certificate: None,
            renew: None,
        })
    }

    #[test]
    fn lifecycle_status() {
        let mut v = fast(LocalVault::open_in_memory().unwrap());
        assert_eq!(v.status().unwrap(), Status::Uninitialized);
        assert!(matches!(v.unlock(PW), Err(Error::NotInitialized)));
        v.create(PW).unwrap();
        assert_eq!(v.status().unwrap(), Status::Unlocked);
        assert!(matches!(v.create(PW), Err(Error::AlreadyInitialized)));
        v.lock();
        assert_eq!(v.status().unwrap(), Status::Locked);
        assert!(matches!(v.items(), Err(Error::Locked)));
        assert!(matches!(
            v.unlock("wrong password"),
            Err(Error::WrongPassword)
        ));
        v.unlock(PW).unwrap();
        assert_eq!(v.status().unwrap(), Status::Unlocked);
    }

    #[test]
    fn short_password_is_rejected() {
        let mut v = fast(LocalVault::open_in_memory().unwrap());
        assert!(matches!(v.create("short"), Err(Error::Invalid(_))));
        assert_eq!(v.status().unwrap(), Status::Uninitialized);
    }

    #[test]
    fn crud_roundtrip() {
        let (mut v, _) = new_vault();
        let k = v.upsert(None, key("laptop")).unwrap();
        let h = v
            .upsert(
                None,
                host(
                    "db1",
                    HostAuth::Key {
                        key_ref: k.id.clone(),
                    },
                ),
            )
            .unwrap();
        let s = v
            .upsert(
                None,
                ItemData::Snippet(Snippet {
                    name: "disk".into(),
                    body: "df -h".into(),
                    tags: vec![],
                }),
            )
            .unwrap();
        assert_eq!(v.items().unwrap().len(), 3);
        assert_eq!(v.item(&h.id).unwrap().data, h.data);

        let edited = host(
            "db1-renamed",
            HostAuth::Password {
                password: Some("pw".into()),
            },
        );
        v.upsert(Some(&h.id), edited.clone()).unwrap();
        assert_eq!(v.item(&h.id).unwrap().data, edited);

        v.delete(&s.id).unwrap();
        assert!(matches!(v.item(&s.id), Err(Error::NotFound(_))));
        assert_eq!(v.items().unwrap().len(), 2);
        let (deleted, envelope, dirty): (bool, Option<Vec<u8>>, bool) = v
            .conn
            .query_row(
                "SELECT deleted, envelope, dirty FROM items WHERE id = ?1",
                [&s.id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert!(
            deleted && envelope.is_none() && dirty,
            "deletes become syncable tombstones"
        );
    }

    #[test]
    fn type_and_reference_checks() {
        let (mut v, _) = new_vault();
        let k = v.upsert(None, key("k")).unwrap();
        assert!(matches!(
            v.upsert(Some(&k.id), host("h", HostAuth::system_agent())),
            Err(Error::TypeMismatch { .. })
        ));
        assert!(matches!(
            v.upsert(Some("01NOPE"), host("h", HostAuth::system_agent())),
            Err(Error::NotFound(_))
        ));
        assert!(matches!(
            v.upsert(
                None,
                host(
                    "h",
                    HostAuth::Key {
                        key_ref: "01MISSING".into()
                    }
                )
            ),
            Err(Error::Invalid(_))
        ));
        let h = v
            .upsert(
                None,
                host(
                    "web",
                    HostAuth::Key {
                        key_ref: k.id.clone(),
                    },
                ),
            )
            .unwrap();
        assert!(matches!(v.delete(&k.id), Err(Error::Invalid(msg)) if msg.contains("web")));
        v.delete(&h.id).unwrap();
        v.delete(&k.id).unwrap();
    }

    #[test]
    fn jump_routes_and_loops() {
        let (mut v, _) = new_vault();
        let bastion = v
            .upsert(None, host("bastion", HostAuth::system_agent()))
            .unwrap();
        let inner = v
            .upsert(
                None,
                with_jump(host("inner", HostAuth::system_agent()), &bastion.id),
            )
            .unwrap();
        let db = v
            .upsert(
                None,
                with_jump(host("db", HostAuth::system_agent()), &inner.id),
            )
            .unwrap();

        let (jumps, target) = v.route(&db.id).unwrap();
        assert_eq!(
            jumps.iter().map(|j| j.id.as_str()).collect::<Vec<_>>(),
            [&bastion.id, &inner.id]
        );
        assert_eq!(target.id, db.id);
        assert!(v.route(&bastion.id).unwrap().0.is_empty());

        // bastion -> db would close the loop db -> inner -> bastion -> db.
        let looped = with_jump(host("bastion", HostAuth::system_agent()), &db.id);
        assert!(
            matches!(v.upsert(Some(&bastion.id), looped), Err(Error::Invalid(m)) if m.contains("itself"))
        );
        let selfie = with_jump(host("bastion", HostAuth::system_agent()), &bastion.id);
        assert!(matches!(
            v.upsert(Some(&bastion.id), selfie),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            v.upsert(None, with_jump(host("x", HostAuth::system_agent()), "01MISSING")),
            Err(Error::Invalid(m)) if m.contains("does not exist")
        ));

        // A host used as a jump host cannot be deleted out from under others.
        assert!(matches!(v.delete(&inner.id), Err(Error::Invalid(m)) if m.contains("db")));
        v.delete(&db.id).unwrap();
        v.delete(&inner.id).unwrap();
    }

    fn theme(name: &str) -> crate::TerminalTheme {
        crate::TerminalTheme {
            name: name.into(),
            background: "#101010".into(),
            foreground: "#e0e0e0".into(),
            cursor: "#ff8800".into(),
            cursor_accent: "#101010".into(),
            selection_background: "#303030".into(),
            selection_foreground: None,
            ansi: (0..16).map(|i| format!("#0000{i:02x}")).collect(),
        }
    }

    #[test]
    fn terminal_themes_and_the_hosts_that_use_them() {
        let (mut v, _) = new_vault();
        let bad = |t: crate::TerminalTheme| {
            matches!(
                v.validate("", None, &ItemData::TerminalTheme(t)),
                Err(Error::Invalid(_))
            )
        };
        assert!(bad(crate::TerminalTheme {
            ansi: vec!["#000000".into(); 15],
            ..theme("short")
        }));
        assert!(bad(crate::TerminalTheme {
            background: "black".into(),
            ..theme("named color")
        }));
        assert!(bad(theme("  ")));

        let t = v
            .upsert(None, ItemData::TerminalTheme(theme("Ocean")))
            .unwrap();
        let with_theme = |r: &str| match host("db", HostAuth::system_agent()) {
            ItemData::Host(h) => ItemData::Host(Host {
                theme_ref: Some(r.into()),
                record_sessions: false,
                ..h
            }),
            _ => unreachable!(),
        };
        // A theme of the vault, or one built into the app.
        let h = v.upsert(None, with_theme(&t.id)).unwrap();
        v.upsert(None, with_theme("builtin:anything")).unwrap();
        assert!(matches!(
            v.upsert(None, with_theme("01JNOSUCHTHEME000000000000")),
            Err(Error::Invalid(_))
        ));
        let k = v.upsert(None, key("not a theme")).unwrap();
        assert!(matches!(
            v.upsert(None, with_theme(&k.id)),
            Err(Error::Invalid(_))
        ));
        // In use, it can't be deleted.
        assert!(matches!(v.delete(&t.id), Err(Error::Invalid(m)) if m.contains("db")));
        v.delete(&h.id).unwrap();
        v.delete(&t.id).unwrap();
    }

    #[test]
    fn hosts_reference_vpns() {
        use crate::{VpnKind, VpnProfile};
        let (mut v, _) = new_vault();
        let vpn = v
            .upsert(
                None,
                ItemData::Vpn(VpnProfile {
                    label: "client A".into(),
                    vpn: VpnKind::Wireguard {
                        config: "[Interface]".into(),
                    },
                }),
            )
            .unwrap();
        let with_vpn = |r: &str| match host("db", HostAuth::system_agent()) {
            ItemData::Host(h) => ItemData::Host(Host {
                vpn_ref: Some(r.into()),
                ..h
            }),
            _ => unreachable!(),
        };
        assert!(
            matches!(v.upsert(None, with_vpn("01NOPE")), Err(Error::Invalid(m)) if m.contains("VPN"))
        );
        let h = v.upsert(None, with_vpn(&vpn.id)).unwrap();
        assert!(matches!(v.delete(&vpn.id), Err(Error::Invalid(m)) if m.contains("db")));
        assert!(matches!(
            v.upsert(
                None,
                ItemData::Vpn(VpnProfile {
                    label: "x".into(),
                    vpn: VpnKind::Wireguard { config: " ".into() }
                })
            ),
            Err(Error::Invalid(_))
        ));
        v.delete(&h.id).unwrap();
        v.delete(&vpn.id).unwrap();
    }

    #[test]
    fn prepared_credentials_change_nothing_until_applied() {
        let (mut v, rk) = new_vault();
        let (_, creds) = v.prepare_password_change(PW, "second password").unwrap();
        v.lock();
        v.unlock(PW).expect("still the old password");
        v.apply_credentials(creds).unwrap();
        v.lock();
        assert!(matches!(v.unlock(PW), Err(Error::WrongPassword)));
        v.unlock("second password").unwrap();
        assert!(matches!(
            v.prepare_password_change("wrong", "x".repeat(10).as_str()),
            Err(Error::WrongPassword)
        ));

        // A new recovery key keeps the password and retires the old key.
        let (_, creds) = v.prepare_new_recovery_key("second password").unwrap();
        let new_rk = v.apply_credentials(creds).unwrap().unwrap();
        assert!(matches!(
            v.prepare_recovery(&rk.to_code(), "third password"),
            Err(Error::WrongRecoveryKey)
        ));
        v.recover(&new_rk.to_code(), "third password").unwrap();
        v.lock();
        v.unlock("third password").unwrap();
    }

    #[test]
    fn another_accounts_keys_are_refused() {
        let (mut mine, _) = new_vault();
        let (other, other_rk) = new_vault();
        let other_row = other.account_row().unwrap().unwrap();
        // The other account's recovery material, even with its valid code.
        assert!(matches!(
            mine.prepare_recovery_from(&other_rk.to_code(), &other_row.wrapped_rk, "new password"),
            Err(Error::WrongRecoveryKey)
        ));
        // Its password-wrapped keys offered as "the password changed elsewhere".
        let mk = MasterKey::derive(PW.as_bytes(), &other_row.kdf).unwrap();
        assert!(matches!(
            mine.adopt_credentials(&mk, &other_row.kdf, &other_row.wrapped, None),
            Err(Error::Corrupt(_))
        ));
        let (_, theirs) = other.prepare_password_change(PW, "their new one").unwrap();
        assert!(matches!(
            mine.apply_credentials(theirs),
            Err(Error::Corrupt(_))
        ));
        mine.lock();
        mine.unlock(PW).expect("untouched");
    }

    #[test]
    fn every_vpn_kind_round_trips() {
        use crate::{VpnKind, VpnProfile};
        let (mut v, _) = new_vault();
        let kinds = [
            VpnKind::Openvpn {
                config: "client\nremote vpn.example 1194\n".into(),
                username: Some("alice".into()),
                password: None,
            },
            VpnKind::Openconnect {
                server: "vpn.example.com/eng".into(),
                protocol: "anyconnect".into(),
                username: Some("alice".into()),
                password: Some("pw".into()),
                authgroup: Some("Engineering".into()),
                server_cert: Some("pin-sha256:abc=".into()),
            },
        ];
        for vpn in kinds {
            let data = ItemData::Vpn(VpnProfile {
                label: "client".into(),
                vpn,
            });
            let saved = v.upsert(None, data.clone()).unwrap();
            assert_eq!(v.item(&saved.id).unwrap().data, data);
        }
        let json = serde_json::to_value(VpnKind::Openconnect {
            server: "s".into(),
            protocol: "gp".into(),
            username: None,
            password: None,
            authgroup: None,
            server_cert: None,
        })
        .unwrap();
        assert_eq!(
            json,
            serde_json::json!({"type": "openconnect", "server": "s", "protocol": "gp"})
        );
        for empty in [
            VpnKind::Openvpn {
                config: "  ".into(),
                username: None,
                password: None,
            },
            VpnKind::Openconnect {
                server: "".into(),
                protocol: "anyconnect".into(),
                username: None,
                password: None,
                authgroup: None,
                server_cert: None,
            },
        ] {
            let data = ItemData::Vpn(VpnProfile {
                label: "x".into(),
                vpn: empty,
            });
            assert!(matches!(v.upsert(None, data), Err(Error::Invalid(_))));
        }
    }

    #[test]
    fn port_forwards_reference_hosts() {
        use crate::PortForward;
        let (mut v, _) = new_vault();
        let db = v
            .upsert(None, host("db", HostAuth::system_agent()))
            .unwrap();
        let fwd = |host_ref: &str, target_port| {
            ItemData::PortForward(PortForward {
                label: "postgres".into(),
                host_ref: host_ref.into(),
                rule: ForwardRule::Local {
                    bind_host: "127.0.0.1".into(),
                    bind_port: 15432,
                    target_host: "127.0.0.1".into(),
                    target_port,
                },
            })
        };
        assert!(matches!(
            v.upsert(None, fwd("01NOPE", 5432)),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            v.upsert(None, fwd(&db.id, 0)),
            Err(Error::Invalid(_))
        ));
        let f = v.upsert(None, fwd(&db.id, 5432)).unwrap();
        assert_eq!(v.item(&f.id).unwrap().data, fwd(&db.id, 5432));
        assert!(
            matches!(v.delete(&db.id), Err(Error::Invalid(m)) if m.contains("tunnel postgres"))
        );
        v.delete(&f.id).unwrap();
        v.delete(&db.id).unwrap();
    }

    #[test]
    fn erase_leaves_a_first_run_device() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.sqlite3");
        {
            let mut v = fast(LocalVault::open(&path).unwrap());
            v.create(PW).unwrap();
            v.upsert(
                None,
                host(
                    "db1",
                    HostAuth::Password {
                        password: Some("hunter2-plaintext".into()),
                    },
                ),
            )
            .unwrap();
            v.set_setting("auto_lock_minutes", Some("5")).unwrap();
            v.erase().unwrap();
            assert_eq!(v.status().unwrap(), Status::Uninitialized);
            assert_eq!(v.setting("auto_lock_minutes").unwrap(), None);
            // A new vault can be made on it, and has nothing of the old one.
            v.create(PW).unwrap();
            assert!(v.items().unwrap().is_empty());
        }
        // Reopened (the schema stays), still nothing of the erased vault in the file.
        let v = LocalVault::open(&path).unwrap();
        assert_eq!(v.status().unwrap(), Status::Locked);
        let bytes = std::fs::read(&path).unwrap();
        assert!(!bytes.windows(4).any(|w| w == b"db1."));
    }

    #[test]
    fn persists_and_stores_only_ciphertext() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.sqlite3");
        let id = {
            let mut v = fast(LocalVault::open(&path).unwrap());
            v.create(PW).unwrap();
            v.upsert(None, key("k")).unwrap();
            v.upsert(
                None,
                host(
                    "db1",
                    HostAuth::Password {
                        password: Some("hunter2-plaintext".into()),
                    },
                ),
            )
            .unwrap()
            .id
        };
        let bytes = std::fs::read(&path).unwrap();
        for needle in [
            "secret-host.internal",
            "hunter2-plaintext",
            "secret-key-material",
            "deploy",
            "db1",
        ] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
                "{needle} leaked to disk"
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let mut v = LocalVault::open(&path).unwrap();
        assert_eq!(v.status().unwrap(), Status::Locked);
        v.unlock(PW).unwrap();
        assert!(
            matches!(v.item(&id).unwrap().data, ItemData::Host(Host { ref label, .. }) if label == "db1")
        );
    }

    #[test]
    fn tampered_or_swapped_envelopes_are_rejected() {
        let (mut v, _) = new_vault();
        let a = v.upsert(None, host("a", HostAuth::system_agent())).unwrap();
        let b = v.upsert(None, host("b", HostAuth::system_agent())).unwrap();

        // Swap a's ciphertext into b's row: AAD binds the envelope to its item id.
        v.conn
            .execute("UPDATE items SET envelope = (SELECT envelope FROM items WHERE id = ?1) WHERE id = ?2", [&a.id, &b.id])
            .unwrap();
        assert!(matches!(
            v.item(&b.id),
            Err(Error::Crypto(mg_vault::Error::Signature))
        ));

        // Flip a byte in a's ciphertext.
        let mut env: Vec<u8> = v
            .conn
            .query_row("SELECT envelope FROM items WHERE id = ?1", [&a.id], |r| {
                r.get(0)
            })
            .unwrap();
        env[60] ^= 1;
        v.conn
            .execute(
                "UPDATE items SET envelope = ?1 WHERE id = ?2",
                params![env, a.id],
            )
            .unwrap();
        assert!(matches!(v.item(&a.id), Err(Error::Crypto(_))));
        assert!(
            v.items().is_err(),
            "listing must not silently skip corrupt items"
        );
    }

    #[test]
    fn recovery_resets_password_and_keeps_items() {
        let (mut v, rk) = new_vault();
        let h = v
            .upsert(None, host("db1", HostAuth::system_agent()))
            .unwrap();
        v.lock();

        let wrong = RecoveryKey::generate().unwrap();
        assert!(matches!(
            v.recover(&wrong.to_code(), "new password!"),
            Err(Error::WrongRecoveryKey)
        ));
        assert!(matches!(
            v.recover("ABCD-EFGH", "new password!"),
            Err(Error::Invalid(_))
        ));

        v.recover(&rk.to_code(), "new password!").unwrap();
        assert_eq!(v.item(&h.id).unwrap().data, h.data);
        v.lock();
        assert!(matches!(v.unlock(PW), Err(Error::WrongPassword)));
        v.unlock("new password!").unwrap();

        // The recovery key keeps working after a reset.
        v.lock();
        v.recover(&rk.to_code(), "third password").unwrap();
    }

    #[test]
    fn change_password() {
        let (mut v, _) = new_vault();
        assert!(matches!(
            v.change_password("not it at all", "brand new pw"),
            Err(Error::WrongPassword)
        ));
        v.change_password(PW, "brand new pw").unwrap();
        v.lock();
        assert!(matches!(v.unlock(PW), Err(Error::WrongPassword)));
        v.unlock("brand new pw").unwrap();
    }
}
