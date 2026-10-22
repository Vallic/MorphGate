//! Organizations and shared vaults: joining, confirming members, granting access, rotating keys,
//! and bringing shared vaults onto this device ([`refresh`]).
//!
//! The server is trusted to say who belongs where, never about keys. Every account key is checked
//! against the organization's certificate chain (its root pinned on joining), every sealed vault
//! key against its grant signature, and every item against its author's verified key. A key that
//! changes for a known account is a hard error.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, MutexGuard};

use mg_sync::{
    B64, ConfirmMember, CreateInvite, CreateOrg, CreateVault, DeleteOrg, GrantKey, Invite, Member,
    MemberCertificate, MemberStatus, MemberVaultKey, OwnerLink, Permission, Role, RotateVaultKey,
    SealedFor, SetVaultMember, SyncClient, TransferOrg, UpdateMember, VaultGrant,
};
use mg_vault::sharing::{self as crypto, CertKind};
use mg_vault::{PublicKeys, VaultKey, envelope};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::account::{AccountError, SharedVault, blocking};
use crate::sync::{Hold, note_held};
use crate::sync_http::held;
use crate::vault::{Access, Ring, context, envelope_key_id, now};
use crate::{Error, ItemData, LocalVault, MemberKey};

type Result<T> = core::result::Result<T, AccountError>;

/// Item id of a vault's encrypted name.
pub const META_ID: &str = "vault-meta";

#[derive(Serialize, Deserialize)]
struct VaultMeta {
    name: String,
    /// The organization's member key directory.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    directory: bool,
}

/// The name a member key directory is created with.
pub const DIRECTORY_NAME: &str = "Member keys";

fn lock(vault: &SharedVault) -> Result<MutexGuard<'_, LocalVault>> {
    vault.lock().map_err(|_| AccountError::Poisoned)
}

fn untrusted(msg: impl Into<String>) -> Error {
    Error::Untrusted(msg.into())
}

fn key32(b: &B64) -> core::result::Result<[u8; 32], Error> {
    b.0.as_slice()
        .try_into()
        .map_err(|_| untrusted("the server sent a malformed public key"))
}

fn link_keys(l: &OwnerLink) -> core::result::Result<PublicKeys, Error> {
    Ok(PublicKeys {
        enc: key32(&l.enc_public_key)?,
        sign: key32(&l.sign_public_key)?,
    })
}

fn member_keys(m: &Member) -> core::result::Result<PublicKeys, Error> {
    Ok(PublicKeys {
        enc: key32(&m.enc_public_key)?,
        sign: key32(&m.sign_public_key)?,
    })
}

fn access_of(p: Permission) -> Access {
    match p {
        Permission::Read => Access::Read,
        Permission::Write => Access::Write,
        Permission::Manage => Access::Manage,
    }
}

pub fn permission_of(a: Access) -> Permission {
    match a {
        Access::Read => Permission::Read,
        Access::Write => Permission::Write,
        Access::Manage => Permission::Manage,
    }
}

// ------------------------------------------------------------------ trust

/// The account an organization's trust starts from: its creator, pinned when this device
/// created or joined the organization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Root {
    pub account_id: String,
    pub keys: PublicKeys,
}

/// The accounts of an organization whose keys this device can vouch for.
#[derive(Debug, Default)]
pub struct Trust {
    pub keys: HashMap<String, PublicKeys>,
    /// Confirmed members the server lists whose keys couldn't be verified.
    pub unverified: Vec<String>,
    /// Members trusted only because this device verified them before: their certificate no
    /// longer verifies (the admin who signed it left). An admin's device certifies them again.
    pub pinned_only: Vec<String>,
}

/// The ownership chain from the pinned root: each later owner certified by the one before.
pub fn verify_owners(
    org_id: &str,
    root: &Root,
    chain: &[OwnerLink],
) -> core::result::Result<Vec<(String, PublicKeys)>, Error> {
    let first = chain
        .first()
        .ok_or_else(|| untrusted("the organization has no owner"))?;
    if first.account_id != root.account_id || link_keys(first)? != root.keys {
        return Err(untrusted(
            "the organization's root key isn't the one this device pinned",
        ));
    }
    let mut owners = vec![(root.account_id.clone(), root.keys)];
    for link in &chain[1..] {
        let cert = link
            .cert
            .as_ref()
            .ok_or_else(|| untrusted("the ownership chain is broken"))?;
        let (prev_id, prev_keys) = owners.last().expect("not empty");
        if cert.signer_id != *prev_id {
            return Err(untrusted("the ownership chain is broken"));
        }
        let keys = link_keys(link)?;
        crypto::verify_cert(
            &prev_keys.sign,
            CertKind::Owner,
            org_id,
            &link.account_id,
            &keys,
            &cert.sig.0,
        )
        .map_err(|_| untrusted("an ownership certificate doesn't verify"))?;
        owners.push((link.account_id.clone(), keys));
    }
    Ok(owners)
}

/// Whose keys this device trusts in an organization: owners through the chain, admins through
/// an owner's admin certificate, everyone through a member certificate by an owner or admin, or
/// an earlier verification pinned on this device. Any listed account whose keys differ from its
/// pin is an error.
pub fn verify_org(
    org_id: &str,
    root: &Root,
    chain: &[OwnerLink],
    members: &[Member],
    pins: &HashMap<String, PublicKeys>,
) -> core::result::Result<Trust, Error> {
    let owners = verify_owners(org_id, root, chain)?;
    for m in members {
        let keys = member_keys(m)?;
        if pins.get(&m.account_id).is_some_and(|p| *p != keys) {
            return Err(untrusted(format!(
                "the keys of {} changed; they must be removed and invited again",
                m.email
            )));
        }
    }
    let mut trust = Trust::default();
    let mut signers: HashMap<String, [u8; 32]> = HashMap::new();
    for (id, keys) in &owners {
        trust.keys.insert(id.clone(), *keys);
        signers.insert(id.clone(), keys.sign);
    }
    let confirmed = || {
        members
            .iter()
            .filter(|m| m.status == MemberStatus::Confirmed)
    };
    for m in confirmed().filter(|m| m.role == Role::Admin) {
        let keys = member_keys(m)?;
        let certified = m.admin_cert.as_ref().is_some_and(|c| {
            owners.iter().any(|(id, k)| {
                *id == c.signer_id
                    && crypto::verify_cert(
                        &k.sign,
                        CertKind::Admin,
                        org_id,
                        &m.account_id,
                        &keys,
                        &c.sig.0,
                    )
                    .is_ok()
            })
        });
        if certified {
            signers.insert(m.account_id.clone(), keys.sign);
        }
    }
    for m in confirmed() {
        let keys = member_keys(m)?;
        if let Some(known) = trust.keys.get(&m.account_id) {
            if *known != keys {
                return Err(untrusted(format!(
                    "the server lists other keys for owner {} than the ownership chain",
                    m.email
                )));
            }
            continue;
        }
        let certified = m.member_cert.as_ref().is_some_and(|c| {
            signers.get(&c.signer_id).is_some_and(|s| {
                crypto::verify_cert(s, CertKind::Member, org_id, &m.account_id, &keys, &c.sig.0)
                    .is_ok()
            })
        });
        if certified || pins.get(&m.account_id) == Some(&keys) {
            trust.keys.insert(m.account_id.clone(), keys);
            if !certified {
                trust.pinned_only.push(m.account_id.clone());
            }
        } else {
            trust.unverified.push(m.account_id.clone());
        }
    }
    Ok(trust)
}

// ------------------------------------------------------------------ local state

/// An organization this device knows (works offline).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgInfo {
    pub id: String,
    pub name: String,
    pub role: Role,
    pub status: MemberStatus,
    /// The pinned root's fingerprint (the creator).
    pub root_fingerprint: String,
}

fn role_str(r: Role) -> &'static str {
    match r {
        Role::Owner => "owner",
        Role::Admin => "admin",
        Role::Member => "member",
    }
}

fn parse_role(s: &str) -> Role {
    match s {
        "owner" => Role::Owner,
        "admin" => Role::Admin,
        _ => Role::Member,
    }
}

/// What [`LocalVault::store_shared_vault`] stores: verified and ready to open.
struct SharedVaultRecord {
    id: String,
    org_id: String,
    name: Option<String>,
    directory: bool,
    access: Access,
    rotation_due: bool,
    current: [u8; 16],
    /// `(key_id, wrapped)` for every generation, all grant-checked.
    keys: Vec<(Vec<u8>, Vec<u8>)>,
    created_at: i64,
}

impl LocalVault {
    /// Organizations on this device.
    pub fn orgs(&self) -> crate::Result<Vec<OrgInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, role, status, root_account, root_enc, root_sign FROM orgs ORDER BY name, id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, Vec<u8>>(5)?,
                r.get::<_, Vec<u8>>(6)?,
            ))
        })?;
        rows.map(|row| {
            let (id, name, role, status, root, enc, sign) = row?;
            let keys = PublicKeys {
                enc: enc
                    .try_into()
                    .map_err(|_| Error::Corrupt("pinned key".into()))?,
                sign: sign
                    .try_into()
                    .map_err(|_| Error::Corrupt("pinned key".into()))?,
            };
            Ok(OrgInfo {
                id,
                name,
                role: parse_role(&role),
                status: if status == "confirmed" {
                    MemberStatus::Confirmed
                } else {
                    MemberStatus::Accepted
                },
                root_fingerprint: crypto::fingerprint(&root, &keys),
            })
        })
        .collect()
    }

    fn org_root(&self, org: &str) -> crate::Result<Option<Root>> {
        let row: Option<(String, Vec<u8>, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT root_account, root_enc, root_sign FROM orgs WHERE id = ?1",
                [org],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        row.map(|(account_id, enc, sign)| {
            Ok(Root {
                account_id,
                keys: PublicKeys {
                    enc: enc
                        .try_into()
                        .map_err(|_| Error::Corrupt("pinned key".into()))?,
                    sign: sign
                        .try_into()
                        .map_err(|_| Error::Corrupt("pinned key".into()))?,
                },
            })
        })
        .transpose()
    }

    /// Records an organization; its root is pinned the first time and never replaced.
    fn save_org(
        &self,
        id: &str,
        name: &str,
        role: Role,
        status: MemberStatus,
        root: &Root,
    ) -> crate::Result<()> {
        let status = if status == MemberStatus::Confirmed {
            "confirmed"
        } else {
            "accepted"
        };
        self.conn.execute(
            "INSERT INTO orgs (id, name, role, status, root_account, root_enc, root_sign) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT (id) DO UPDATE SET name = excluded.name, role = excluded.role, status = excluded.status",
            params![id, name, role_str(role), status, root.account_id, root.keys.enc.as_slice(), root.keys.sign.as_slice()],
        )?;
        Ok(())
    }

    fn pinned(&self) -> crate::Result<HashMap<String, PublicKeys>> {
        let rows: Vec<(String, Vec<u8>, Vec<u8>)> = self
            .conn
            .prepare("SELECT account_id, enc, sign FROM pinned_keys")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        rows.into_iter()
            .map(|(a, enc, sign)| {
                Ok((
                    a,
                    PublicKeys {
                        enc: enc
                            .try_into()
                            .map_err(|_| Error::Corrupt("pinned key".into()))?,
                        sign: sign
                            .try_into()
                            .map_err(|_| Error::Corrupt("pinned key".into()))?,
                    },
                ))
            })
            .collect()
    }

    /// Emails of the accounts this device verified, people who since left included (names for
    /// an organization's activity log).
    pub fn known_emails(&self) -> crate::Result<HashMap<String, String>> {
        Ok(self
            .conn
            .prepare("SELECT account_id, email FROM pinned_keys WHERE email IS NOT NULL")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// Pins an account's verified keys (a different pin already there is an error).
    fn pin(&mut self, account: &str, keys: &PublicKeys, email: Option<&str>) -> crate::Result<()> {
        if let Some(existing) = self.pinned()?.get(account)
            && existing != keys
        {
            return Err(untrusted(format!("the keys of account {account} changed")));
        }
        self.conn.execute(
            "INSERT INTO pinned_keys (account_id, enc, sign, email) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (account_id) DO UPDATE SET email = COALESCE(excluded.email, pinned_keys.email)",
            params![account, keys.enc.as_slice(), keys.sign.as_slice(), email],
        )?;
        if let Some(k) = self.keys.as_mut() {
            k.pins.insert(account.to_owned(), keys.sign);
        }
        Ok(())
    }

    /// Stores (or updates) a shared vault and opens its keys.
    fn store_shared_vault(&mut self, r: SharedVaultRecord) -> crate::Result<()> {
        let keys = self.unlocked()?;
        if r.id == keys.vault_id {
            return Err(untrusted(
                "the server offered the personal vault as a shared one",
            ));
        }
        let opened = r
            .keys
            .iter()
            .map(|(id, w)| {
                let k = VaultKey::open(&keys.account, w)?;
                if k.id()[..] != id[..] {
                    return Err(untrusted("a sealed vault key doesn't match its key id"));
                }
                Ok(k)
            })
            .collect::<crate::Result<Vec<_>>>()?;
        let current_wrapped = r
            .keys
            .iter()
            .find(|(id, _)| id[..] == r.current)
            .map(|(_, w)| w.clone())
            .ok_or_else(|| untrusted("the vault's current key isn't sealed to this account"))?;
        let personal: bool = self
            .conn
            .query_row(
                "SELECT personal FROM vaults WHERE id = ?1",
                [&r.id],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(false);
        if personal {
            return Err(untrusted(
                "the server offered the personal vault as a shared one",
            ));
        }
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO vaults (id, key_id, wrapped_vault_key, created_at, personal, org_id, permission, name, rotation_due, directory)
             VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT (id) DO UPDATE SET key_id = excluded.key_id, wrapped_vault_key = excluded.wrapped_vault_key,
                 org_id = excluded.org_id, permission = excluded.permission, name = excluded.name,
                 rotation_due = excluded.rotation_due, directory = excluded.directory",
            params![r.id, r.current.as_slice(), current_wrapped, r.created_at, r.org_id, r.access.as_str(), r.name, r.rotation_due, r.directory],
        )?;
        tx.execute("DELETE FROM vault_keys WHERE vault_id = ?1", [&r.id])?;
        for (id, w) in &r.keys {
            tx.execute(
                "INSERT INTO vault_keys (vault_id, key_id, wrapped) VALUES (?1, ?2, ?3)",
                params![r.id, id, w],
            )?;
        }
        tx.commit()?;
        if let Some(k) = self.keys.as_mut() {
            k.shared.insert(
                r.id,
                Ring {
                    current: r.current,
                    keys: opened,
                    access: r.access,
                },
            );
        }
        Ok(())
    }

    /// Forgets shared vaults (and their items) not in `keep`: access lost, or left.
    fn shared_vault_ids(&self) -> crate::Result<Vec<String>> {
        Ok(self
            .conn
            .prepare("SELECT id FROM vaults WHERE personal = 0")?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    }

    fn drop_shared_vaults_except(&mut self, keep: &HashSet<String>) -> crate::Result<usize> {
        let ids: Vec<String> = self
            .conn
            .prepare("SELECT id FROM vaults WHERE personal = 0")?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let mut n = 0;
        for id in ids.iter().filter(|id| !keep.contains(*id)) {
            self.conn
                .execute("DELETE FROM vaults WHERE id = ?1", [id])?;
            if let Some(k) = self.keys.as_mut() {
                k.shared.remove(id);
            }
            n += 1;
        }
        Ok(n)
    }

    /// Forgets the organizations not in `keep`; returns their names.
    fn drop_orgs_except(&mut self, keep: &HashSet<String>) -> crate::Result<Vec<String>> {
        let orgs: Vec<(String, String)> = self
            .conn
            .prepare("SELECT id, name FROM orgs ORDER BY name")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let mut gone = Vec::new();
        for (id, name) in orgs.into_iter().filter(|(id, _)| !keep.contains(id)) {
            self.conn.execute("DELETE FROM orgs WHERE id = ?1", [&id])?;
            gone.push(name);
        }
        Ok(gone)
    }

    fn my_id(&self) -> crate::Result<String> {
        self.sync_info()?
            .map(|i| i.config.account_id)
            .ok_or_else(|| Error::Invalid("turn on sync first".into()))
    }

    /// The vault's key ring as `(key_id, VaultKey)` pairs, sealed afresh to `to`.
    fn seal_ring(
        &self,
        vault: &str,
        to_id: &str,
        to: &PublicKeys,
    ) -> crate::Result<Vec<MemberVaultKey>> {
        let keys = self.unlocked()?;
        let ring = keys.shared.get(vault).ok_or(Error::UnknownVault)?;
        ring.keys
            .iter()
            .map(|k| {
                let wrapped = k.seal_to(&to.enc)?;
                Ok(MemberVaultKey {
                    vault_id: vault.to_owned(),
                    key_id: B64(k.id().to_vec()),
                    grant_sig: B64(crypto::sign_grant(
                        &keys.account,
                        vault,
                        k.id(),
                        to_id,
                        &wrapped,
                    )
                    .to_vec()),
                    wrapped_vault_key: B64(wrapped),
                })
            })
            .collect()
    }

    /// `(key_id, wrapped)` of every generation of a shared vault.
    fn ring_rows(&self, vault: &str) -> crate::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        Ok(self
            .conn
            .prepare("SELECT key_id, wrapped FROM vault_keys WHERE vault_id = ?1")?
            .query_map([vault], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?)
    }

    fn org_vault_ids(&self, org: &str) -> crate::Result<Vec<String>> {
        Ok(self
            .conn
            .prepare("SELECT id FROM vaults WHERE personal = 0 AND org_id = ?1")?
            .query_map([org], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// The organization's member key directories on this device, the one in use (lowest id)
    /// first: two admins may each create one at the same time.
    fn directories(&self, org: &str) -> crate::Result<Vec<String>> {
        Ok(self
            .conn
            .prepare("SELECT id FROM vaults WHERE org_id = ?1 AND directory = 1 ORDER BY id")?
            .query_map([org], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// Members' SSH public keys published in the organization's directory, each checked against
    /// the member's own signature with their verified (or pinned) key.
    pub fn member_keys(&self, org: &str) -> crate::Result<Vec<MemberKeyEntry>> {
        let me = self.my_id()?;
        let mine = self.unlocked()?.sign_pub;
        let pins = self.pinned()?;
        let dirs = self.directories(org)?;
        let mut out = Vec::new();
        for item in self.items()? {
            let ItemData::MemberKey(k) = item.data else {
                continue;
            };
            if !dirs.contains(&item.vault_id) {
                continue;
            }
            let signer = if k.account_id == me {
                Some(mine)
            } else {
                pins.get(&k.account_id).map(|p| p.sign)
            };
            let verified = signer.is_some_and(|pk| {
                from_hex(&k.sig).is_some_and(|sig| {
                    crypto::verify_member_key(&pk, org, &k.account_id, &k.public_key, &sig).is_ok()
                })
            });
            out.push(MemberKeyEntry {
                id: item.id,
                mine: k.account_id == me,
                account_id: k.account_id,
                public_key: k.public_key,
                label: k.label,
                verified,
            });
        }
        out.sort_by(|a, b| (&a.account_id, &a.label).cmp(&(&b.account_id, &b.label)));
        Ok(out)
    }

    /// Publishes one of this account's SSH public keys (OpenSSH `type base64 [comment]`) in the
    /// organization's directory, signed by this account; the next sync shares it. Publishing a
    /// key again returns the existing entry.
    pub fn publish_member_key(
        &mut self,
        org: &str,
        public_key: &str,
        label: &str,
    ) -> crate::Result<String> {
        let parts: Vec<&str> = public_key.split_ascii_whitespace().take(2).collect();
        let [kind, body] = parts[..] else {
            return Err(Error::Invalid("not an OpenSSH public key".into()));
        };
        let public_key = format!("{kind} {body}");
        if let Some(existing) = self
            .member_keys(org)?
            .into_iter()
            .find(|k| k.mine && k.public_key == public_key)
        {
            return Ok(existing.id);
        }
        let dir = self.directories(org)?.into_iter().next().ok_or_else(|| {
            Error::Invalid("the organization has no member key directory yet; sync first".into())
        })?;
        let me = self.my_id()?;
        let sig = crypto::sign_member_key(&self.unlocked()?.account, org, &me, &public_key);
        let item = self.upsert_in(
            &dir,
            None,
            ItemData::MemberKey(MemberKey {
                account_id: me,
                public_key,
                label: label.trim().to_owned(),
                sig: to_hex(&sig),
            }),
        )?;
        Ok(item.id)
    }
}

/// A public key in an organization's member key directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberKeyEntry {
    /// The directory item (to unpublish it, delete it).
    pub id: String,
    pub account_id: String,
    /// OpenSSH `type base64`.
    pub public_key: String,
    pub label: String,
    /// Signed by that member (checked with their verified key).
    pub verified: bool,
    pub mine: bool,
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

// ------------------------------------------------------------------ refresh

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RefreshReport {
    pub orgs: usize,
    pub vaults: usize,
    /// Shared vaults this device no longer has access to (their local copies were removed).
    pub dropped: usize,
    /// Organizations this account is no longer in, by name, that this device didn't leave or
    /// delete itself: it left on another device, an admin removed it, or the owner deleted the
    /// organization. Their vaults left this device; the app says so.
    pub orgs_gone: Vec<String>,
    /// Something the app shows changed: an organization, a vault, an access level, a name.
    pub changed: bool,
    /// Problems with one organization or vault; the rest went on.
    pub errors: Vec<String>,
    /// Organizations whose vaults wait on this device, and why (they stay here meanwhile).
    pub held: Vec<(String, Hold)>,
    /// Other devices waiting for this account's approval, per organization (with device
    /// approval on): everyone's for owners and admins, the member's own new devices otherwise.
    pub approvals_waiting: Vec<(String, usize)>,
    /// Members this device (an owner's or admin's) certified again: the admin who confirmed them
    /// had left.
    pub recertified: usize,
    /// Organizations that ask members to publish their SSH keys, where this account has none
    /// published.
    pub member_keys_due: Vec<String>,
    /// Every vault this account can open, and its latest revision (`GET /vaults`): a vault this
    /// device has up to there needn't be pulled. Empty on a server without `sharing`.
    pub heads: HashMap<String, i64>,
}

/// What one sync round keeps for the next: the server's capabilities for an hour, and what each
/// organization was as of its revision (`rev` in `GET /orgs`). A quiet round then asks for the
/// lists only (organizations and vaults); one that finds an organization changed fetches it
/// again. Verification runs every round either way (this device's pins may have changed).
#[derive(Default)]
pub struct RoundCache {
    capabilities: Option<(std::time::Instant, mg_sync::Capabilities)>,
    orgs: HashMap<String, OrgSnapshot>,
}

impl RoundCache {
    /// How many organizations the next round can take as they are (unless they changed).
    pub fn kept(&self) -> usize {
        self.orgs.len()
    }
}

/// An organization as fetched at `rev`.
#[derive(Clone)]
struct OrgSnapshot {
    rev: u64,
    org: mg_sync::Org,
    members: Option<Vec<Member>>,
    devices: Option<Vec<mg_sync::DeviceApproval>>,
    directory: Option<Vec<mg_sync::VaultMember>>,
}

const CAPABILITIES_FOR: std::time::Duration = std::time::Duration::from_secs(3600);

async fn trust_for(vault: &SharedVault, client: &SyncClient, org: &str) -> Result<Trust> {
    let info = client.org(org).await?;
    let members = client.members(org).await?;
    trust_from(vault, org, &info, &members)
}

/// Verifies an organization's members from what the server said (`info`, `members`) against
/// what this device pinned, and pins the ones that check out.
fn trust_from(
    vault: &SharedVault,
    org: &str,
    info: &mg_sync::Org,
    members: &[Member],
) -> Result<Trust> {
    let (root, pins) = {
        let v = lock(vault)?;
        (v.org_root(org)?, v.pinned()?)
    };
    let root = root.ok_or_else(|| untrusted("this device hasn't joined that organization"))?;
    let trust = verify_org(org, &root, &info.owner_chain, members, &pins)?;
    let mut v = lock(vault)?;
    for m in members {
        if let Some(keys) = trust.keys.get(&m.account_id) {
            v.pin(&m.account_id, keys, Some(&m.email))?;
        }
    }
    Ok(trust)
}

/// Brings organizations and shared vaults onto this device: verifies members and sealed keys,
/// stores what checks out and removes vaults this account lost. (The sync round that follows
/// finishes rotations.) Does nothing on a server without `sharing`.
pub async fn refresh(vault: &SharedVault, client: &SyncClient) -> Result<RefreshReport> {
    refresh_with(vault, client, &mut RoundCache::default()).await
}

/// [`refresh`], keeping what's unchanged from one round to the next in `cache` (one per signed-in
/// account).
pub async fn refresh_with(
    vault: &SharedVault,
    client: &SyncClient,
    cache: &mut RoundCache,
) -> Result<RefreshReport> {
    let mut report = RefreshReport::default();
    let capabilities = match cache.capabilities.take() {
        Some((at, c)) if at.elapsed() < CAPABILITIES_FOR => (at, c),
        _ => (std::time::Instant::now(), client.capabilities().await?),
    };
    let sharing = capabilities.1.features.sharing.is_some();
    cache.capabilities = Some(capabilities);
    if !sharing {
        cache.orgs.clear();
        return Ok(report);
    }
    // This round's snapshots replace the last round's: organizations left behind are forgotten.
    let mut last = std::mem::take(&mut cache.orgs);
    let mut fetched: HashMap<String, OrgSnapshot> = HashMap::new();
    // Organizations this round wrote to, or had trouble with: fetched afresh next round.
    let mut unsettled: HashSet<String> = HashSet::new();
    let snapshot = || -> Result<_> {
        let v = lock(vault)?;
        Ok((v.vaults()?, v.orgs()?))
    };
    let before = snapshot()?;
    let me = lock(vault)?.my_id()?;
    let memberships = client.orgs().await?;
    let mut trusts: HashMap<String, Trust> = HashMap::new();
    let mut known = HashSet::new();
    let mut approving = Vec::new();
    let mut keys_required = Vec::new();
    let mut totp_required = Vec::new();
    for m in &memberships {
        known.insert(m.id.clone());
        let mut snap = match last.remove(&m.id).filter(|s| m.rev == Some(s.rev)) {
            Some(s) => s,
            None => match client.org(&m.id).await {
                Ok(org) => OrgSnapshot {
                    rev: m.rev.unwrap_or_default(),
                    org,
                    members: None,
                    devices: None,
                    directory: None,
                },
                Err(e) => {
                    report.errors.push(format!("{}: {e}", m.name));
                    continue;
                }
            },
        };
        let org = snap.org.clone();
        if m.status == MemberStatus::Confirmed && org.policies.require_device_approval {
            approving.push(m);
        }
        if m.status == MemberStatus::Confirmed && org.policies.require_member_keys == Some(true) {
            keys_required.push(m);
        }
        if m.status == MemberStatus::Confirmed && org.policies.require_totp {
            totp_required.push(m.id.clone());
        }
        {
            let v = lock(vault)?;
            let root = match v.org_root(&m.id)? {
                Some(r) => r,
                // Joined on another device: trust the root on first sight here.
                None => {
                    let first = org
                        .owner_chain
                        .first()
                        .ok_or_else(|| untrusted("the organization has no owner"))?;
                    Root {
                        account_id: first.account_id.clone(),
                        keys: link_keys(first)?,
                    }
                }
            };
            v.save_org(&m.id, &org.name, m.role, m.status, &root)?;
        }
        report.orgs += 1;
        if m.status != MemberStatus::Confirmed {
            fetched.insert(m.id.clone(), snap);
            continue;
        }
        let members = match snap.members.take() {
            Some(members) => Ok(members),
            None => client.members(&m.id).await.map_err(AccountError::from),
        };
        let trust = members.and_then(|members| {
            let trust = trust_from(vault, &m.id, &org, &members);
            snap.members = Some(members);
            trust
        });
        fetched.insert(m.id.clone(), snap);
        match trust {
            Ok(t) => {
                // Members whose certifying admin left: certify them again, so devices that never
                // verified them can.
                if m.role.is_admin() {
                    for account in t.pinned_only.iter().filter(|a| **a != me) {
                        unsettled.insert(m.id.clone());
                        match recertify(vault, client, &m.id, account, None).await {
                            Ok(true) => report.recertified += 1,
                            // A server without it: nothing to do here (members stay trusted
                            // where they were verified).
                            Ok(false) => break,
                            Err(e) => report
                                .errors
                                .push(format!("{}: certifying a member again: {e}", m.name)),
                        }
                    }
                }
                trusts.insert(m.id.clone(), t);
            }
            Err(e) => {
                unsettled.insert(m.id.clone());
                report.errors.push(format!("{}: {e}", m.name));
            }
        }
    }
    report.orgs_gone = lock(vault)?.drop_orgs_except(&known)?;

    let vaults = client.list_vaults().await?;
    report.heads = vaults.iter().map(|v| (v.id.clone(), v.head_rev)).collect();
    // An organization that requires two-step verification leaves its vaults out of the list for
    // an account without it, without saying why. When none of its vaults is listed (it may have
    // none for this account yet), the account says whether that's the reason.
    let totp_unlisted: Vec<String> = totp_required
        .into_iter()
        .filter(|org| !vaults.iter().any(|v| v.org_id.as_ref() == Some(org)))
        .collect();
    if !totp_unlisted.is_empty() {
        match client.account().await {
            Ok(account) if !account.totp_enabled => {
                for org in totp_unlisted {
                    note_held(&mut report.held, org, Hold::Totp);
                }
            }
            Ok(_) => {}
            Err(e) => report.errors.push(format!("two-step verification: {e}")),
        }
    }
    // Former members this device verified: their grants and vault names stay valid.
    let pins = lock(vault)?.pinned()?;
    let mut keep = HashSet::new();
    for sv in vaults.into_iter().filter(|v| v.org_id.is_some()) {
        let org = sv.org_id.clone().expect("filtered");
        keep.insert(sv.id.clone());
        // An organization that didn't verify keeps its local copies, untouched.
        let Some(trust) = trusts.get(&org) else {
            continue;
        };
        match shared_record(&me, &sv, &org, trust, &pins) {
            Ok(mut record) => {
                let mut v = lock(vault)?;
                if let Some(meta) = sv.meta.as_ref().and_then(|m| {
                    vault_meta(
                        &v,
                        &sv.id,
                        &record,
                        m,
                        sv.created_by.as_deref(),
                        trust,
                        &pins,
                    )
                }) {
                    record.name = Some(meta.name);
                    record.directory = meta.directory;
                }
                match v.store_shared_vault(record) {
                    Ok(()) => report.vaults += 1,
                    Err(e) => report.errors.push(format!("vault {}: {e}", sv.id)),
                }
            }
            Err(e) => report.errors.push(format!("vault {}: {e}", sv.id)),
        }
    }
    // A vault missing from the list may only be held back (single sign-on, device approval or
    // two-step verification required): ask about each one before dropping its local copy.
    let unlisted: Vec<String> = lock(vault)?
        .shared_vault_ids()?
        .into_iter()
        .filter(|id| !keep.contains(id))
        .collect();
    for id in unlisted {
        match client.vault(&id).await {
            Err(mg_sync::Error::Api { status: 404, .. }) => {}
            Err(e) if held(&e).is_some() => {
                let (org, why) = held(&e).expect("held");
                note_held(&mut report.held, org, why);
                keep.insert(id);
            }
            // Listed late, held back by a server that doesn't say why, or unknown: keep it.
            _ => {
                keep.insert(id);
            }
        }
    }
    // With device approval on, a new device learns where it stands from the requests (the
    // vault list leaves out what waits, and files the request).
    let device = lock(vault)?.sync_info()?.map(|i| i.config.device_id);
    for m in approving {
        let snap = fetched.get_mut(&m.id);
        let rows = match snap.as_ref().and_then(|s| s.devices.clone()) {
            Some(rows) => rows,
            None => match client.org_devices(&m.id, None).await {
                Ok(rows) => {
                    if let Some(s) = snap {
                        s.devices = Some(rows.clone());
                    }
                    rows
                }
                Err(e) => {
                    unsettled.insert(m.id.clone());
                    report
                        .errors
                        .push(format!("{}: device approvals: {e}", m.name));
                    continue;
                }
            },
        };
        let this = |r: &&mg_sync::DeviceApproval| {
            r.account_id == me && Some(&r.device_id) == device.as_ref()
        };
        match rows.iter().find(this).map(|r| r.status.as_str()) {
            Some("pending") => note_held(&mut report.held, m.id.clone(), Hold::Approval),
            Some("denied") => note_held(&mut report.held, m.id.clone(), Hold::Denied),
            _ => {}
        }
        let waiting = rows
            .iter()
            .filter(|r| r.status == "pending" && !this(r))
            .count();
        if waiting > 0 {
            report.approvals_waiting.push((m.id.clone(), waiting));
        }
    }
    report.dropped = lock(vault)?.drop_shared_vaults_except(&keep)?;
    // Owners and admins keep the member key directory: there is one, and every member can write.
    for m in &memberships {
        if m.status != MemberStatus::Confirmed || !m.role.is_admin() {
            continue;
        }
        // Held back, the directory waits like the organization's other vaults.
        if report.held.iter().any(|(org, _)| *org == m.id) {
            continue;
        }
        let Some(trust) = trusts.get(&m.id) else {
            continue;
        };
        let Some(snap) = fetched.get_mut(&m.id) else {
            continue;
        };
        match keep_directory(vault, client, &m.id, trust, snap).await {
            Ok(false) => {}
            Ok(true) => {
                unsettled.insert(m.id.clone());
            }
            Err(e) => {
                unsettled.insert(m.id.clone());
                match e {
                    AccountError::Held(org, why) => note_held(&mut report.held, org, why),
                    e => report
                        .errors
                        .push(format!("{}: member key directory: {e}", m.name)),
                }
            }
        }
    }
    for m in keys_required {
        if !lock(vault)?.member_keys(&m.id)?.iter().any(|k| k.mine) {
            report.member_keys_due.push(m.id.clone());
        }
    }
    // Held back, an organization's next round asks again (the wait may be over).
    for (org, _) in &report.held {
        unsettled.insert(org.clone());
    }
    cache.orgs = memberships
        .iter()
        .filter(|m| m.rev.is_some() && !unsettled.contains(&m.id))
        .filter_map(|m| fetched.remove(&m.id).map(|s| (m.id.clone(), s)))
        .collect();
    report.changed = snapshot()? != before;
    Ok(report)
}

/// Certifies a confirmed member again (an owner or admin): when the admin who confirmed them
/// left, devices that never verified them can't trust them otherwise. `fingerprint` is what the
/// user compared with them; without it, this device's earlier verification (its pin) stands in.
/// `false`: the server can't store a new certificate (it predates the endpoint).
pub async fn recertify(
    vault: &SharedVault,
    client: &SyncClient,
    org: &str,
    account: &str,
    fingerprint: Option<&str>,
) -> Result<bool> {
    let list = client.members(org).await?;
    let target = list
        .iter()
        .find(|m| m.account_id == account)
        .ok_or_else(|| Error::NotFound(account.to_owned()))?;
    if target.status != MemberStatus::Confirmed {
        return Err(Error::Invalid("not confirmed yet: confirm them instead".into()).into());
    }
    let keys = member_keys(target)?;
    let cert = {
        let v = lock(vault)?;
        let pins = v.pinned()?;
        let pinned = pins.get(account);
        match fingerprint {
            Some(f) => {
                if crypto::fingerprint(account, &keys) != f.trim() {
                    return Err(untrusted(
                        "their keys don't match the fingerprint you compared; compare again",
                    )
                    .into());
                }
                if pinned.is_some_and(|p| *p != keys) {
                    return Err(untrusted("this account's keys changed").into());
                }
            }
            None if pinned != Some(&keys) => {
                return Err(untrusted("compare their fingerprint with them first").into());
            }
            None => {}
        }
        B64(crypto::certify(
            &v.unlocked()?.account,
            CertKind::Member,
            org,
            account,
            &keys,
        )
        .to_vec())
    };
    match client
        .recertify_member(org, account, &MemberCertificate { member_cert: cert })
        .await
    {
        Ok(_) => {}
        Err(mg_sync::Error::Api {
            status: 404 | 405, ..
        }) => return Ok(false),
        Err(e) => return Err(e.into()),
    }
    lock(vault)?.pin(account, &keys, Some(&target.email))?;
    Ok(true)
}

/// Creates the organization's member key directory if it has none, and gives every confirmed
/// member who can't write to it `write`.
/// `true`: it changed something on the server (a directory made, a member granted).
async fn keep_directory(
    vault: &SharedVault,
    client: &SyncClient,
    org: &str,
    trust: &Trust,
    snap: &mut OrgSnapshot,
) -> Result<bool> {
    let Some(dir) = lock(vault)?.directories(org)?.into_iter().next() else {
        create_vault_with(vault, client, org, DIRECTORY_NAME, true).await?;
        return Ok(true);
    };
    let writers = match &snap.directory {
        Some(writers) => writers.clone(),
        None => {
            let writers = client.vault_members(&dir).await?;
            snap.directory = Some(writers.clone());
            writers
        }
    };
    let can: HashSet<String> = writers
        .into_iter()
        .filter(|m| m.permission >= Permission::Write)
        .map(|m| m.account_id)
        .collect();
    let members = match &snap.members {
        Some(members) => members.clone(),
        None => client.members(org).await?,
    };
    let mut wrote = false;
    for m in members {
        if m.status != MemberStatus::Confirmed || can.contains(&m.account_id) {
            continue;
        }
        // Members this device can't verify yet wait for a later round.
        if let Some(keys) = trust.keys.get(&m.account_id) {
            grant(vault, client, &dir, &m.account_id, keys, Access::Write).await?;
            wrote = true;
        }
    }
    Ok(wrote)
}

/// Checks every key generation's grant signature.
///
/// The current generation must be granted by a verified member, or by a former member this
/// device verified (`pins`) while a rotation is due: after someone leaves, their grants stand
/// until an admin rotates, which needs the ring. Older generations only open older items: a
/// former member's grant is fine there, and a generation that can't be verified is left out
/// (its items stay unreadable here until they're re-sealed).
fn shared_record(
    me: &str,
    sv: &mg_sync::Vault,
    org: &str,
    trust: &Trust,
    pins: &HashMap<String, PublicKeys>,
) -> core::result::Result<SharedVaultRecord, Error> {
    let current: [u8; 16] = sv
        .key_id
        .0
        .as_slice()
        .try_into()
        .map_err(|_| untrusted("malformed key id"))?;
    let mut keys = Vec::new();
    for g in &sv.keys {
        let key_id: [u8; 16] = g
            .key_id
            .0
            .as_slice()
            .try_into()
            .map_err(|_| untrusted("malformed key id"))?;
        let is_current = key_id == current;
        let checked = (|| {
            let grant = g
                .grant
                .as_ref()
                .ok_or_else(|| untrusted("a shared vault key has no grant signature"))?;
            let former_ok = !is_current || sv.rotation_due;
            let signer = trust
                .keys
                .get(&grant.signer_id)
                .or_else(|| pins.get(&grant.signer_id).filter(|_| former_ok))
                .ok_or_else(|| {
                    untrusted("a vault key was sealed by an account this device can't verify")
                })?;
            crypto::verify_grant(
                &signer.sign,
                &sv.id,
                &key_id,
                me,
                &g.wrapped_vault_key.0,
                &grant.sig.0,
            )
            .map_err(|_| untrusted("a vault key's grant signature doesn't verify"))
        })();
        match checked {
            Ok(()) => keys.push((key_id.to_vec(), g.wrapped_vault_key.0.clone())),
            Err(e) if is_current => return Err(e),
            Err(_) => {}
        }
    }
    Ok(SharedVaultRecord {
        id: sv.id.clone(),
        org_id: org.to_owned(),
        name: None,
        directory: false,
        access: sv.permission.map(access_of).unwrap_or(Access::Read),
        rotation_due: sv.rotation_due,
        current,
        keys,
        created_at: now(),
    })
}

/// The vault's encrypted `meta`, if it opens and its creator verifies.
fn vault_meta(
    v: &LocalVault,
    vault: &str,
    record: &SharedVaultRecord,
    meta: &B64,
    created_by: Option<&str>,
    trust: &Trust,
    pins: &HashMap<String, PublicKeys>,
) -> Option<VaultMeta> {
    let keys = v.unlocked().ok()?;
    let key_id = envelope_key_id(&meta.0).ok()?;
    let wrapped = record.keys.iter().find(|(id, _)| id[..] == *key_id)?;
    let vk = VaultKey::open(&keys.account, &wrapped.1).ok()?;
    let author = match created_by {
        // A vault keeps its name after its creator leaves.
        Some(a) if Some(a) != keys.account_id.as_deref() => {
            trust.keys.get(a).or_else(|| pins.get(a))?.sign
        }
        _ => keys.sign_pub,
    };
    let plain = envelope::open(&vk, &author, &context(vault, META_ID), &meta.0).ok()?;
    serde_json::from_slice::<VaultMeta>(&plain).ok()
}

// ------------------------------------------------------------------ organizations

/// Creates an organization with this account as its owner and trust root.
pub async fn create_org(vault: &SharedVault, client: &SyncClient, name: &str) -> Result<String> {
    let id = Ulid::generate().to_string();
    let (me, mine) = {
        let v = lock(vault)?;
        (v.my_id()?, v.unlocked()?.account.public())
    };
    let org = client
        .create_org(&CreateOrg {
            id: id.clone(),
            name: name.trim().to_owned(),
        })
        .await?;
    let root = Root {
        account_id: me,
        keys: mine,
    };
    // The server must have put this account's real keys at the root.
    verify_owners(&id, &root, &org.owner_chain)?;
    lock(vault)?.save_org(&id, &org.name, Role::Owner, MemberStatus::Confirmed, &root)?;
    // If this fails, the next refresh creates it.
    let _ = create_vault_with(vault, client, &id, DIRECTORY_NAME, true).await;
    Ok(id)
}

/// Creates a vault in an organization, its key sealed to every owner and admin.
pub async fn create_vault(
    vault: &SharedVault,
    client: &SyncClient,
    org: &str,
    name: &str,
) -> Result<String> {
    create_vault_with(vault, client, org, name, false).await
}

async fn create_vault_with(
    vault: &SharedVault,
    client: &SyncClient,
    org: &str,
    name: &str,
    directory: bool,
) -> Result<String> {
    let members = client.members(org).await?;
    let trust = trust_for(vault, client, org).await?;
    let (req, record) = {
        let v = lock(vault)?;
        let me = v.my_id()?;
        let keys = v.unlocked()?;
        let mut recipients: Vec<(String, PublicKeys)> = Vec::new();
        for m in members
            .iter()
            .filter(|m| m.status == MemberStatus::Confirmed && m.role.is_admin())
        {
            let k = trust
                .keys
                .get(&m.account_id)
                .ok_or_else(|| untrusted(format!("can't verify the keys of {}", m.email)))?;
            recipients.push((m.account_id.clone(), *k));
        }
        if !recipients.iter().any(|(a, _)| *a == me) {
            recipients.push((me.clone(), keys.account.public()));
        }
        let id = Ulid::generate().to_string();
        let vk = VaultKey::generate().map_err(Error::from)?;
        let meta = serde_json::to_vec(&VaultMeta {
            name: name.trim().to_owned(),
            directory,
        })
        .map_err(|e| Error::Invalid(e.to_string()))?;
        let meta = envelope::seal(&vk, &keys.account, &context(&id, META_ID), &meta)
            .map_err(Error::from)?;
        let mut sealed = Vec::new();
        for (account, k) in &recipients {
            let wrapped = vk.seal_to(&k.enc).map_err(Error::from)?;
            sealed.push(SealedFor {
                account_id: account.clone(),
                grant_sig: B64(
                    crypto::sign_grant(&keys.account, &id, vk.id(), account, &wrapped).to_vec(),
                ),
                wrapped_vault_key: B64(wrapped),
            });
        }
        let mine = sealed
            .iter()
            .find(|s| s.account_id == me)
            .expect("added above")
            .wrapped_vault_key
            .clone();
        let record = SharedVaultRecord {
            id: id.clone(),
            org_id: org.to_owned(),
            name: Some(name.trim().to_owned()),
            directory,
            access: Access::Manage,
            rotation_due: false,
            current: *vk.id(),
            keys: vec![(vk.id().to_vec(), mine.0.clone())],
            created_at: now(),
        };
        let req = CreateVault {
            id,
            key_id: B64(vk.id().to_vec()),
            wrapped_vault_key: mine,
            meta: Some(B64(meta)),
            org_id: Some(org.to_owned()),
            keys: sealed,
        };
        (req, record)
    };
    client.create_vault(&req).await?;
    lock(vault)?.store_shared_vault(record)?;
    Ok(req.id)
}

/// What an invite token is for, before accepting it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitePreview {
    pub org_id: String,
    pub org_name: String,
    pub email: String,
    pub role: Role,
    pub inviter_email: String,
    /// The current owner's fingerprint, to compare with them out of band.
    pub owner_fingerprint: String,
    pub expires_at: String,
}

pub async fn preview_invite(client: &SyncClient, token: &str) -> Result<InvitePreview> {
    let info = client.invite_info(token.trim()).await?;
    let first = info
        .owner_chain
        .first()
        .ok_or_else(|| untrusted("the organization has no owner"))?;
    let root = Root {
        account_id: first.account_id.clone(),
        keys: link_keys(first)?,
    };
    let owners = verify_owners(&info.org_id, &root, &info.owner_chain)?;
    let (owner_id, owner_keys) = owners.last().expect("not empty");
    Ok(InvitePreview {
        org_id: info.org_id,
        org_name: info.org_name,
        email: info.email,
        role: info.role,
        inviter_email: info.inviter_email,
        owner_fingerprint: crypto::fingerprint(owner_id, owner_keys),
        expires_at: info.expires_at,
    })
}

/// Joins an organization and pins its root. `owner_fingerprint` is what the user was shown
/// (and compared): if the organization's keys changed since, nothing happens.
pub async fn accept_invite(
    vault: &SharedVault,
    client: &SyncClient,
    token: &str,
    owner_fingerprint: &str,
) -> Result<String> {
    let token = token.trim();
    let info = client.invite_info(token).await?;
    let first = info
        .owner_chain
        .first()
        .ok_or_else(|| untrusted("the organization has no owner"))?;
    let root = Root {
        account_id: first.account_id.clone(),
        keys: link_keys(first)?,
    };
    let owners = verify_owners(&info.org_id, &root, &info.owner_chain)?;
    let (owner_id, owner_keys) = owners.last().expect("not empty");
    if crypto::fingerprint(owner_id, owner_keys) != owner_fingerprint.trim() {
        return Err(untrusted(
            "the organization's keys changed while you were looking; check the fingerprint again",
        )
        .into());
    }
    if let Some(pinned) = lock(vault)?.org_root(&info.org_id)?
        && pinned != root
    {
        return Err(untrusted("this organization's root key changed").into());
    }
    let m = client.accept_invite(token).await?;
    lock(vault)?.save_org(&m.id, &m.name, m.role, m.status, &root)?;
    Ok(m.id)
}

pub async fn invite(
    client: &SyncClient,
    org: &str,
    email: &str,
    role: Role,
    vaults: Vec<(String, Access)>,
) -> Result<Invite> {
    Ok(client
        .invite(
            org,
            &CreateInvite {
                email: email.trim().to_owned(),
                role,
                vaults: vaults
                    .into_iter()
                    .map(|(vault_id, a)| VaultGrant {
                        vault_id,
                        permission: permission_of(a),
                    })
                    .collect(),
            },
        )
        .await?)
}

/// A member as the app shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberView {
    pub account_id: String,
    pub email: String,
    pub role: Role,
    pub status: MemberStatus,
    /// From the keys the server lists; compare it out of band before confirming.
    pub fingerprint: String,
    /// The keys check out against the organization's certificates (or an earlier check).
    pub verified: bool,
    pub me: bool,
    pub pending_vaults: Vec<VaultGrant>,
}

pub async fn members(
    vault: &SharedVault,
    client: &SyncClient,
    org: &str,
) -> Result<Vec<MemberView>> {
    let list = client.members(org).await?;
    let trust = trust_for(vault, client, org).await?;
    let me = lock(vault)?.my_id()?;
    list.into_iter()
        .map(|m| {
            let keys = member_keys(&m)?;
            Ok(MemberView {
                fingerprint: crypto::fingerprint(&m.account_id, &keys),
                verified: trust.keys.get(&m.account_id) == Some(&keys),
                me: m.account_id == me,
                account_id: m.account_id,
                email: m.email,
                role: m.role,
                status: m.status,
                pending_vaults: m.pending_vaults,
            })
        })
        .collect::<core::result::Result<_, Error>>()
        .map_err(Into::into)
}

/// Confirms an accepted member: certifies their keys and seals them the keys of the vaults their
/// invite grants (every organization vault for an admin). `fingerprint` is what the user
/// compared with them; if the keys changed since, nothing happens.
pub async fn confirm_member(
    vault: &SharedVault,
    client: &SyncClient,
    org: &str,
    account: &str,
    fingerprint: &str,
) -> Result<()> {
    refresh(vault, client).await?;
    let list = client.members(org).await?;
    let target = list
        .iter()
        .find(|m| m.account_id == account)
        .ok_or_else(|| Error::NotFound(account.to_owned()))?;
    if target.status != MemberStatus::Accepted {
        return Err(Error::Invalid("already confirmed".into()).into());
    }
    let keys = member_keys(target)?;
    if crypto::fingerprint(account, &keys) != fingerprint.trim() {
        return Err(untrusted(
            "their keys don't match the fingerprint you compared; compare again",
        )
        .into());
    }
    let req = {
        let v = lock(vault)?;
        if v.pinned()?.get(account).is_some_and(|p| *p != keys) {
            return Err(untrusted("this account's keys changed").into());
        }
        let signer = &v.unlocked()?.account;
        let vaults: Vec<String> = if target.role.is_admin() {
            v.org_vault_ids(org)?
        } else {
            target
                .pending_vaults
                .iter()
                .map(|g| g.vault_id.clone())
                .collect()
        };
        let mut vault_keys = Vec::new();
        for id in &vaults {
            vault_keys.extend(v.seal_ring(id, account, &keys)?);
        }
        ConfirmMember {
            member_cert: B64(
                crypto::certify(signer, CertKind::Member, org, account, &keys).to_vec(),
            ),
            admin_cert: target.role.is_admin().then(|| {
                B64(crypto::certify(signer, CertKind::Admin, org, account, &keys).to_vec())
            }),
            vault_keys,
        }
    };
    client.confirm_member(org, account, &req).await?;
    lock(vault)?.pin(account, &keys, Some(&target.email))?;
    // The member key directory, so they can publish theirs (the next refresh retries a failure).
    let dir = lock(vault)?.directories(org)?.into_iter().next();
    if let Some(dir) = dir.filter(|_| !target.role.is_admin()) {
        let _ = grant(vault, client, &dir, account, &keys, Access::Write).await;
    }
    Ok(())
}

/// Grants a confirmed member a vault (sealing them every key generation), or changes their
/// permission.
pub async fn set_access(
    vault: &SharedVault,
    client: &SyncClient,
    vault_id: &str,
    account: &str,
    access: Access,
) -> Result<()> {
    let current = client.vault_members(vault_id).await?;
    if current.iter().any(|m| m.account_id == account) {
        client
            .set_vault_member(
                vault_id,
                account,
                &SetVaultMember {
                    permission: permission_of(access),
                    keys: Vec::new(),
                },
            )
            .await?;
        return Ok(());
    }
    let org = lock(vault)?
        .vaults()?
        .into_iter()
        .find(|v| v.id == vault_id)
        .and_then(|v| v.org_id)
        .ok_or(Error::UnknownVault)?;
    let trust = trust_for(vault, client, &org).await?;
    let k = trust
        .keys
        .get(account)
        .ok_or_else(|| untrusted("can't verify that member's keys"))?;
    grant(vault, client, vault_id, account, k, access).await
}

/// Gives a member a vault they don't have yet, sealing them every key generation.
async fn grant(
    vault: &SharedVault,
    client: &SyncClient,
    vault_id: &str,
    account: &str,
    keys: &PublicKeys,
    access: Access,
) -> Result<()> {
    let keys = lock(vault)?
        .seal_ring(vault_id, account, keys)?
        .into_iter()
        .map(|m| GrantKey {
            key_id: m.key_id,
            wrapped_vault_key: m.wrapped_vault_key,
            grant_sig: m.grant_sig,
        })
        .collect();
    client
        .set_vault_member(
            vault_id,
            account,
            &SetVaultMember {
                permission: permission_of(access),
                keys,
            },
        )
        .await?;
    Ok(())
}

pub async fn revoke_access(client: &SyncClient, vault_id: &str, account: &str) -> Result<()> {
    Ok(client.revoke_vault_member(vault_id, account).await?)
}

/// Moves a vault to a new key, sealed to everyone with access, and re-seals this device's
/// copies of its items (the next sync pushes them).
pub async fn rotate(vault: &SharedVault, client: &SyncClient, vault_id: &str) -> Result<()> {
    refresh(vault, client).await?;
    let org = lock(vault)?
        .vaults()?
        .into_iter()
        .find(|v| v.id == vault_id)
        .and_then(|v| v.org_id)
        .ok_or(Error::UnknownVault)?;
    let trust = trust_for(vault, client, &org).await?;
    let with_access = client.vault_members(vault_id).await?;
    let (req, record) = {
        let v = lock(vault)?;
        let me = v.my_id()?;
        let keys = v.unlocked()?;
        let ring = keys.shared.get(vault_id).ok_or(Error::UnknownVault)?;
        let vk = VaultKey::generate().map_err(Error::from)?;
        let mut wrapped = Vec::new();
        for m in &with_access {
            let k = if m.account_id == me {
                keys.account.public()
            } else {
                *trust.keys.get(&m.account_id).ok_or_else(|| {
                    untrusted(format!("can't verify the keys of account {}", m.account_id))
                })?
            };
            let w = vk.seal_to(&k.enc).map_err(Error::from)?;
            wrapped.push(SealedFor {
                account_id: m.account_id.clone(),
                grant_sig: B64(crypto::sign_grant(
                    &keys.account,
                    vault_id,
                    vk.id(),
                    &m.account_id,
                    &w,
                )
                .to_vec()),
                wrapped_vault_key: B64(w),
            });
        }
        let mine = wrapped
            .iter()
            .find(|w| w.account_id == me)
            .ok_or_else(|| Error::Invalid("you have no access to this vault".into()))?
            .wrapped_vault_key
            .0
            .clone();
        let mut ring_keys = v.ring_rows(vault_id)?;
        ring_keys.push((vk.id().to_vec(), mine));
        let (name, directory): (Option<String>, bool) = v
            .conn
            .query_row(
                "SELECT name, directory FROM vaults WHERE id = ?1",
                [vault_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(Error::from)?;
        let record = SharedVaultRecord {
            id: vault_id.to_owned(),
            org_id: org.clone(),
            name,
            directory,
            access: ring.access,
            rotation_due: false,
            current: *vk.id(),
            keys: ring_keys,
            created_at: now(),
        };
        let req = RotateVaultKey {
            key_id: B64(vk.id().to_vec()),
            previous_key_id: B64(ring.current.to_vec()),
            wrapped,
        };
        (req, record)
    };
    client.rotate_vault_key(vault_id, &req).await?;
    let mut v = lock(vault)?;
    v.store_shared_vault(record)?;
    v.reseal_old_items(vault_id)?;
    Ok(())
}

/// Removes a member, or leaves (`account` = this account; the organization's vaults then go
/// from this device).
pub async fn remove_member(
    vault: &SharedVault,
    client: &SyncClient,
    org: &str,
    account: &str,
) -> Result<()> {
    client.remove_member(org, account).await?;
    let mut v = lock(vault)?;
    if account == v.my_id()? {
        forget_org(&mut v, org)?;
    }
    Ok(())
}

fn forget_org(v: &mut LocalVault, org: &str) -> crate::Result<()> {
    let keep: HashSet<String> = v
        .vaults()?
        .into_iter()
        .filter(|x| !x.personal && x.org_id.as_deref() != Some(org))
        .map(|x| x.id)
        .collect();
    v.drop_shared_vaults_except(&keep)?;
    v.conn.execute("DELETE FROM orgs WHERE id = ?1", [org])?;
    Ok(())
}

/// The owner promotes a member to admin (certifying them and sealing every organization vault
/// key) or demotes an admin.
pub async fn set_role(
    vault: &SharedVault,
    client: &SyncClient,
    org: &str,
    account: &str,
    role: Role,
) -> Result<()> {
    let req = if role == Role::Admin {
        refresh(vault, client).await?;
        let trust = trust_for(vault, client, org).await?;
        let keys = *trust
            .keys
            .get(account)
            .ok_or_else(|| untrusted("can't verify that member's keys"))?;
        let v = lock(vault)?;
        let mut vault_keys = Vec::new();
        for id in v.org_vault_ids(org)? {
            vault_keys.extend(v.seal_ring(&id, account, &keys)?);
        }
        UpdateMember {
            role,
            admin_cert: Some(B64(crypto::certify(
                &v.unlocked()?.account,
                CertKind::Admin,
                org,
                account,
                &keys,
            )
            .to_vec())),
            vault_keys,
        }
    } else {
        UpdateMember {
            role,
            admin_cert: None,
            vault_keys: Vec::new(),
        }
    };
    client.update_member(org, account, &req).await?;
    Ok(())
}

/// Hands the organization to a confirmed admin (the master password proves it's the owner).
pub async fn transfer(
    vault: &SharedVault,
    client: &SyncClient,
    org: &str,
    account: &str,
    password: Zeroizing<String>,
) -> Result<()> {
    let trust = trust_for(vault, client, org).await?;
    let keys = *trust
        .keys
        .get(account)
        .ok_or_else(|| untrusted("can't verify the new owner's keys"))?;
    let auth_key = blocking(vault, move |v| v.auth_key(&password)).await?;
    let owner_cert = {
        let v = lock(vault)?;
        crypto::certify(&v.unlocked()?.account, CertKind::Owner, org, account, &keys)
    };
    client
        .transfer_org(
            org,
            &TransferOrg {
                account_id: account.to_owned(),
                auth_key: B64(auth_key.as_bytes().to_vec()),
                owner_cert: B64(owner_cert.to_vec()),
            },
        )
        .await?;
    Ok(())
}

/// Deletes the organization with its vaults (the master password proves it's the owner).
pub async fn delete_org(
    vault: &SharedVault,
    client: &SyncClient,
    org: &str,
    password: Zeroizing<String>,
) -> Result<()> {
    let auth_key = blocking(vault, move |v| v.auth_key(&password)).await?;
    client
        .delete_org(
            org,
            &DeleteOrg {
                auth_key: B64(auth_key.as_bytes().to_vec()),
            },
        )
        .await?;
    forget_org(&mut *lock(vault)?, org)?;
    Ok(())
}

/// Shared handle used by the desktop app.
pub type Client = Arc<SyncClient>;

#[cfg(test)]
mod tests {
    use mg_sync::Signed;
    use mg_vault::AccountKeys;

    use super::*;

    const ORG: &str = "01JORG00000000000000000000";

    struct Who {
        id: String,
        keys: AccountKeys,
    }

    fn who(id: &str) -> Who {
        Who {
            id: id.into(),
            keys: AccountKeys::generate().unwrap(),
        }
    }

    fn link(w: &Who, cert: Option<Signed>) -> OwnerLink {
        let p = w.keys.public();
        OwnerLink {
            account_id: w.id.clone(),
            enc_public_key: B64(p.enc.to_vec()),
            sign_public_key: B64(p.sign.to_vec()),
            cert,
        }
    }

    fn signed(by: &Who, kind: CertKind, of: &Who) -> Signed {
        Signed {
            signer_id: by.id.clone(),
            sig: B64(crypto::certify(&by.keys, kind, ORG, &of.id, &of.keys.public()).to_vec()),
        }
    }

    fn member(w: &Who, role: Role, cert: Option<Signed>, admin: Option<Signed>) -> Member {
        let p = w.keys.public();
        Member {
            account_id: w.id.clone(),
            email: format!("{}@x", w.id),
            role,
            status: MemberStatus::Confirmed,
            enc_public_key: B64(p.enc.to_vec()),
            sign_public_key: B64(p.sign.to_vec()),
            member_cert: cert,
            admin_cert: admin,
            joined_at: String::new(),
            pending_vaults: Vec::new(),
        }
    }

    fn root(w: &Who) -> Root {
        Root {
            account_id: w.id.clone(),
            keys: w.keys.public(),
        }
    }

    #[test]
    fn chain_admins_and_members_verify() {
        let (alice, bob, carol, dave) = (who("A"), who("B"), who("C"), who("D"));
        // Alice created it and handed it to Bob; Bob made Carol admin; Carol confirmed Dave.
        let chain = [
            link(&alice, None),
            link(&bob, Some(signed(&alice, CertKind::Owner, &bob))),
        ];
        let members = [
            member(&alice, Role::Admin, None, None),
            member(
                &bob,
                Role::Owner,
                Some(signed(&alice, CertKind::Member, &bob)),
                None,
            ),
            member(
                &carol,
                Role::Admin,
                Some(signed(&bob, CertKind::Member, &carol)),
                Some(signed(&bob, CertKind::Admin, &carol)),
            ),
            member(
                &dave,
                Role::Member,
                Some(signed(&carol, CertKind::Member, &dave)),
                None,
            ),
        ];
        let t = verify_org(ORG, &root(&alice), &chain, &members, &HashMap::new()).unwrap();
        for w in [&alice, &bob, &carol, &dave] {
            assert_eq!(t.keys.get(&w.id), Some(&w.keys.public()), "{}", w.id);
        }
        assert!(t.unverified.is_empty());
    }

    #[test]
    fn what_does_not_verify() {
        let (alice, bob, mallory) = (who("A"), who("B"), who("M"));
        let chain = [link(&alice, None)];
        let pins = HashMap::new();

        // Another root than the pinned one.
        assert!(verify_org(ORG, &root(&mallory), &chain, &[], &pins).is_err());

        // A member certified by nobody known, or by a plain member: unverified, not trusted.
        let members = [
            member(
                &bob,
                Role::Member,
                Some(signed(&mallory, CertKind::Member, &bob)),
                None,
            ),
            member(&mallory, Role::Member, None, None),
        ];
        let t = verify_org(ORG, &root(&alice), &chain, &members, &pins).unwrap();
        assert!(!t.keys.contains_key("B") && !t.keys.contains_key("M"));
        assert_eq!(t.unverified, ["B", "M"]);

        // An admin certificate not from an owner doesn't make a signer.
        let members = [
            member(
                &mallory,
                Role::Admin,
                Some(signed(&alice, CertKind::Member, &mallory)),
                Some(signed(&mallory, CertKind::Admin, &mallory)),
            ),
            member(
                &bob,
                Role::Member,
                Some(signed(&mallory, CertKind::Member, &bob)),
                None,
            ),
        ];
        let t = verify_org(ORG, &root(&alice), &chain, &members, &pins).unwrap();
        assert!(t.keys.contains_key("M"), "a member alright");
        assert!(!t.keys.contains_key("B"), "but not a signer");

        // A forged ownership link.
        let forged = [
            link(&alice, None),
            link(&mallory, Some(signed(&mallory, CertKind::Owner, &mallory))),
        ];
        assert!(verify_org(ORG, &root(&alice), &forged, &[], &pins).is_err());
    }

    #[test]
    fn pins_hold_against_swapped_keys() {
        let (alice, bob) = (who("A"), who("B"));
        let chain = [link(&alice, None)];
        let good = member(
            &bob,
            Role::Member,
            Some(signed(&alice, CertKind::Member, &bob)),
            None,
        );
        let pins: HashMap<String, PublicKeys> =
            HashMap::from([("B".to_owned(), bob.keys.public())]);
        verify_org(
            ORG,
            &root(&alice),
            &chain,
            std::slice::from_ref(&good),
            &pins,
        )
        .unwrap();

        // The server swaps Bob's keys: a hard error, even with a certificate for the new ones.
        let swapped = who("B");
        let bad = member(
            &swapped,
            Role::Member,
            Some(signed(&alice, CertKind::Member, &swapped)),
            None,
        );
        assert!(matches!(
            verify_org(ORG, &root(&alice), &chain, &[bad], &pins),
            Err(Error::Untrusted(_))
        ));

        // A pinned member whose certificate went missing (say its admin left) stays trusted.
        let uncertified = member(&bob, Role::Member, None, None);
        let t = verify_org(ORG, &root(&alice), &chain, &[uncertified], &pins).unwrap();
        assert!(t.keys.contains_key("B"));
    }
}
