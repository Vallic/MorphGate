//! Glue between the sync engine and `mg_sync::SyncClient`, plus wire conversions.

use mg_sync::{B64, SyncClient};
use mg_vault::{KdfParams, PublicKeys};

use crate::sync::{
    AccountExport, AccountImport, Hold, Outgoing, PushOutcome, Remote, RemoteError, RemoteItem,
    RemotePage, VaultMaterial,
};
use crate::{Error, Refusal, Result};

const PAGE: u32 = 500;

/// The organization and why, when the server held its vaults back.
pub(crate) fn held(e: &mg_sync::Error) -> Option<(String, Hold)> {
    match e {
        mg_sync::Error::TotpSetupRequired { org_id } if !org_id.is_empty() => {
            Some((org_id.clone(), Hold::Totp))
        }
        mg_sync::Error::SsoRequired { org_id } => Some((org_id.clone(), Hold::Sso)),
        mg_sync::Error::DeviceApprovalRequired { org_id, denied } => Some((
            org_id.clone(),
            if *denied {
                Hold::Denied
            } else {
                Hold::Approval
            },
        )),
        _ => None,
    }
}

pub struct HttpRemote<'a>(pub &'a SyncClient);

fn remote_err(e: mg_sync::Error) -> RemoteError {
    match e {
        mg_sync::Error::Gone => RemoteError::Gone,
        mg_sync::Error::Unauthorized => RemoteError::Unauthorized,
        mg_sync::Error::DeviceRevoked => RemoteError::DeviceRevoked,
        mg_sync::Error::AccountDeleted => RemoteError::AccountDeleted,
        mg_sync::Error::Api { status: 404, .. } => RemoteError::NotFound,
        e @ mg_sync::Error::PaymentRequired(_) => RemoteError::PlanRequired(e.to_string()),
        other => match held(&other) {
            Some((org, why)) => RemoteError::Held(org, why),
            None => RemoteError::Other(other.to_string()),
        },
    }
}

/// For a blob: what the server won't take is a reason for the user, not a failed sync.
fn blob_err(e: mg_sync::Error) -> RemoteError {
    match e {
        mg_sync::Error::PaymentRequired(p) => {
            let upgrade_url = if p.code == "upgrade_required" {
                p.billing_url.clone()
            } else {
                None
            };
            RemoteError::Refused(Refusal {
                reason: mg_sync::Error::PaymentRequired(p).to_string(),
                upgrade_url,
            })
        }
        mg_sync::Error::Api {
            status: 400 | 403 | 413,
            message,
            ..
        } => RemoteError::Refused(message.into()),
        // A server that predates blobs.
        mg_sync::Error::Api {
            status: 404 | 405, ..
        } => RemoteError::Refused("the sync server doesn't store session logs".into()),
        other => remote_err(other),
    }
}

fn item(i: mg_sync::Item) -> RemoteItem {
    RemoteItem {
        id: i.id,
        rev: i.rev,
        deleted: i.deleted,
        envelope: i.envelope.map(|e| e.0),
        author_id: i.author_id,
    }
}

impl Remote for HttpRemote<'_> {
    async fn pull(
        &self,
        vault_id: &str,
        since: i64,
    ) -> core::result::Result<RemotePage, RemoteError> {
        let page = self
            .0
            .pull(vault_id, since, PAGE)
            .await
            .map_err(remote_err)?;
        Ok(RemotePage {
            items: page.items.into_iter().map(item).collect(),
            head_rev: page.head_rev,
            has_more: page.has_more,
        })
    }

    async fn push(
        &self,
        vault_id: &str,
        items: Vec<Outgoing>,
    ) -> core::result::Result<Vec<PushOutcome>, RemoteError> {
        let wire = items
            .into_iter()
            .map(|o| mg_sync::PushItem {
                id: o.id,
                base_rev: o.base_rev,
                deleted: o.deleted,
                envelope: o.envelope.map(B64),
            })
            .collect();
        let resp = self.0.push(vault_id, wire).await.map_err(remote_err)?;
        Ok(resp
            .results
            .into_iter()
            .map(|r| match (r.status, r.rev, r.current) {
                (mg_sync::PushStatus::Accepted, Some(rev), _) => {
                    PushOutcome::Accepted { id: r.id, rev }
                }
                (mg_sync::PushStatus::Conflict, _, Some(current)) => PushOutcome::Conflict {
                    current: item(current),
                },
                _ => {
                    let (code, reason) = r
                        .error
                        .map(|e| (e.code, e.message))
                        .unwrap_or_else(|| ("rejected".into(), "rejected by server".into()));
                    PushOutcome::Rejected {
                        id: r.id,
                        code,
                        reason,
                    }
                }
            })
            .collect())
    }

    async fn put_blob(
        &self,
        vault_id: &str,
        hash: &str,
        kind: &str,
        bytes: Vec<u8>,
    ) -> core::result::Result<(), RemoteError> {
        self.0
            .put_blob(vault_id, hash, kind, bytes)
            .await
            .map(|_| ())
            .map_err(blob_err)
    }

    async fn delete_blob(
        &self,
        vault_id: &str,
        hash: &str,
    ) -> core::result::Result<(), RemoteError> {
        self.0.delete_blob(vault_id, hash).await.map_err(remote_err)
    }
}

pub fn kdf_to_wire(k: &KdfParams) -> mg_sync::KdfParams {
    mg_sync::KdfParams {
        alg: "argon2id".into(),
        m_kib: k.m_kib,
        t: k.t,
        p: k.p,
        salt: B64(k.salt.clone()),
    }
}

/// Rejects anything but Argon2id; `mg-vault` additionally enforces the cost floors on use.
pub fn kdf_from_wire(k: &mg_sync::KdfParams) -> Result<KdfParams> {
    if k.alg != "argon2id" {
        return Err(Error::Invalid(format!("unsupported KDF {}", k.alg)));
    }
    Ok(KdfParams {
        m_kib: k.m_kib,
        t: k.t,
        p: k.p,
        salt: k.salt.0.clone(),
    })
}

pub fn register_request(
    export: &AccountExport,
    email: &str,
    device: mg_sync::DeviceInfo,
    email_code: Option<String>,
) -> mg_sync::RegisterRequest {
    mg_sync::RegisterRequest {
        email: email.into(),
        kdf: kdf_to_wire(&export.kdf),
        auth_key: B64(export.auth_key.as_bytes().to_vec()),
        keys: mg_sync::AccountKeys {
            enc_public_key: B64(export.public.enc.to_vec()),
            sign_public_key: B64(export.public.sign.to_vec()),
            wrapped_private_keys: B64(export.wrapped.clone()),
        },
        recovery: mg_sync::RecoveryMaterial {
            wrapped_private_keys_rk: B64(export.wrapped_rk.clone()),
            recovery_proof: B64(export.recovery_proof.clone()),
        },
        device,
        email_code,
        accepted_terms: None,
    }
}

pub fn create_vault_request(vault: &VaultMaterial) -> mg_sync::CreateVault {
    mg_sync::CreateVault {
        id: vault.id.clone(),
        key_id: B64(vault.key_id.to_vec()),
        wrapped_vault_key: B64(vault.wrapped_vault_key.clone()),
        meta: None,
        org_id: None,
        keys: Vec::new(),
    }
}

fn key32(b: &B64, what: &str) -> Result<[u8; 32]> {
    b.0.clone()
        .try_into()
        .map_err(|_| Error::Corrupt(format!("server sent a malformed {what}")))
}

pub fn account_import(account: &mg_sync::Account, vault: &mg_sync::Vault) -> Result<AccountImport> {
    Ok(AccountImport {
        kdf: kdf_from_wire(&account.kdf)?,
        public: PublicKeys {
            enc: key32(&account.keys.enc_public_key, "encryption key")?,
            sign: key32(&account.keys.sign_public_key, "signing key")?,
        },
        wrapped: account.keys.wrapped_private_keys.0.clone(),
        wrapped_rk: account
            .wrapped_private_keys_rk
            .as_ref()
            .map(|b| b.0.clone()),
        vault: VaultMaterial {
            id: vault.id.clone(),
            key_id: vault
                .key_id
                .0
                .clone()
                .try_into()
                .map_err(|_| Error::Corrupt("server sent a malformed vault key id".into()))?,
            wrapped_vault_key: vault.wrapped_vault_key.0.clone(),
        },
    })
}
