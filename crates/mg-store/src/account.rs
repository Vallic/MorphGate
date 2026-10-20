//! Account changes that involve the sync server: changing the master password, a new recovery
//! key, recovery with the recovery key, joining from a fresh device, signing in again after the
//! password changed on another device, two-step verification, changing the account email and
//! deleting the account.
//!
//! The server always goes first. If it can't be reached or refuses, the device keeps its current
//! password, so the two never disagree about which password opens the vault. Argon2id runs off
//! the async runtime.

use std::sync::{Arc, Mutex};

use mg_sync::{
    B64, DeleteAccountRequest, DeviceInfo, EmailChangeRequest, LoginRequest, RecoverRequest,
    RotateCredentialsRequest, SyncClient, TotpDisableRequest, TotpSetup, TotpStartRequest,
};
use mg_vault::{AuthKey, MasterKey, RecoveryKey};
use zeroize::Zeroizing;

use crate::sync::{AccountImport, SyncConfig};
use crate::sync_http::{account_import, kdf_from_wire, kdf_to_wire};
use crate::{Error, LocalVault, NewCredentials};

pub type SharedVault = Arc<Mutex<LocalVault>>;

#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error(transparent)]
    Store(#[from] Error),
    #[error("wrong email or master password")]
    WrongPassword,
    #[error("the sync server doesn't accept this recovery code for that account")]
    WrongRecoveryCode,
    /// The account has two-step verification: ask for a code and try again with it.
    #[error("enter the 6-digit code from your authenticator app")]
    TotpRequired,
    #[error("that authenticator code is wrong; use the newest one")]
    WrongTotp,
    #[error("that code is wrong or has expired")]
    WrongEmailCode,
    #[error(
        "this device is signed out of sync; sign in again (Sync panel) before changing the account"
    )]
    SignedOut,
    /// The account signed this device out: the app forgets what it keeps from it.
    #[error("this device was signed out of its sync account")]
    DeviceRevoked,
    /// The account was deleted elsewhere: sync goes off, team vaults go, the personal one stays.
    #[error("the sync account was deleted")]
    AccountDeleted,
    /// The organization's vaults wait on this device (single sign-on, approval).
    #[error("the organization's vaults wait on this device")]
    Held(String, crate::sync::Hold),
    #[error(
        "you own a team: transfer it to an admin or delete it (Teams), then delete your account"
    )]
    OwnsOrg,
    /// `402 team_limit`: shown with the prefix, so the app can offer the account portal.
    #[error("team_limit: {0}")]
    TeamLimit(String),
    #[error(
        "the subscription couldn't be cancelled just now, so nothing was deleted: try again in a minute"
    )]
    BillingUnavailable,
    #[error(
        "the sync server doesn't take this master password: if it was changed on another device, sign in again first"
    )]
    ServerRejectsPassword,
    #[error("sync server: {0}")]
    Server(String),
    #[error("vault state is poisoned; restart MorphGate")]
    Poisoned,
}

impl From<mg_sync::Error> for AccountError {
    fn from(e: mg_sync::Error) -> Self {
        match e {
            mg_sync::Error::Unauthorized => AccountError::SignedOut,
            mg_sync::Error::DeviceRevoked => AccountError::DeviceRevoked,
            mg_sync::Error::AccountDeleted => AccountError::AccountDeleted,
            mg_sync::Error::Api { code, .. } if code == "totp_required" => {
                AccountError::TotpRequired
            }
            mg_sync::Error::Api { code, .. } if code == "invalid_totp" => AccountError::WrongTotp,
            mg_sync::Error::Api { code, .. } if code == "invalid_code" => {
                AccountError::WrongEmailCode
            }
            mg_sync::Error::PaymentRequired(p) if p.code == "team_limit" => {
                AccountError::TeamLimit(mg_sync::Error::PaymentRequired(p).to_string())
            }
            other => match crate::sync_http::held(&other) {
                Some((org, why)) => AccountError::Held(org, why),
                None => AccountError::Server(other.to_string()),
            },
        }
    }
}

type Result<T> = core::result::Result<T, AccountError>;

pub(crate) async fn blocking<T: Send + 'static>(
    vault: &SharedVault,
    f: impl FnOnce(&mut LocalVault) -> crate::Result<T> + Send + 'static,
) -> Result<T> {
    let vault = vault.clone();
    tokio::task::spawn_blocking(move || {
        let mut v = vault.lock().map_err(|_| AccountError::Poisoned)?;
        f(&mut v).map_err(AccountError::from)
    })
    .await
    .map_err(|e| AccountError::Server(e.to_string()))?
}

/// Argon2id for `password` with the server's parameters for `email`.
async fn derive(
    client: &SyncClient,
    email: &str,
    password: &Zeroizing<String>,
) -> Result<(MasterKey, mg_vault::KdfParams)> {
    let kdf = kdf_from_wire(&client.prelogin(email).await?)?;
    let pw = password.clone();
    let k = kdf.clone();
    let mk = tokio::task::spawn_blocking(move || MasterKey::derive(pw.as_bytes(), &k))
        .await
        .map_err(|e| AccountError::Server(e.to_string()))?
        .map_err(Error::from)?;
    Ok((mk, kdf))
}

fn rotate_request(current: Option<&AuthKey>, c: &NewCredentials) -> RotateCredentialsRequest {
    RotateCredentialsRequest {
        current_auth_key: current.map(|k| B64(k.as_bytes().to_vec())),
        new_kdf: kdf_to_wire(&c.kdf),
        new_auth_key: B64(c.auth_key.as_bytes().to_vec()),
        wrapped_private_keys: B64(c.wrapped.clone()),
        recovery: c
            .new_recovery
            .as_ref()
            .map(|(rk, wrapped_rk)| mg_sync::RecoveryMaterial {
                wrapped_private_keys_rk: B64(wrapped_rk.clone()),
                recovery_proof: B64(rk.proof().to_vec()),
            }),
    }
}

async fn login(
    client: &SyncClient,
    email: &str,
    auth_key: &AuthKey,
    device: DeviceInfo,
    totp: Option<String>,
) -> Result<mg_sync::Session> {
    let req = LoginRequest {
        email: email.to_owned(),
        auth_key: B64(auth_key.as_bytes().to_vec()),
        totp,
        device,
    };
    client.login(&req).await.map_err(|e| match e {
        mg_sync::Error::Api {
            status: 401,
            ref code,
            ..
        } if code != "invalid_totp" => AccountError::WrongPassword,
        other => other.into(),
    })
}

/// Keeps a refresh token the client rotated while talking to the server.
fn keep_rotated(v: &LocalVault, client: &SyncClient) -> crate::Result<()> {
    match client.take_rotated_refresh() {
        Some(t) => v.set_sync_token(&t),
        None => Ok(()),
    }
}

/// Changes the master password on the server and then here. `client` is this device's signed-in
/// session. Other devices are signed out and pick up the new password when they sign in again.
pub async fn change_password(
    vault: &SharedVault,
    client: Arc<SyncClient>,
    current: Zeroizing<String>,
    new_password: Zeroizing<String>,
) -> Result<()> {
    let (current_auth, creds) = blocking(vault, move |v| {
        v.prepare_password_change(&current, &new_password)
    })
    .await?;
    client
        .rotate_credentials(&rotate_request(Some(&current_auth), &creds))
        .await?;
    blocking(vault, move |v| {
        v.apply_credentials(creds)?;
        keep_rotated(v, &client)
    })
    .await
}

/// Replaces the recovery key on the server and then here (the old one stops working). Returns
/// the new key, to show once. The password stays; nobody is signed out.
pub async fn new_recovery_key(
    vault: &SharedVault,
    client: Arc<SyncClient>,
    password: Zeroizing<String>,
) -> Result<RecoveryKey> {
    let (auth, creds) = blocking(vault, move |v| v.prepare_new_recovery_key(&password)).await?;
    client
        .rotate_credentials(&rotate_request(Some(&auth), &creds))
        .await?;
    blocking(vault, move |v| {
        let rk = v.apply_credentials(creds)?;
        keep_rotated(v, &client)?;
        rk.ok_or_else(|| Error::Corrupt("no recovery key was made".into()))
    })
    .await
}

/// Lost password: proves the recovery key to the server, takes the account keys it holds under
/// that key, and sets `new_password` for them. Every device is signed out.
async fn recover_on_server(
    vault: &SharedVault,
    client: &SyncClient,
    email: &str,
    recovery_code: Zeroizing<String>,
    new_password: Zeroizing<String>,
) -> Result<(NewCredentials, Vec<u8>, Vec<u8>)> {
    let rk = RecoveryKey::from_code(&recovery_code).map_err(|e| Error::Invalid(e.to_string()))?;
    let proof = rk.proof().to_vec();
    let resp = client
        .recover(&RecoverRequest {
            email: email.to_owned(),
            recovery_proof: B64(proof.clone()),
        })
        .await
        .map_err(|e| match e {
            mg_sync::Error::Api { status: 401, .. } => AccountError::WrongRecoveryCode,
            other => other.into(),
        })?;
    let wrapped_rk = resp.wrapped_private_keys_rk.0;
    let w = wrapped_rk.clone();
    let creds = blocking(vault, move |v| {
        v.prepare_recovery_from(&recovery_code, &w, &new_password)
    })
    .await?;
    client
        .rotate_credentials(&rotate_request(None, &creds))
        .await?;
    Ok((creds, wrapped_rk, proof))
}

/// Lost password on a device that has the (synced, locked) vault: sets the new password on the
/// server, signs this device back in, then stores it here and unlocks.
pub async fn recover(
    vault: &SharedVault,
    client: Arc<SyncClient>,
    email: &str,
    recovery_code: Zeroizing<String>,
    new_password: Zeroizing<String>,
    device: DeviceInfo,
) -> Result<()> {
    let (creds, wrapped_rk, proof) =
        recover_on_server(vault, &client, email, recovery_code, new_password).await?;
    // Recovery turns two-step verification off, so no code is needed here.
    let session = login(&client, email, &creds.auth_key, device, None).await?;
    blocking(vault, move |v| {
        v.apply_credentials(creds)?;
        v.store_recovery(&wrapped_rk, Some(&proof))?;
        v.set_sync_token(&session.tokens.refresh_token)?;
        client.take_rotated_refresh();
        Ok(())
    })
    .await
}

/// A fresh device (no vault yet) joins an existing account: downloads the account keys and the
/// vault key, unlocks, and keeps the session. Items arrive with the first sync.
///
/// With two-step verification on, the first try without `totp` fails with
/// [`AccountError::TotpRequired`]; ask for a code and call again with it.
pub async fn sign_in(
    vault: &SharedVault,
    client: Arc<SyncClient>,
    email: &str,
    password: Zeroizing<String>,
    device: DeviceInfo,
    totp: Option<String>,
) -> Result<()> {
    let (import, cfg, refresh) = signed_in(&client, email, &password, device, totp).await?;
    blocking(vault, move |v| {
        v.adopt_account(&password, import)?;
        v.enable_sync(&cfg)?;
        v.set_sync_token(&refresh)?;
        client.take_rotated_refresh();
        Ok(())
    })
    .await
}

/// Signs this device in and fetches what it needs to take the account on: its keys and vault,
/// the sync settings, and the session's refresh token.
async fn signed_in(
    client: &SyncClient,
    email: &str,
    password: &Zeroizing<String>,
    device: DeviceInfo,
    totp: Option<String>,
) -> Result<(AccountImport, SyncConfig, String)> {
    let (mk, _) = derive(client, email, password).await?;
    let (device_id, device_key) = (device.id.clone(), device.public_key.0.clone());
    let session = login(client, email, &mk.auth_key(), device, totp).await?;
    let account = client.account().await?;
    let remote_vault = client
        .list_vaults()
        .await?
        .into_iter()
        // The account's own vault, not one shared with it.
        .find(|v| v.org_id.is_none())
        .ok_or_else(|| {
            AccountError::Server(
                "this account has no vault yet; enable sync from the device that created it".into(),
            )
        })?;
    let import = account_import(&account, &remote_vault)?;
    let cfg = SyncConfig {
        server_url: client.origin().to_owned(),
        email: email.to_owned(),
        account_id: session.account_id.clone(),
        device_id,
        device_public_key: device_key.try_into().unwrap_or([0; 32]),
    };
    Ok((import, cfg, session.tokens.refresh_token))
}

/// Signing in on a device that already has a vault (never synced): like [`sign_in`], but what
/// that vault holds goes into the account's vault. The device then opens with the account's
/// master password. Returns how many items it brought.
pub async fn join(
    vault: &SharedVault,
    client: Arc<SyncClient>,
    email: &str,
    password: Zeroizing<String>,
    device: DeviceInfo,
    totp: Option<String>,
) -> Result<usize> {
    let (import, cfg, refresh) = signed_in(&client, email, &password, device, totp).await?;
    blocking(vault, move |v| {
        let count = v.join_account(&password, import)?;
        v.enable_sync(&cfg)?;
        v.set_sync_token(&refresh)?;
        client.take_rotated_refresh();
        Ok(count)
    })
    .await
}

/// Lost password on a fresh device: sets the new password with the recovery key, then signs in
/// with it as [`sign_in`] does.
pub async fn recover_and_sign_in(
    vault: &SharedVault,
    client: Arc<SyncClient>,
    email: &str,
    recovery_code: Zeroizing<String>,
    new_password: Zeroizing<String>,
    device: DeviceInfo,
) -> Result<()> {
    recover_on_server(vault, &client, email, recovery_code, new_password.clone()).await?;
    // Recovery turns two-step verification off, so no code is needed here.
    sign_in(vault, client, email, new_password, device, None).await
}

/// The account password changed on another device and this one was signed out: signs in with
/// the new password and re-wraps this vault's keys under it, so it unlocks with it from now on.
pub async fn sign_in_again(
    vault: &SharedVault,
    client: Arc<SyncClient>,
    email: &str,
    password: Zeroizing<String>,
    device: DeviceInfo,
    totp: Option<String>,
) -> Result<()> {
    let (mk, kdf) = derive(&client, email, &password).await?;
    let session = login(&client, email, &mk.auth_key(), device, totp).await?;
    let account = client.account().await?;
    blocking(vault, move |v| {
        v.adopt_credentials(
            &mk,
            &kdf,
            &session.keys.wrapped_private_keys.0,
            account
                .wrapped_private_keys_rk
                .as_ref()
                .map(|w| w.0.as_slice()),
        )?;
        v.set_sync_token(&session.tokens.refresh_token)?;
        client.take_rotated_refresh();
        Ok(())
    })
    .await
}

/// Checks the master password here and returns its `AuthKey` for the server.
async fn proof(vault: &SharedVault, password: Zeroizing<String>) -> Result<B64> {
    let auth = blocking(vault, move |v| v.auth_key(&password)).await?;
    Ok(B64(auth.as_bytes().to_vec()))
}

/// Deletes the sync account (the master password proves it's the holder): the server forgets it,
/// its devices and its memberships. This device keeps its vault, as after turning sync off: its
/// own items stay, team vaults go. Owners transfer or delete their organizations first.
pub async fn delete_account(
    vault: &SharedVault,
    client: Arc<SyncClient>,
    password: Zeroizing<String>,
) -> Result<()> {
    let auth_key = proof(vault, password).await?;
    let result = client
        .delete_account(&DeleteAccountRequest { auth_key })
        .await;
    match result {
        Ok(()) => blocking(vault, LocalVault::disable_sync).await,
        Err(mg_sync::Error::Api { code, .. }) if code == "sole_owner" => {
            blocking(vault, move |v| keep_rotated(v, &client)).await?;
            Err(AccountError::OwnsOrg)
        }
        Err(mg_sync::Error::Api { code, .. }) if code == "billing_unavailable" => {
            blocking(vault, move |v| keep_rotated(v, &client)).await?;
            Err(AccountError::BillingUnavailable)
        }
        Err(mg_sync::Error::Api { code, .. }) if code == "invalid_credentials" => {
            blocking(vault, move |v| keep_rotated(v, &client)).await?;
            Err(AccountError::ServerRejectsPassword)
        }
        Err(e) => {
            blocking(vault, move |v| keep_rotated(v, &client)).await?;
            Err(e.into())
        }
    }
}

/// Starts two-step verification: a new secret for the authenticator app. Nothing changes until
/// [`enable_totp`] gets a code from it.
pub async fn start_totp(
    vault: &SharedVault,
    client: Arc<SyncClient>,
    password: Zeroizing<String>,
) -> Result<TotpSetup> {
    let auth_key = proof(vault, password).await?;
    let setup = client.start_totp(&TotpStartRequest { auth_key }).await;
    blocking(vault, move |v| keep_rotated(v, &client)).await?;
    Ok(setup?)
}

/// Turns two-step verification on with a code from the secret [`start_totp`] returned.
pub async fn enable_totp(vault: &SharedVault, client: Arc<SyncClient>, code: String) -> Result<()> {
    let result = client.enable_totp(code.trim()).await;
    blocking(vault, move |v| keep_rotated(v, &client)).await?;
    Ok(result?)
}

/// Turns two-step verification off; needs the master password and a current code.
pub async fn disable_totp(
    vault: &SharedVault,
    client: Arc<SyncClient>,
    password: Zeroizing<String>,
    code: String,
) -> Result<()> {
    let auth_key = proof(vault, password).await?;
    let result = client
        .disable_totp(&TotpDisableRequest {
            auth_key,
            code: code.trim().to_owned(),
        })
        .await;
    blocking(vault, move |v| keep_rotated(v, &client)).await?;
    Ok(result?)
}

/// First half of moving the account to another address: the server mails it a code.
pub async fn start_email_change(
    vault: &SharedVault,
    client: Arc<SyncClient>,
    new_email: String,
) -> Result<()> {
    let result = client.start_email_change(new_email.trim()).await;
    blocking(vault, move |v| keep_rotated(v, &client)).await?;
    Ok(result?)
}

/// Second half: the server switches with the mailed code and the master password, then this
/// device remembers the new address (it signs in with it from now on).
pub async fn change_email(
    vault: &SharedVault,
    client: Arc<SyncClient>,
    password: Zeroizing<String>,
    new_email: String,
    code: String,
) -> Result<()> {
    let auth_key = proof(vault, password).await?;
    let new_email = new_email.trim().to_owned();
    let result = client
        .change_email(&EmailChangeRequest {
            new_email: new_email.clone(),
            code: code.trim().to_owned(),
            auth_key,
        })
        .await;
    let changed = result.is_ok();
    blocking(vault, move |v| {
        if changed {
            v.set_sync_email(&new_email)?;
        }
        keep_rotated(v, &client)
    })
    .await?;
    Ok(result?)
}
