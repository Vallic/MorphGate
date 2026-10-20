//! Account changes across devices, through the reference server over HTTP: password change,
//! recovery, a new recovery key, signing in again after a change elsewhere, device sign-out,
//! and two-step verification on servers that offer it.

use std::sync::{Arc, Mutex};

use mg_store::account::{self, AccountError, SharedVault};
use mg_store::sync::{SyncConfig, SyncError, sync_once};
use mg_store::sync_http::{HttpRemote, create_vault_request, register_request};
use mg_store::{Error, Host, HostAuth, ItemData, LocalVault};
use mg_sync::{B64, DeviceInfo, DeviceUpdate, SyncClient};
use mg_vault::{KdfParams, RecoveryKey};
mod common;

use common::server;
use zeroize::Zeroizing;

const PW: &str = "correct horse battery";

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.into())
}

fn device(name: &str) -> DeviceInfo {
    DeviceInfo {
        id: ulid::Ulid::generate().to_string(),
        name: name.into(),
        platform: "linux".into(),
        client_version: None,
        public_key: B64(vec![1; 32]),
    }
}

fn fast() -> LocalVault {
    LocalVault::open_in_memory()
        .unwrap()
        .with_kdf_cost(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1)
}

fn host(label: &str) -> ItemData {
    ItemData::Host(Host {
        label: label.into(),
        hostname: format!("{label}.internal"),
        port: 22,
        user: "deploy".into(),
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

struct Device {
    vault: SharedVault,
    client: Arc<SyncClient>,
    info: DeviceInfo,
}

impl Device {
    async fn sync(&self) -> Result<mg_store::sync::SyncReport, SyncError> {
        sync_once(&self.vault, &HttpRemote(&self.client)).await
    }

    fn labels(&self) -> Vec<String> {
        let mut l: Vec<String> = self
            .vault
            .lock()
            .unwrap()
            .items()
            .unwrap()
            .into_iter()
            .filter_map(|i| match i.data {
                ItemData::Host(h) => Some(h.label),
                _ => None,
            })
            .collect();
        l.sort();
        l
    }

    fn unlocks_with(&self, password: &str) -> bool {
        let mut v = self.vault.lock().unwrap();
        v.lock();
        v.unlock(password).is_ok()
    }

    /// The app's view after a sign-out: a fresh client for the next sign-in.
    fn new_client(&mut self, url: &str) {
        self.client = Arc::new(SyncClient::new(url).unwrap());
    }
}

/// Device A creates a vault with one host and enables sync. Returns it and its recovery key.
async fn first_device(url: &str, email: &str) -> (Device, RecoveryKey) {
    let mut v = fast();
    let rk = v.create(PW).unwrap();
    v.upsert(None, host("prod-db")).unwrap();
    let (export, rotated) = v.export_for_registration(PW).unwrap();
    assert!(rotated.is_none());
    let client = Arc::new(SyncClient::new(url).unwrap());
    let info = device("laptop");
    let session = client
        .register(&register_request(&export, email, info.clone(), None))
        .await
        .unwrap();
    client
        .create_vault(&create_vault_request(&export.vault))
        .await
        .unwrap();
    v.enable_sync(&SyncConfig {
        server_url: url.into(),
        email: email.into(),
        account_id: session.account_id,
        device_id: info.id.clone(),
        device_public_key: [1; 32],
    })
    .unwrap();
    v.set_sync_token(&session.tokens.refresh_token).unwrap();
    client.take_rotated_refresh();
    let a = Device {
        vault: Arc::new(Mutex::new(v)),
        client,
        info,
    };
    a.sync().await.unwrap();
    (a, rk)
}

async fn join(url: &str, email: &str, name: &str, password: &str) -> Device {
    let d = Device {
        vault: Arc::new(Mutex::new(fast())),
        client: Arc::new(SyncClient::new(url).unwrap()),
        info: device(name),
    };
    account::sign_in(
        &d.vault,
        d.client.clone(),
        email,
        z(password),
        d.info.clone(),
        None,
    )
    .await
    .unwrap();
    d.sync().await.unwrap();
    d
}

#[tokio::test]
async fn password_change_reaches_every_device() {
    let url = server().await;
    let email = common::email("val");
    let (a, _) = first_device(&url, &email).await;
    let mut b = join(&url, &email, "desktop", PW).await;
    assert_eq!(b.labels(), vec!["prod-db"]);

    let wrong =
        account::change_password(&a.vault, a.client.clone(), z("not it"), z("new password 2"))
            .await;
    assert!(matches!(
        wrong,
        Err(AccountError::Store(Error::WrongPassword))
    ));
    account::change_password(&a.vault, a.client.clone(), z(PW), z("new password 2"))
        .await
        .unwrap();
    assert!(a.unlocks_with("new password 2"));
    assert!(!a.unlocks_with(PW));
    // The device that changed it keeps syncing.
    a.vault.lock().unwrap().unlock("new password 2").unwrap();
    a.vault
        .lock()
        .unwrap()
        .upsert(None, host("after-change"))
        .unwrap();
    a.sync().await.unwrap();

    // B was signed out; its vault still opens with the old password until it signs in again.
    assert!(matches!(b.sync().await, Err(SyncError::Unauthorized)));
    assert!(b.unlocks_with(PW));
    b.vault.lock().unwrap().unlock(PW).unwrap();
    b.new_client(&url);
    let old = account::sign_in_again(
        &b.vault,
        b.client.clone(),
        &email,
        z(PW),
        b.info.clone(),
        None,
    )
    .await;
    assert!(matches!(old, Err(AccountError::WrongPassword)));
    account::sign_in_again(
        &b.vault,
        b.client.clone(),
        &email,
        z("new password 2"),
        b.info.clone(),
        None,
    )
    .await
    .unwrap();
    b.sync().await.unwrap();
    assert_eq!(b.labels(), vec!["after-change", "prod-db"]);
    assert!(b.unlocks_with("new password 2"));
    assert!(!b.unlocks_with(PW));

    // And a new device needs the new password.
    let c = join(&url, &email, "phone", "new password 2").await;
    assert_eq!(c.labels(), vec!["after-change", "prod-db"]);
}

#[tokio::test]
async fn recovery_on_a_synced_device_and_on_a_fresh_one() {
    let url = server().await;
    let email = common::email("val");
    let (mut a, rk) = first_device(&url, &email).await;
    let mut b = join(&url, &email, "desktop", PW).await;
    let code = rk.to_code().to_string();

    // A forgot the password: recovery code + new password, vault locked.
    a.vault.lock().unwrap().lock();
    a.new_client(&url);
    let bad = RecoveryKey::generate().unwrap().to_code().to_string();
    let r = account::recover(
        &a.vault,
        a.client.clone(),
        &email,
        z(&bad),
        z("recovered pw 1"),
        a.info.clone(),
    )
    .await;
    assert!(matches!(r, Err(AccountError::WrongRecoveryCode)), "{r:?}");
    a.new_client(&url);
    account::recover(
        &a.vault,
        a.client.clone(),
        &email,
        z(&code),
        z("recovered pw 1"),
        a.info.clone(),
    )
    .await
    .unwrap();
    // Unlocked, signed back in, syncing.
    a.vault
        .lock()
        .unwrap()
        .upsert(None, host("after-recovery"))
        .unwrap();
    a.sync().await.unwrap();
    assert!(a.unlocks_with("recovered pw 1"));

    // Every other device was signed out.
    assert!(matches!(b.sync().await, Err(SyncError::Unauthorized)));
    b.new_client(&url);
    account::sign_in_again(
        &b.vault,
        b.client.clone(),
        &email,
        z("recovered pw 1"),
        b.info.clone(),
        None,
    )
    .await
    .unwrap();
    b.sync().await.unwrap();
    assert_eq!(b.labels(), vec!["after-recovery", "prod-db"]);

    // A fresh device that only knows the recovery code.
    let c = Device {
        vault: Arc::new(Mutex::new(fast())),
        client: Arc::new(SyncClient::new(&url).unwrap()),
        info: device("tablet"),
    };
    account::recover_and_sign_in(
        &c.vault,
        c.client.clone(),
        &email,
        z(&code),
        z("recovered pw 2"),
        c.info.clone(),
    )
    .await
    .unwrap();
    c.sync().await.unwrap();
    assert_eq!(c.labels(), vec!["after-recovery", "prod-db"]);
    assert!(c.unlocks_with("recovered pw 2"));
    assert!(matches!(a.sync().await, Err(SyncError::Unauthorized)));
}

#[tokio::test]
async fn a_new_recovery_key_replaces_the_old_one_without_signing_anyone_out() {
    let url = server().await;
    let email = common::email("val");
    let (a, old) = first_device(&url, &email).await;
    let b = join(&url, &email, "desktop", PW).await;

    let wrong = account::new_recovery_key(&a.vault, a.client.clone(), z("nope nope")).await;
    assert!(matches!(
        wrong,
        Err(AccountError::Store(Error::WrongPassword))
    ));
    let new = account::new_recovery_key(&a.vault, a.client.clone(), z(PW))
        .await
        .unwrap();
    b.sync().await.unwrap();
    a.sync().await.unwrap();

    let fresh = |name: &str| Device {
        vault: Arc::new(Mutex::new(fast())),
        client: Arc::new(SyncClient::new(&url).unwrap()),
        info: device(name),
    };
    let c = fresh("old code");
    let r = account::recover_and_sign_in(
        &c.vault,
        c.client.clone(),
        &email,
        z(&old.to_code()),
        z("whatever 123"),
        c.info.clone(),
    )
    .await;
    assert!(matches!(r, Err(AccountError::WrongRecoveryCode)), "{r:?}");
    let d = fresh("new code");
    account::recover_and_sign_in(
        &d.vault,
        d.client.clone(),
        &email,
        z(&new.to_code()),
        z("whatever 123"),
        d.info.clone(),
    )
    .await
    .unwrap();
    d.sync().await.unwrap();
    assert_eq!(d.labels(), vec!["prod-db"]);

    // The device that made the new key can itself recover with it.
    let mut a = a;
    a.vault.lock().unwrap().lock();
    a.new_client(&url);
    account::recover(
        &a.vault,
        a.client.clone(),
        &email,
        z(&new.to_code()),
        z("third pw 333"),
        a.info.clone(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn signing_out_another_device() {
    let url = server().await;
    let email = common::email("val");
    let (a, _) = first_device(&url, &email).await;
    let b = join(&url, &email, "desktop", PW).await;

    let devices = a.client.devices().await.unwrap();
    assert_eq!(devices.len(), 2);
    assert!(devices.iter().any(|d| d.current && d.info.id == a.info.id));
    a.client.revoke_device(&b.info.id).await.unwrap();
    // B learns it was signed out (not that its session ran out): the app clears it.
    assert!(matches!(b.sync().await, Err(SyncError::DeviceRevoked)));
    let devices = a.client.devices().await.unwrap();
    assert_eq!(devices.len(), 1);
    a.sync().await.unwrap();

    // Signing in again brings it back.
    let mut b = b;
    b.new_client(&url);
    account::sign_in_again(
        &b.vault,
        b.client.clone(),
        &email,
        z(PW),
        b.info.clone(),
        None,
    )
    .await
    .unwrap();
    b.sync().await.unwrap();
    assert_eq!(a.client.devices().await.unwrap().len(), 2);
}

/// A device says what it is now (after an app update, on a phone that signed in as "Linux"); it
/// can't rename another.
#[tokio::test]
async fn a_device_updates_what_it_says_about_itself() {
    let url = server().await;
    let email = common::email("val");
    let (a, _) = first_device(&url, &email).await;
    let b = join(&url, &email, "MorphGate desktop", PW).await;

    let update = DeviceUpdate {
        name: "Google Pixel 8".into(),
        platform: "android".into(),
        client_version: Some("0.1.1".into()),
    };
    b.client.update_device(&b.info.id, &update).await.unwrap();
    let devices = a.client.devices().await.unwrap();
    let phone = devices.iter().find(|d| d.info.id == b.info.id).unwrap();
    assert_eq!(
        (
            phone.info.name.as_str(),
            phone.info.platform.as_str(),
            phone.info.client_version.as_deref()
        ),
        ("Google Pixel 8", "android", Some("0.1.1"))
    );

    // Not another device's.
    let err = b
        .client
        .update_device(&a.info.id, &update)
        .await
        .unwrap_err();
    assert!(
        matches!(err, mg_sync::Error::Api { status: 403, .. }),
        "{err:?}"
    );
    // Nothing empty.
    let blank = DeviceUpdate {
        name: " ".into(),
        ..update
    };
    assert!(matches!(
        b.client
            .update_device(&b.info.id, &blank)
            .await
            .unwrap_err(),
        mg_sync::Error::Api { status: 400, .. }
    ));
}

/// An account deleted from one device: the others hear `account_deleted` (not a plain 401), and
/// the app turns their sync off.
#[tokio::test]
async fn deleting_an_account_tells_its_other_devices() {
    let url = server().await;
    let email = common::email("deleted");
    let (a, _) = first_device(&url, &email).await;
    let b = join(&url, &email, "phone", PW).await;
    let lost = join(&url, &email, "tablet", PW).await;
    b.sync().await.unwrap();
    // Signed out before the deletion: it still hears that, and erases itself.
    a.client.revoke_device(&lost.info.id).await.unwrap();
    account::delete_account(&a.vault, a.client.clone(), z(PW))
        .await
        .unwrap();
    // Whichever call hears it first (the app's Sync panel, say), the next sync hears it too.
    assert!(matches!(
        b.client.account().await,
        Err(mg_sync::Error::AccountDeleted)
    ));
    assert!(matches!(b.sync().await, Err(SyncError::AccountDeleted)));
    assert!(matches!(
        lost.client.devices().await,
        Err(mg_sync::Error::DeviceRevoked)
    ));
    assert!(matches!(lost.sync().await, Err(SyncError::DeviceRevoked)));
}

/// What the server keeps about an account, readable (servers without an export are skipped).
#[tokio::test]
async fn the_data_export_tells_what_the_server_keeps() {
    let url = server().await;
    let email = common::email("export");
    let (a, _) = first_device(&url, &email).await;
    let b = join(&url, &email, "desktop", PW).await;
    a.client.revoke_device(&b.info.id).await.unwrap();
    let data = match a.client.account_export().await {
        Err(mg_sync::Error::Api { status: 404, .. }) => return,
        r => r.unwrap(),
    };
    assert_eq!(data["format"], "morphgate-account-export/1");
    assert!(data["generated_at"].is_string());
    assert!(
        data["account"]["email"]
            .as_str()
            .unwrap()
            .eq_ignore_ascii_case(&email)
    );
    assert!(data["account"]["public_keys"]["enc_public_key"].is_string());
    let devices = data["devices"].as_array().unwrap();
    assert_eq!(devices.len(), 2, "signed-out devices are in it too");
    assert!(
        devices
            .iter()
            .any(|d| d["id"] == b.info.id.as_str() && d["signed_out"] == true)
    );
    let personal = data["vaults"]["personal"].as_array().unwrap();
    assert_eq!(personal.len(), 1);
    assert!(personal[0]["items"].as_u64().unwrap() >= 1);
    let text = data.to_string();
    for secret in ["auth_hash", "recovery_hash", "wrapped", "kdf", "envelope"] {
        assert!(!text.contains(secret), "{secret} in the export");
    }
}

/// RFC 4648 base32 (no padding) to bytes.
fn unbase32(text: &str) -> Vec<u8> {
    const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut out, mut acc, mut bits) = (Vec::new(), 0u32, 0);
    for c in text.chars() {
        acc = (acc << 5) | ALPHABET.find(c).expect("base32") as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

/// The RFC 6238 code (SHA-1, 6 digits, 30 s) for a time step.
fn totp(secret: &[u8], step: u64) -> String {
    use hmac::{KeyInit, Mac};
    let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(secret).unwrap();
    mac.update(&step.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let o = (h[19] & 0x0f) as usize;
    let n = u32::from_be_bytes([h[o] & 0x7f, h[o + 1], h[o + 2], h[o + 3]]);
    format!("{:06}", n % 1_000_000)
}

/// A code that is not the one for `step` or its neighbours.
fn wrong_totp(secret: &[u8], step: u64) -> String {
    let near = [
        totp(secret, step - 1),
        totp(secret, step),
        totp(secret, step + 1),
    ];
    (0..4)
        .map(|i| format!("{i}{i}{i}{i}{i}{i}"))
        .find(|c| !near.contains(c))
        .unwrap()
}

/// Servers with `totp`: turning it on needs a code from the new secret, a new device then needs
/// one to sign in, each code works once, and turning it off needs one too. The reference server
/// doesn't offer it, so this runs only against servers that do (`VAULT_SYNC_URL`).
#[tokio::test]
async fn two_step_verification_where_offered() {
    let url = server().await;
    if !SyncClient::new(&url)
        .unwrap()
        .capabilities()
        .await
        .unwrap()
        .features
        .totp
    {
        return;
    }
    let email = common::email("totp");
    let (a, _) = first_device(&url, &email).await;

    assert!(matches!(
        account::start_totp(&a.vault, a.client.clone(), z("not the password")).await,
        Err(AccountError::Store(Error::WrongPassword))
    ));
    let setup = account::start_totp(&a.vault, a.client.clone(), z(PW))
        .await
        .unwrap();
    assert!(setup.uri.starts_with("otpauth://totp/"));
    let secret = unbase32(&setup.secret);
    // Codes for consecutive steps from here on, so none is reused by accident.
    let step = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30;
    assert!(matches!(
        account::enable_totp(&a.vault, a.client.clone(), wrong_totp(&secret, step)).await,
        Err(AccountError::WrongTotp)
    ));
    assert!(
        !a.client.account().await.unwrap().totp_enabled,
        "pending until a good code"
    );
    account::enable_totp(&a.vault, a.client.clone(), totp(&secret, step - 1))
        .await
        .unwrap();
    assert!(a.client.account().await.unwrap().totp_enabled);

    let b = Device {
        vault: Arc::new(Mutex::new(fast())),
        client: Arc::new(SyncClient::new(&url).unwrap()),
        info: device("desktop"),
    };
    let sign_in = |code: Option<String>| {
        account::sign_in(
            &b.vault,
            b.client.clone(),
            &email,
            z(PW),
            b.info.clone(),
            code,
        )
    };
    assert!(matches!(
        sign_in(None).await,
        Err(AccountError::TotpRequired)
    ));
    assert!(matches!(
        sign_in(Some(wrong_totp(&secret, step))).await,
        Err(AccountError::WrongTotp)
    ));
    assert!(
        matches!(
            sign_in(Some(totp(&secret, step - 1))).await,
            Err(AccountError::WrongTotp)
        ),
        "the code that turned it on is spent"
    );
    sign_in(Some(totp(&secret, step))).await.unwrap();
    b.sync().await.unwrap();
    assert_eq!(b.labels(), vec!["prod-db"]);

    assert!(
        matches!(
            account::disable_totp(&a.vault, a.client.clone(), z(PW), totp(&secret, step)).await,
            Err(AccountError::WrongTotp)
        ),
        "and so is the one b signed in with"
    );
    account::disable_totp(&a.vault, a.client.clone(), z(PW), totp(&secret, step + 1))
        .await
        .unwrap();
    assert!(!a.client.account().await.unwrap().totp_enabled);

    let c = Device {
        vault: Arc::new(Mutex::new(fast())),
        client: Arc::new(SyncClient::new(&url).unwrap()),
        info: device("phone"),
    };
    account::sign_in(
        &c.vault,
        c.client.clone(),
        &email,
        z(PW),
        c.info.clone(),
        None,
    )
    .await
    .unwrap();
}
