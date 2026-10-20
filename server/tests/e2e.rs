//! Two real local vaults syncing through the reference server over HTTP.

use std::sync::Mutex;

use mg_store::sync::sync_once;
use mg_store::sync_http::{
    HttpRemote, account_import, create_vault_request, kdf_from_wire, register_request,
};
use mg_store::{Host, HostAuth, ItemData, LocalVault};
use mg_sync::{B64, DeviceInfo, LoginRequest, SyncClient};
use mg_vault::{KdfParams, MasterKey};
mod common;

use common::{email, server};

const PW: &str = "correct horse battery";

fn device(name: &str) -> DeviceInfo {
    DeviceInfo {
        id: ulid::Ulid::generate().to_string(),
        name: name.into(),
        platform: "linux".into(),
        client_version: None,
        public_key: B64(vec![1; 32]),
    }
}

fn host(label: &str, password: Option<&str>) -> ItemData {
    ItemData::Host(Host {
        label: label.into(),
        hostname: format!("{label}.internal"),
        port: 22,
        user: "deploy".into(),
        auth: HostAuth::Password {
            password: password.map(Into::into),
        },
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

fn fast() -> LocalVault {
    LocalVault::open_in_memory()
        .unwrap()
        .with_kdf_cost(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1)
}

#[tokio::test]
async fn second_device_signs_in_and_syncs() {
    let url = server().await;
    let val = email("val");

    // Device A: existing local vault, enables sync.
    let mut a = fast();
    a.create(PW).unwrap();
    a.upsert(None, host("prod-db", Some("s3cret-db-password")))
        .unwrap();
    let (export, _) = a.export_for_registration(PW).unwrap();
    let client_a = SyncClient::new(&url).unwrap();
    client_a
        .register(&register_request(&export, &val, device("laptop"), None))
        .await
        .unwrap();
    client_a
        .create_vault(&create_vault_request(&export.vault))
        .await
        .unwrap();
    let a = Mutex::new(a);
    let r = sync_once(&a, &HttpRemote(&client_a)).await.unwrap();
    assert_eq!(r.pushed, 1);

    // Device B: fresh install, signs in with email + master password only.
    let client_b = SyncClient::new(&url).unwrap();
    let kdf = client_b.prelogin(&val).await.unwrap();
    let mk = MasterKey::derive(PW.as_bytes(), &kdf_from_wire(&kdf).unwrap()).unwrap();
    let login = LoginRequest {
        email: val.clone(),
        auth_key: B64(mk.auth_key().as_bytes().to_vec()),
        totp: None,
        device: device("desktop"),
    };
    client_b.login(&login).await.unwrap();
    let account = client_b.account().await.unwrap();
    let vault = client_b.list_vaults().await.unwrap().remove(0);
    let mut b = fast();
    b.adopt_account(PW, account_import(&account, &vault).unwrap())
        .unwrap();
    let b = Mutex::new(b);
    assert_eq!(
        sync_once(&b, &HttpRemote(&client_b)).await.unwrap().pulled,
        1
    );

    let items = b.lock().unwrap().items().unwrap();
    let ItemData::Host(h) = &items[0].data else {
        panic!("expected a host")
    };
    assert_eq!(
        h.auth,
        HostAuth::Password {
            password: Some("s3cret-db-password".into())
        }
    );

    // B edits, A picks it up.
    let id = items[0].id.clone();
    b.lock()
        .unwrap()
        .upsert(Some(&id), host("prod-db-renamed", None))
        .unwrap();
    sync_once(&b, &HttpRemote(&client_b)).await.unwrap();
    assert_eq!(
        sync_once(&a, &HttpRemote(&client_a)).await.unwrap().pulled,
        1
    );
    let ItemData::Host(h) = a.lock().unwrap().item(&id).unwrap().data else {
        panic!()
    };
    assert_eq!(h.label, "prod-db-renamed");

    // B also gets local recovery: the recovery-wrapped keys came down with the account.
    let mut b = b.into_inner().unwrap();
    b.lock();
    assert!(matches!(
        b.unlock("wrong password"),
        Err(mg_store::Error::WrongPassword)
    ));
    b.unlock(PW).unwrap();
}

#[tokio::test]
async fn wrong_password_never_reaches_a_session() {
    let url = server().await;
    let v = email("v");
    let mut a = fast();
    a.create(PW).unwrap();
    let (export, _) = a.export_for_registration(PW).unwrap();
    let c = SyncClient::new(&url).unwrap();
    c.register(&register_request(&export, &v, device("a"), None))
        .await
        .unwrap();

    let kdf = c.prelogin(&v).await.unwrap();
    let mk = MasterKey::derive(b"not my password", &kdf_from_wire(&kdf).unwrap()).unwrap();
    let login = LoginRequest {
        email: v.clone(),
        auth_key: B64(mk.auth_key().as_bytes().to_vec()),
        totp: None,
        device: device("b"),
    };
    assert!(matches!(
        SyncClient::new(&url).unwrap().login(&login).await,
        Err(mg_sync::Error::Api { status: 401, .. })
    ));
}
