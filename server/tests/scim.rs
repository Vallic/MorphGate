//! SCIM 2.0 provisioning through the reference server: an identity provider invites people into
//! an organization, deactivates them (their membership goes and the vaults they could open want a
//! new key) and deletes them; the owner can't be deprovisioned. In-process only: SCIM is outside
//! vault-sync/v1, and only an operator makes the token.

use std::sync::{Arc, Mutex};

use mg_store::account::SharedVault;
use mg_store::sharing;
use mg_store::sync::SyncConfig;
use mg_store::sync_http::{create_vault_request, register_request};
use mg_store::{Access, LocalVault};
use mg_sync::{B64, DeviceInfo, Role, SyncClient};
use mg_vault::KdfParams;
use reqwest::Method;
use serde_json::{Value, json};

mod common;

const PW: &str = "correct horse battery";
const USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const PATCH: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const ERROR: &str = "urn:ietf:params:scim:api:messages:2.0:Error";

struct Person {
    vault: SharedVault,
    client: SyncClient,
    id: String,
    email: String,
}

async fn person(url: &str, name: &str) -> Person {
    let mut v = LocalVault::open_in_memory().unwrap().with_kdf_cost(
        KdfParams::MIN_M_KIB,
        KdfParams::MIN_T,
        1,
    );
    v.create(PW).unwrap();
    let (export, _) = v.export_for_registration(PW).unwrap();
    let client = SyncClient::new(url).unwrap();
    let email = common::email(name);
    let device = DeviceInfo {
        id: ulid::Ulid::generate().to_string(),
        name: name.into(),
        platform: "linux".into(),
        client_version: None,
        public_key: B64(vec![1; 32]),
    };
    let session = client
        .register(&register_request(&export, &email, device.clone(), None))
        .await
        .unwrap();
    client
        .create_vault(&create_vault_request(&export.vault))
        .await
        .unwrap();
    v.enable_sync(&SyncConfig {
        server_url: url.into(),
        email: email.clone(),
        account_id: session.account_id.clone(),
        device_id: device.id,
        device_public_key: [1; 32],
    })
    .unwrap();
    Person {
        vault: Arc::new(Mutex::new(v)),
        client,
        id: session.account_id,
        email,
    }
}

fn fingerprint(p: &Person) -> String {
    let keys = p.vault.lock().unwrap().public_keys().unwrap();
    mg_vault::sharing::fingerprint(&p.id, &keys)
}

/// Invites someone the usual way (the admin passes the token on); they accept.
async fn join(admin: &Person, org: &str, p: &Person, vaults: Vec<(String, Access)>) {
    let token = sharing::invite(&admin.client, org, &p.email, Role::Member, vaults)
        .await
        .unwrap()
        .token
        .unwrap();
    let preview = sharing::preview_invite(&p.client, &token).await.unwrap();
    sharing::accept_invite(&p.vault, &p.client, &token, &preview.owner_fingerprint)
        .await
        .unwrap();
}

/// An identity provider: raw SCIM calls with a bearer token.
struct Provider {
    http: reqwest::Client,
    base: String,
    token: String,
}

impl Provider {
    fn new(url: &str, org: &str, token: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            base: format!("{url}/scim/v2/{org}"),
            token: token.into(),
        }
    }

    /// The status and the body (`Null` when empty).
    async fn call(&self, method: Method, path: &str, body: Option<Value>) -> (u16, Value) {
        let mut req = self
            .http
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(&self.token);
        if let Some(body) = body {
            req = req
                .header("content-type", "application/scim+json")
                .body(body.to_string());
        }
        let resp = req.send().await.unwrap();
        let status = resp.status().as_u16();
        if status != 204 {
            assert_eq!(
                resp.headers()["content-type"],
                "application/scim+json",
                "{path}"
            );
        }
        let text = resp.text().await.unwrap();
        let body = if text.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).unwrap()
        };
        (status, body)
    }

    async fn get(&self, path: &str) -> (u16, Value) {
        self.call(Method::GET, path, None).await
    }

    async fn create(&self, user: Value) -> (u16, Value) {
        self.call(Method::POST, "/Users", Some(user)).await
    }

    async fn patch(&self, id: &str, ops: Value) -> (u16, Value) {
        let body = json!({ "schemas": [PATCH], "Operations": ops });
        self.call(Method::PATCH, &format!("/Users/{id}"), Some(body))
            .await
    }

    /// Users whose userName matches (in any case).
    async fn find(&self, user_name: &str) -> Vec<Value> {
        let filter = format!("userName eq \"{user_name}\"");
        let (status, list) = self
            .call(Method::GET, &format!("/Users?filter={filter}"), None)
            .await;
        assert_eq!(status, 200, "{list}");
        list["Resources"].as_array().unwrap().clone()
    }
}

/// A SCIM error: its status (as a string) and `scimType`.
fn error(body: &Value) -> (&str, Option<&str>) {
    assert_eq!(body["schemas"], json!([ERROR]), "{body}");
    assert!(body["detail"].is_string(), "{body}");
    (body["status"].as_str().unwrap(), body["scimType"].as_str())
}

async fn invited(admin: &Person, org: &str, email: &str) -> bool {
    admin
        .client
        .invites(org)
        .await
        .unwrap()
        .iter()
        .any(|i| i.email.eq_ignore_ascii_case(email))
}

#[tokio::test]
async fn tokens_and_discovery() {
    let Some((url, state)) = common::reference_state().await else {
        return;
    };
    let alice = person(&url, "alice").await;
    let org = sharing::create_org(&alice.vault, &alice.client, "Acme")
        .await
        .unwrap();
    // Nothing answers before the operator makes a token.
    let none = Provider::new(&url, &org, "scim_nothing");
    let (status, body) = none.get("/ServiceProviderConfig").await;
    assert_eq!((status, error(&body)), (401, ("401", None)));

    let (id, token) = state.scim_token("Acme").unwrap();
    assert_eq!(id, org);
    assert!(
        token.starts_with("scim_") && token.len() == 5 + 43,
        "{token}"
    );
    let idp = Provider::new(&url, &org, &token);
    let (status, config) = idp.get("/ServiceProviderConfig").await;
    assert_eq!(status, 200, "{config}");
    assert_eq!(config["patch"]["supported"], true);
    assert_eq!(
        config["filter"],
        json!({ "supported": true, "maxResults": 200 })
    );
    assert_eq!(config["bulk"]["supported"], false);
    assert_eq!(
        config["authenticationSchemes"][0]["type"],
        "oauthbearertoken"
    );
    let (status, types) = idp.get("/ResourceTypes").await;
    assert_eq!(status, 200);
    assert_eq!(types["Resources"][0]["schema"], USER);
    let (status, schemas) = idp.get("/Schemas").await;
    assert_eq!(status, 200);
    let attributes = schemas["Resources"][0]["attributes"].as_array().unwrap();
    let names: Vec<&str> = attributes
        .iter()
        .map(|a| a["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["userName", "externalId", "active"]);
    assert_eq!(attributes[0]["mutability"], "immutable");

    // A token works for its own organization only, and a bad id isn't an organization.
    let other = Provider::new(&url, &ulid::Ulid::generate().to_string(), &token);
    assert_eq!(other.get("/Users").await.0, 401);
    assert_eq!(
        Provider::new(&url, "acme", &token).get("/Users").await.0,
        404
    );

    // A new token replaces the old one; revoking stops provisioning.
    let (_, newer) = state.scim_token(&org).unwrap();
    assert_eq!(idp.get("/Users").await.0, 401);
    let idp = Provider::new(&url, &org, &newer);
    assert_eq!(idp.get("/Users").await.0, 200);
    state.revoke_scim("Acme").unwrap();
    let (status, body) = idp.get("/Users").await;
    assert_eq!((status, error(&body)), (401, ("401", None)));

    let events = alice.client.org_events(&org, 0, 1000).await.unwrap().events;
    let kinds: Vec<&str> = events.iter().map(|e| e.kind.as_str()).collect();
    for kind in ["scim_token_created", "scim_token_revoked"] {
        assert!(kinds.contains(&kind), "{kind} in {kinds:?}");
    }
}

/// Creating a user invites the address; an admin hands the invite on by inviting again.
#[tokio::test]
async fn provisioning_invites() {
    let Some((url, state)) = common::reference_state().await else {
        return;
    };
    let alice = person(&url, "alice").await;
    let bob = person(&url, "bob").await;
    let org = sharing::create_org(&alice.vault, &alice.client, "Acme")
        .await
        .unwrap();
    let (_, token) = state.scim_token(&org).unwrap();
    let idp = Provider::new(&url, &org, &token);

    let (status, user) = idp
        .create(json!({
            "schemas": [USER],
            "userName": bob.email,
            "externalId": "00u-bob",
            "name": { "givenName": "Bob" },
            "active": true,
        }))
        .await;
    assert_eq!(status, 201, "{user}");
    let id = user["id"].as_str().unwrap().to_owned();
    assert_eq!(id.len(), 26);
    assert_eq!(user["schemas"], json!([USER]));
    assert_eq!(
        (&user["userName"], &user["externalId"], &user["active"]),
        (&json!(bob.email), &json!("00u-bob"), &json!(true))
    );
    assert_eq!(
        user["emails"],
        json!([{ "value": bob.email, "primary": true, "type": "work" }])
    );
    assert_eq!(user["meta"]["resourceType"], "User");
    assert_eq!(
        user["meta"]["location"],
        format!("{url}/scim/v2/{org}/Users/{id}")
    );
    assert!(user["meta"]["created"].is_string() && user["meta"]["lastModified"].is_string());
    assert!(invited(&alice, &org, &bob.email).await);
    let events = alice.client.org_events(&org, 0, 1000).await.unwrap().events;
    let invite = events.iter().find(|e| e.kind == "member_invited").unwrap();
    assert_eq!(
        (invite.actor_id.as_deref(), invite.detail.as_deref()),
        (None, Some(bob.email.as_str()))
    );
    assert_eq!(idp.get(&format!("/Users/{id}")).await.1, user);

    // Filters: userName in any case, externalId; anything else is refused.
    assert_eq!(
        idp.find(&bob.email.to_uppercase()).await,
        std::slice::from_ref(&user)
    );
    let (status, list) = idp
        .get("/Users?filter=externalid%20eq%20%2200u-bob%22")
        .await;
    assert_eq!((status, &list["totalResults"]), (200, &json!(1)));
    assert!(idp.find("nobody@example.com").await.is_empty());
    let (status, body) = idp.get("/Users?filter=displayName%20eq%20%22Bob%22").await;
    assert_eq!(
        (status, error(&body)),
        (400, ("400", Some("invalidFilter")))
    );

    // The userName is unique (in any case) and can't change.
    let (status, body) = idp
        .create(json!({ "schemas": [USER], "userName": bob.email.to_uppercase() }))
        .await;
    assert_eq!((status, error(&body)), (409, ("409", Some("uniqueness"))));
    let (status, body) = idp
        .call(
            Method::PUT,
            &format!("/Users/{id}"),
            Some(json!({ "schemas": [USER], "userName": "robert@example.com", "active": true })),
        )
        .await;
    assert_eq!((status, error(&body)), (400, ("400", Some("mutability"))));
    let (status, body) = idp
        .call(
            Method::PUT,
            &format!("/Users/{id}"),
            Some(json!({ "schemas": [USER], "userName": bob.email, "externalId": "00u-bob-2" })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        (&body["externalId"], &body["active"]),
        (&json!("00u-bob-2"), &json!(true))
    );
    let (status, body) = idp.create(json!({ "userName": "not an address" })).await;
    assert_eq!((status, error(&body).0), (400, "400"));
    let (status, body) = idp.call(Method::POST, "/Users", None).await;
    assert_eq!((status, error(&body).0), (400, "400"));

    // A userName that isn't an address: the primary email is.
    let (status, carol) = idp
        .create(json!({
            "userName": "carol",
            "emails": [{ "value": "carol.home@example.com" }, { "value": "Carol@Example.com", "primary": true }],
        }))
        .await;
    assert_eq!(status, 201, "{carol}");
    assert_eq!(carol["userName"], "Carol@Example.com");
    assert!(carol.get("externalId").is_none());
    assert!(invited(&alice, &org, "carol@example.com").await);

    // Pages start at 1.
    let (status, page) = idp.get("/Users?startIndex=2&count=1").await;
    assert_eq!(status, 200);
    assert_eq!(
        (
            &page["totalResults"],
            &page["startIndex"],
            &page["itemsPerPage"]
        ),
        (&json!(2), &json!(2), &json!(1))
    );
    assert_eq!(page["Resources"][0]["id"], carol["id"]);
    assert_eq!(idp.get("/Users?count=0").await.1["itemsPerPage"], 0);

    // Nobody has the provisioned invite's token: an admin invites the address again, which
    // replaces it, and passes the new token on.
    join(&alice, &org, &bob, vec![]).await;
    let members = alice.client.members(&org).await.unwrap();
    assert!(members.iter().any(|m| m.account_id == bob.id));
    assert!(!invited(&alice, &org, &bob.email).await);
}

/// Deactivating a confirmed member removes them and flags their vaults; reactivating invites
/// them again; deleting deprovisions and forgets the user.
#[tokio::test]
async fn deprovisioning_removes_members() {
    let Some((url, state)) = common::reference_state().await else {
        return;
    };
    let alice = person(&url, "alice").await;
    let carol = person(&url, "carol").await;
    let org = sharing::create_org(&alice.vault, &alice.client, "Acme")
        .await
        .unwrap();
    let prod = sharing::create_vault(&alice.vault, &alice.client, &org, "Production")
        .await
        .unwrap();
    join(&alice, &org, &carol, vec![(prod.clone(), Access::Write)]).await;
    sharing::confirm_member(
        &alice.vault,
        &alice.client,
        &org,
        &carol.id,
        &fingerprint(&carol),
    )
    .await
    .unwrap();
    assert!(!alice.client.vault(&prod).await.unwrap().rotation_due);
    let (_, token) = state.scim_token(&org).unwrap();
    let idp = Provider::new(&url, &org, &token);

    // Already a member: nothing changes.
    let (status, user) = idp
        .create(json!({ "schemas": [USER], "userName": carol.email, "active": "True" }))
        .await;
    assert_eq!(status, 201, "{user}");
    let id = user["id"].as_str().unwrap().to_owned();
    assert!(!invited(&alice, &org, &carol.email).await);

    // Only replace and add.
    let (status, body) = idp
        .patch(&id, json!([{ "op": "remove", "path": "externalId" }]))
        .await;
    assert_eq!(
        (status, error(&body)),
        (400, ("400", Some("invalidSyntax")))
    );

    // Deactivated (as Entra ID sends it): the membership goes, the vault wants a new key.
    let (status, user) = idp
        .patch(
            &id,
            json!([{ "op": "Replace", "path": "active", "value": "False" }]),
        )
        .await;
    assert_eq!(status, 200, "{user}");
    assert_eq!(user["active"], false);
    let members = alice.client.members(&org).await.unwrap();
    assert!(members.iter().all(|m| m.account_id != carol.id));
    assert!(alice.client.vault(&prod).await.unwrap().rotation_due);
    assert!(carol.client.vault(&prod).await.is_err());
    let events = alice.client.org_events(&org, 0, 1000).await.unwrap().events;
    let removed = events.iter().find(|e| e.kind == "member_removed").unwrap();
    assert_eq!(
        (removed.actor_id.as_deref(), removed.target_id.as_deref()),
        (None, Some(carol.id.as_str()))
    );

    // Reactivated (as Okta sends it, no path): invited again.
    let (status, user) = idp
        .patch(
            &id,
            json!([{ "op": "replace", "value": { "active": true, "externalId": "00u-carol" } }]),
        )
        .await;
    assert_eq!(status, 200, "{user}");
    assert_eq!(
        (&user["active"], &user["externalId"]),
        (&json!(true), &json!("00u-carol"))
    );
    assert!(invited(&alice, &org, &carol.email).await);

    // Deleted: the pending invite is cancelled and the user is gone.
    let (status, body) = idp
        .call(Method::DELETE, &format!("/Users/{id}"), None)
        .await;
    assert_eq!((status, body), (204, Value::Null));
    assert!(!invited(&alice, &org, &carol.email).await);
    let (status, body) = idp.get(&format!("/Users/{id}")).await;
    assert_eq!((status, error(&body)), (404, ("404", None)));
    let events = alice.client.org_events(&org, 0, 1000).await.unwrap().events;
    assert!(
        events
            .iter()
            .any(|e| e.kind == "invite_cancelled" && e.actor_id.is_none())
    );
}

#[tokio::test]
async fn the_owner_cant_be_deprovisioned() {
    let Some((url, state)) = common::reference_state().await else {
        return;
    };
    let alice = person(&url, "alice").await;
    let org = sharing::create_org(&alice.vault, &alice.client, "Acme")
        .await
        .unwrap();
    let (_, token) = state.scim_token(&org).unwrap();
    let idp = Provider::new(&url, &org, &token);

    // A refused create leaves no user behind.
    let (status, body) = idp
        .create(json!({ "userName": alice.email, "active": false }))
        .await;
    assert_eq!((status, error(&body)), (409, ("409", None)));
    assert!(idp.find(&alice.email).await.is_empty());

    let (status, user) = idp.create(json!({ "userName": alice.email })).await;
    assert_eq!(status, 201, "{user}");
    let id = user["id"].as_str().unwrap();
    let (status, body) = idp
        .patch(
            id,
            json!([{ "op": "replace", "path": "active", "value": false }]),
        )
        .await;
    assert_eq!((status, error(&body).0), (409, "409"));
    let (status, body) = idp
        .call(Method::DELETE, &format!("/Users/{id}"), None)
        .await;
    assert_eq!((status, error(&body).0), (409, "409"));
    assert_eq!(idp.get(&format!("/Users/{id}")).await.1["active"], true);
    let members = alice.client.members(&org).await.unwrap();
    assert!(
        members
            .iter()
            .any(|m| m.account_id == alice.id && m.role == Role::Owner)
    );
}
