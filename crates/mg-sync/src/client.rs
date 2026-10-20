//! HTTP client for `vault-sync/v1`.

use std::sync::Mutex;

use reqwest::{Method, RequestBuilder, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use url::Url;

use crate::types::*;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid server URL: {0}")]
    BadUrl(String),
    #[error("cannot reach the sync server: {0}")]
    Http(#[from] reqwest::Error),
    #[error("not signed in to the sync server (session expired or device revoked)")]
    Unauthorized,
    /// `401 device_revoked` on a refresh: the account signed this device out (from another
    /// device or the account page). Unlike an expired session, the app is to forget what it
    /// keeps from the account.
    #[error("this device was signed out of its sync account")]
    DeviceRevoked,
    /// `401 account_deleted` on a refresh: the account was deleted (from another device or the
    /// website). The app turns sync off and lets go of the account's team vaults.
    #[error("the sync account was deleted")]
    AccountDeleted,
    #[error("the server lost history this device still needs; a full resync is required")]
    Gone,
    /// `402`: the account's or organization's plan doesn't cover this.
    #[error("{}", payment_message(.0))]
    PaymentRequired(Box<Payment>),
    /// `403 sso_required`: the organization's vaults need this device signed in at its
    /// identity provider (`sso_start`).
    #[error("the organization's vaults need single sign-on")]
    SsoRequired { org_id: String },
    /// `403 device_approval_required`: an owner or admin, or one of the member's approved
    /// devices, has to approve this device (`denied`: they decided against it).
    #[error("{}", if *denied { "the organization denied this device" } else { "this device waits for the organization's approval" })]
    DeviceApprovalRequired { org_id: String, denied: bool },
    #[error("{message} ({code})")]
    Api {
        status: u16,
        code: String,
        message: String,
    },
    #[error("{0} does not speak vault-sync/v1")]
    NotASyncServer(String),
}

pub type Result<T> = core::result::Result<T, Error>;

/// What a `402` says (boxed in [`Error::PaymentRequired`], which would otherwise make every
/// result large).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payment {
    /// `payment_required`, `seats_exceeded`, `upgrade_required` or `team_limit`.
    pub code: String,
    /// `trial_ended` or `lapsed`.
    pub reason: Option<String>,
    /// Where the owner can change the plan.
    pub billing_url: Option<String>,
    /// For `upgrade_required`: the plan that has the `feature`.
    pub plan: Option<String>,
    pub feature: Option<String>,
    /// For `team_limit`: how many organizations an account may own without a paid plan.
    pub limit: Option<u32>,
}

/// One client per server. Holds the current tokens and refreshes the access token on 401;
/// call [`take_rotated_refresh`](Self::take_rotated_refresh) after requests to persist rotations.
pub struct SyncClient {
    http: reqwest::Client,
    origin: Url,
    api: Url,
    tokens: Mutex<Option<Tokens>>,
    rotated: Mutex<bool>,
    /// Why the session ended for good, once the server said so (`device_revoked`,
    /// `account_deleted`): every later call gets that, not a bare "signed out", whichever call
    /// heard it first.
    ended: Mutex<Option<Error>>,
}

impl SyncClient {
    /// `server` is the origin, e.g. `https://morphgate.com` or `http://127.0.0.1:8443`.
    /// Plain HTTP only to this computer: anywhere else the login proof and the tokens would
    /// cross the network readable.
    pub fn new(server: &str) -> Result<Self> {
        let mut origin = Url::parse(server.trim()).map_err(|e| Error::BadUrl(e.to_string()))?;
        match origin.scheme() {
            "https" => {}
            "http" if loopback(&origin) => {}
            "http" => {
                return Err(Error::BadUrl(
                    "use https:// (plain http:// only for a server on this computer: localhost, \
                     127.0.0.1 or [::1])"
                        .into(),
                ));
            }
            _ => return Err(Error::BadUrl("use https://".into())),
        }
        if !origin.username().is_empty() || origin.password().is_some() {
            return Err(Error::BadUrl(
                "the address can't hold a user name or password".into(),
            ));
        }
        origin.set_path("/");
        origin.set_query(None);
        origin.set_fragment(None);
        let api = origin
            .join("v1/")
            .map_err(|e| Error::BadUrl(e.to_string()))?;
        let http = reqwest::Client::builder()
            .user_agent(concat!("MorphGate/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(30))
            // The API never redirects: following one could leave HTTPS or the server.
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            http,
            origin,
            api,
            tokens: Mutex::new(None),
            rotated: Mutex::new(false),
            ended: Mutex::new(None),
        })
    }

    pub fn origin(&self) -> &str {
        self.origin.as_str().trim_end_matches('/')
    }

    /// Restores a session from a stored refresh token; the next request refreshes first.
    pub fn resume(&self, refresh_token: String) {
        *self.ended.lock().expect("not poisoned") = None;
        *self.tokens.lock().expect("not poisoned") = Some(Tokens {
            access_token: String::new(),
            refresh_token,
            expires_in: 0,
        });
    }

    pub fn tokens(&self) -> Option<Tokens> {
        self.tokens.lock().expect("not poisoned").clone()
    }

    /// The refresh token, if it changed since the last call (rotation on refresh/login).
    pub fn take_rotated_refresh(&self) -> Option<String> {
        let mut rotated = self.rotated.lock().expect("not poisoned");
        if std::mem::take(&mut *rotated) {
            self.tokens().map(|t| t.refresh_token)
        } else {
            None
        }
    }

    fn set_tokens(&self, tokens: Tokens) {
        *self.ended.lock().expect("not poisoned") = None;
        *self.tokens.lock().expect("not poisoned") = Some(tokens);
        *self.rotated.lock().expect("not poisoned") = true;
    }

    // -------------------------------------------------------------- unauthenticated

    pub async fn capabilities(&self) -> Result<Capabilities> {
        let url = self
            .origin
            .join(".well-known/vault-sync")
            .map_err(|e| Error::BadUrl(e.to_string()))?;
        let caps: Capabilities = match decode(self.http.get(url).send().await?).await {
            Ok(c) => c,
            Err(Error::Api { .. }) | Err(Error::Http(_)) => {
                return Err(Error::NotASyncServer(self.origin().into()));
            }
            Err(e) => return Err(e),
        };
        if caps.spec != SPEC || !caps.versions.iter().any(|v| v == VERSION) {
            return Err(Error::NotASyncServer(self.origin().into()));
        }
        Ok(caps)
    }

    pub async fn prelogin(&self, email: &str) -> Result<KdfParams> {
        self.call_anon(
            Method::POST,
            "auth/prelogin",
            &PreloginRequest {
                email: email.into(),
            },
        )
        .await
    }

    /// First half of sign-up on servers with `email_verification`: mails a code to `email`
    /// (or, if it already has an account, a notice; the answer is the same).
    pub async fn start_registration(&self, email: &str) -> Result<()> {
        let req = RegisterStartRequest {
            email: email.into(),
        };
        empty(
            self.request(Method::POST, "auth/register/start")?
                .json(&req)
                .send()
                .await?,
        )
        .await
    }

    pub async fn register(&self, req: &RegisterRequest) -> Result<Session> {
        let s: Session = self.call_anon(Method::POST, "auth/register", req).await?;
        self.set_tokens(s.tokens.clone());
        Ok(s)
    }

    /// Lost password: trades a recovery proof for the recovery-wrapped account keys and a
    /// short-lived token that only allows [`rotate_credentials`](Self::rotate_credentials).
    /// The client uses that token from here on.
    pub async fn recover(&self, req: &RecoverRequest) -> Result<RecoverResponse> {
        let r: RecoverResponse = self.call_anon(Method::POST, "account/recover", req).await?;
        *self.tokens.lock().expect("not poisoned") = Some(Tokens {
            access_token: r.access_token.clone(),
            refresh_token: String::new(),
            expires_in: 0,
        });
        Ok(r)
    }

    pub async fn login(&self, req: &LoginRequest) -> Result<Session> {
        let s: Session = self.call_anon(Method::POST, "auth/login", req).await?;
        self.set_tokens(s.tokens.clone());
        Ok(s)
    }

    // -------------------------------------------------------------- authenticated

    pub async fn account(&self) -> Result<Account> {
        self.call(Method::GET, "account", None::<&()>).await
    }

    /// Everything the server keeps about the account (`morphgate-account-export/1`), as JSON.
    /// Servers without an export answer `404`.
    /// Deletes the account and everything the server keeps for it; `auth_key` proves the master
    /// password. `409 sole_owner` while it owns an organization.
    pub async fn delete_account(&self, req: &DeleteAccountRequest) -> Result<()> {
        let resp = self.authed(Method::DELETE, "account", Some(req)).await?;
        empty(resp).await
    }

    pub async fn account_export(&self) -> Result<serde_json::Value> {
        self.call(Method::GET, "account/export", None::<&()>).await
    }

    pub async fn list_vaults(&self) -> Result<Vec<Vault>> {
        self.call(Method::GET, "vaults", None::<&()>).await
    }

    pub async fn create_vault(&self, v: &CreateVault) -> Result<Vault> {
        self.call(Method::POST, "vaults", Some(v)).await
    }

    pub async fn pull(&self, vault_id: &str, since: i64, limit: u32) -> Result<ChangePage> {
        let path = format!("vaults/{vault_id}/changes?since={since}&limit={limit}");
        self.call(Method::GET, &path, None::<&()>).await
    }

    pub async fn push(&self, vault_id: &str, items: Vec<PushItem>) -> Result<PushResponse> {
        self.call(
            Method::POST,
            &format!("vaults/{vault_id}/changes"),
            Some(&PushRequest { items }),
        )
        .await
    }

    /// Password change (or recovery-key rotation): re-wrapped keys + new `AuthKey`.
    pub async fn rotate_credentials(&self, req: &RotateCredentialsRequest) -> Result<()> {
        let resp = self.authed(Method::PUT, "account/keys", Some(req)).await?;
        if resp.status() == StatusCode::UNAUTHORIZED {
            return Err(Error::Unauthorized);
        }
        empty(resp).await
    }

    /// Mails a code to `new_email` for [`change_email`](Self::change_email).
    pub async fn start_email_change(&self, new_email: &str) -> Result<()> {
        let req = EmailChangeStartRequest {
            new_email: new_email.into(),
        };
        empty(
            self.authed(Method::POST, "account/email/start", Some(&req))
                .await?,
        )
        .await
    }

    pub async fn change_email(&self, req: &EmailChangeRequest) -> Result<()> {
        empty(self.authed(Method::PUT, "account/email", Some(req)).await?).await
    }

    /// A new authenticator secret; two-step verification turns on once
    /// [`enable_totp`](Self::enable_totp) gets a code from it.
    pub async fn start_totp(&self, req: &TotpStartRequest) -> Result<TotpSetup> {
        self.call(Method::POST, "account/totp/start", Some(req))
            .await
    }

    pub async fn enable_totp(&self, code: &str) -> Result<()> {
        let req = TotpEnableRequest { code: code.into() };
        empty(
            self.authed(Method::POST, "account/totp/enable", Some(&req))
                .await?,
        )
        .await
    }

    pub async fn disable_totp(&self, req: &TotpDisableRequest) -> Result<()> {
        empty(
            self.authed(Method::DELETE, "account/totp", Some(req))
                .await?,
        )
        .await
    }

    /// A single-use link into the server's account portal, to open in a browser.
    /// A single-use link into the account portal, landing on `next` (`/account` without one).
    pub async fn web_session(&self, next: Option<&str>) -> Result<WebSession> {
        match next {
            None => {
                self.call(Method::POST, "account/web-session", None::<&()>)
                    .await
            }
            Some(next) => {
                let req = WebSessionRequest {
                    next: Some(next.to_owned()),
                };
                self.call(Method::POST, "account/web-session", Some(&req))
                    .await
            }
        }
    }

    /// Accepts the server's current terms (`features.terms.version`).
    pub async fn accept_terms(&self, version: &str) -> Result<()> {
        let resp = self
            .authed(
                Method::PUT,
                "account/terms",
                Some(&AcceptTermsRequest {
                    accepted_terms: version.to_owned(),
                }),
            )
            .await?;
        empty(resp).await
    }

    pub async fn devices(&self) -> Result<Vec<Device>> {
        self.call(Method::GET, "devices", None::<&()>).await
    }

    /// This device's name, platform and version as they are now (they're sent at sign-in, and
    /// change: an app update, a renamed computer). Servers without it answer 404 or 405.
    pub async fn update_device(&self, device_id: &str, update: &DeviceUpdate) -> Result<()> {
        let resp = self
            .authed(Method::PATCH, &format!("devices/{device_id}"), Some(update))
            .await?;
        empty(resp).await
    }

    /// Signs another device out (its data stays on it).
    pub async fn revoke_device(&self, device_id: &str) -> Result<()> {
        let resp = self
            .authed(Method::DELETE, &format!("devices/{device_id}"), None::<&()>)
            .await?;
        empty(resp).await
    }

    // -------------------------------------------------------------- vaults (sharing)

    pub async fn vault(&self, vault_id: &str) -> Result<Vault> {
        self.call(Method::GET, &format!("vaults/{vault_id}"), None::<&()>)
            .await
    }

    pub async fn delete_vault(&self, vault_id: &str) -> Result<()> {
        let resp = self
            .authed(Method::DELETE, &format!("vaults/{vault_id}"), None::<&()>)
            .await?;
        empty(resp).await
    }

    pub async fn vault_members(&self, vault_id: &str) -> Result<Vec<VaultMember>> {
        self.call(
            Method::GET,
            &format!("vaults/{vault_id}/members"),
            None::<&()>,
        )
        .await
    }

    /// Grants a confirmed member access, or changes their permission.
    pub async fn set_vault_member(
        &self,
        vault_id: &str,
        account_id: &str,
        req: &SetVaultMember,
    ) -> Result<VaultMember> {
        self.call(
            Method::PUT,
            &format!("vaults/{vault_id}/members/{account_id}"),
            Some(req),
        )
        .await
    }

    /// Revokes a member's access (the vault then wants a key rotation).
    pub async fn revoke_vault_member(&self, vault_id: &str, account_id: &str) -> Result<()> {
        let resp = self
            .authed(
                Method::DELETE,
                &format!("vaults/{vault_id}/members/{account_id}"),
                None::<&()>,
            )
            .await?;
        empty(resp).await
    }

    /// Switches the vault to a new key generation.
    pub async fn rotate_vault_key(&self, vault_id: &str, req: &RotateVaultKey) -> Result<Vault> {
        self.call(Method::POST, &format!("vaults/{vault_id}/keys"), Some(req))
            .await
    }

    // -------------------------------------------------------------- organizations

    pub async fn orgs(&self) -> Result<Vec<OrgMembership>> {
        self.call(Method::GET, "orgs", None::<&()>).await
    }

    pub async fn create_org(&self, req: &CreateOrg) -> Result<Org> {
        self.call(Method::POST, "orgs", Some(req)).await
    }

    pub async fn org(&self, org_id: &str) -> Result<Org> {
        self.call(Method::GET, &format!("orgs/{org_id}"), None::<&()>)
            .await
    }

    /// The organization's identity provider and this device's session with it.
    pub async fn sso_status(&self, org_id: &str) -> Result<SsoStatus> {
        self.call(Method::GET, &format!("orgs/{org_id}/sso"), None::<&()>)
            .await
    }

    /// Certifies a confirmed member again (owners and admins): when the admin who confirmed them
    /// left, devices that never verified them can't trust them otherwise.
    pub async fn recertify_member(
        &self,
        org_id: &str,
        account_id: &str,
        req: &MemberCertificate,
    ) -> Result<Member> {
        self.call(
            Method::PUT,
            &format!("orgs/{org_id}/members/{account_id}/certificate"),
            Some(req),
        )
        .await
    }

    /// Devices' requests to open the organization's vaults (`status`: `pending`, `approved` or
    /// `denied`). Owners and admins see everyone's, members their own.
    pub async fn org_devices(
        &self,
        org_id: &str,
        status: Option<&str>,
    ) -> Result<Vec<DeviceApproval>> {
        let query = status.map(|s| format!("?status={s}")).unwrap_or_default();
        self.call(
            Method::GET,
            &format!("orgs/{org_id}/devices{query}"),
            None::<&()>,
        )
        .await
    }

    /// Approves (or denies) a member's device. Owners and admins decide for anyone, members
    /// for their own other devices, from a device the organization approved.
    pub async fn decide_device(
        &self,
        org_id: &str,
        member: &str,
        device: &str,
        approve: bool,
    ) -> Result<DeviceApproval> {
        let verb = if approve { "approve" } else { "deny" };
        self.call(
            Method::POST,
            &format!("orgs/{org_id}/members/{member}/devices/{device}/{verb}"),
            None::<&()>,
        )
        .await
    }

    /// Starts a sign-in at the organization's identity provider: open the URL in a browser,
    /// then retry what answered `sso_required`.
    pub async fn sso_start(&self, org_id: &str) -> Result<SsoStart> {
        self.call(
            Method::POST,
            &format!("orgs/{org_id}/sso/start"),
            None::<&()>,
        )
        .await
    }

    /// The vault's blobs, oldest first; `kind` filters.
    pub async fn blobs(&self, vault_id: &str, kind: Option<&str>) -> Result<Vec<BlobInfo>> {
        let path = match kind {
            Some(k) => format!("vaults/{vault_id}/blobs?kind={k}"),
            None => format!("vaults/{vault_id}/blobs"),
        };
        self.call(Method::GET, &path, None::<&()>).await
    }

    /// Uploads a blob named by the SHA-256 of `bytes`. `true` when it was new (`201`); the same
    /// bytes already stored answer `200` and change nothing.
    pub async fn put_blob(
        &self,
        vault_id: &str,
        hash: &str,
        kind: &str,
        bytes: Vec<u8>,
    ) -> Result<(BlobInfo, bool)> {
        let resp = self
            .authed_with(
                Method::PUT,
                &format!("vaults/{vault_id}/blobs/{hash}"),
                |req| {
                    req.header("X-Blob-Kind", kind)
                        .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                        .body(bytes.clone())
                },
            )
            .await?;
        let created = resp.status() == StatusCode::CREATED;
        Ok((decode(resp).await?, created))
    }

    /// The blob's bytes. Check them against the hash before use.
    pub async fn blob(&self, vault_id: &str, hash: &str) -> Result<Vec<u8>> {
        let resp = self
            .authed(
                Method::GET,
                &format!("vaults/{vault_id}/blobs/{hash}"),
                None::<&()>,
            )
            .await?;
        if !resp.status().is_success() {
            return Err(error(resp).await);
        }
        Ok(resp.bytes().await?.to_vec())
    }

    pub async fn delete_blob(&self, vault_id: &str, hash: &str) -> Result<()> {
        empty(
            self.authed(
                Method::DELETE,
                &format!("vaults/{vault_id}/blobs/{hash}"),
                None::<&()>,
            )
            .await?,
        )
        .await
    }

    pub async fn update_org(&self, org_id: &str, req: &UpdateOrg) -> Result<Org> {
        self.call(Method::PATCH, &format!("orgs/{org_id}"), Some(req))
            .await
    }

    pub async fn delete_org(&self, org_id: &str, req: &DeleteOrg) -> Result<()> {
        let resp = self
            .authed(Method::DELETE, &format!("orgs/{org_id}"), Some(req))
            .await?;
        empty(resp).await
    }

    pub async fn members(&self, org_id: &str) -> Result<Vec<Member>> {
        self.call(Method::GET, &format!("orgs/{org_id}/members"), None::<&()>)
            .await
    }

    pub async fn invite(&self, org_id: &str, req: &CreateInvite) -> Result<Invite> {
        self.call(Method::POST, &format!("orgs/{org_id}/invites"), Some(req))
            .await
    }

    /// Pending invites.
    pub async fn invites(&self, org_id: &str) -> Result<Vec<Invite>> {
        self.call(Method::GET, &format!("orgs/{org_id}/invites"), None::<&()>)
            .await
    }

    pub async fn cancel_invite(&self, org_id: &str, invite_id: &str) -> Result<()> {
        let resp = self
            .authed(
                Method::DELETE,
                &format!("orgs/{org_id}/invites/{invite_id}"),
                None::<&()>,
            )
            .await?;
        empty(resp).await
    }

    /// What an invite is for; needs only the token.
    pub async fn invite_info(&self, token: &str) -> Result<InviteInfo> {
        decode(
            self.request(Method::GET, &format!("invites/{token}"))?
                .send()
                .await?,
        )
        .await
    }

    pub async fn accept_invite(&self, token: &str) -> Result<OrgMembership> {
        self.call(
            Method::POST,
            &format!("invites/{token}/accept"),
            None::<&()>,
        )
        .await
    }

    pub async fn confirm_member(
        &self,
        org_id: &str,
        account_id: &str,
        req: &ConfirmMember,
    ) -> Result<Member> {
        self.call(
            Method::POST,
            &format!("orgs/{org_id}/members/{account_id}/confirm"),
            Some(req),
        )
        .await
    }

    pub async fn update_member(
        &self,
        org_id: &str,
        account_id: &str,
        req: &UpdateMember,
    ) -> Result<Member> {
        self.call(
            Method::PATCH,
            &format!("orgs/{org_id}/members/{account_id}"),
            Some(req),
        )
        .await
    }

    /// Removes a member, or leaves when `account_id` is the caller.
    pub async fn remove_member(&self, org_id: &str, account_id: &str) -> Result<()> {
        let resp = self
            .authed(
                Method::DELETE,
                &format!("orgs/{org_id}/members/{account_id}"),
                None::<&()>,
            )
            .await?;
        empty(resp).await
    }

    pub async fn transfer_org(&self, org_id: &str, req: &TransferOrg) -> Result<Org> {
        self.call(Method::POST, &format!("orgs/{org_id}/transfer"), Some(req))
            .await
    }

    /// The whole audit log as a file (owners and admins): `csv` or `jsonl`. Servers without it
    /// answer 404.
    pub async fn org_events_export(&self, org_id: &str, format: &str) -> Result<String> {
        let resp = self
            .authed(
                Method::GET,
                &format!("orgs/{org_id}/events/export?format={format}"),
                None::<&()>,
            )
            .await?;
        if !resp.status().is_success() {
            return Err(error(resp).await);
        }
        Ok(resp.text().await?)
    }

    pub async fn org_events(&self, org_id: &str, since: i64, limit: u32) -> Result<EventPage> {
        self.call(
            Method::GET,
            &format!("orgs/{org_id}/events?since={since}&limit={limit}"),
            None::<&()>,
        )
        .await
    }

    pub async fn logout(&self) -> Result<()> {
        let r = self.authed(Method::POST, "auth/logout", None::<&()>).await;
        *self.tokens.lock().expect("not poisoned") = None;
        r.map(|_| ())
    }

    // -------------------------------------------------------------- plumbing

    async fn refresh(&self) -> Result<()> {
        let refresh_token = self
            .tokens()
            .map(|t| t.refresh_token)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| self.signed_out())?;
        let tokens: Tokens = match self
            .call_anon(
                Method::POST,
                "auth/refresh",
                &RefreshRequest { refresh_token },
            )
            .await
        {
            Ok(t) => t,
            Err(Error::Api {
                status: 401, code, ..
            }) => {
                *self.tokens.lock().expect("not poisoned") = None;
                let ended = match code.as_str() {
                    "device_revoked" => Some(Error::DeviceRevoked),
                    "account_deleted" => Some(Error::AccountDeleted),
                    _ => None,
                };
                if let Some(e) = &ended {
                    *self.ended.lock().expect("not poisoned") = Some(e.same());
                }
                return Err(ended.unwrap_or(Error::Unauthorized));
            }
            Err(e) => return Err(e),
        };
        self.set_tokens(tokens);
        Ok(())
    }

    fn request(&self, method: Method, path: &str) -> Result<RequestBuilder> {
        let url = self
            .api
            .join(path)
            .map_err(|e| Error::BadUrl(e.to_string()))?;
        Ok(self.http.request(method, url))
    }

    async fn call_anon<B: Serialize, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: &B,
    ) -> Result<T> {
        decode(self.request(method, path)?.json(body).send().await?).await
    }

    async fn authed<B: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<reqwest::Response> {
        self.authed_with(method, path, |req| match body {
            Some(b) => req.json(b),
            None => req,
        })
        .await
    }

    /// An authenticated request; `build` adds the body and headers (called again on a retry).
    async fn authed_with(
        &self,
        method: Method,
        path: &str,
        build: impl Fn(RequestBuilder) -> RequestBuilder,
    ) -> Result<reqwest::Response> {
        let access = self
            .tokens()
            .map(|t| t.access_token)
            .ok_or_else(|| self.signed_out())?;
        if access.is_empty() {
            self.refresh().await?;
        }
        for attempt in 0..2 {
            let token = self
                .tokens()
                .map(|t| t.access_token)
                .ok_or_else(|| self.signed_out())?;
            let req = build(self.request(method.clone(), path)?.bearer_auth(token));
            let started = std::time::Instant::now();
            let resp = req.send().await?;
            tracing::debug!(
                %method,
                path,
                status = resp.status().as_u16(),
                ms = started.elapsed().as_millis() as u64,
                "sync request"
            );
            if resp.status() == StatusCode::UNAUTHORIZED && attempt == 0 {
                self.refresh().await?;
                continue;
            }
            return Ok(resp);
        }
        Err(self.signed_out())
    }

    /// Not signed in: why, if the server said (see `ended`).
    fn signed_out(&self) -> Error {
        self.ended
            .lock()
            .expect("not poisoned")
            .as_ref()
            .map_or(Error::Unauthorized, Error::same)
    }

    async fn call<B: Serialize, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T> {
        decode(self.authed(method, path, body).await?).await
    }
}

/// A success without a body (202, 204), or the error the server sent.
async fn empty(resp: reqwest::Response) -> Result<()> {
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(error(resp).await)
    }
}

async fn decode<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
    if resp.status().is_success() {
        Ok(resp.json().await?)
    } else {
        Err(error(resp).await)
    }
}

/// Store builds (iOS, Android) say what's wrong but not where plans are bought: the stores don't
/// allow pointing at buying outside them (App Store 3.1.3, Google Play's payments policy).
const STORE_BUILD: bool = cfg!(any(target_os = "ios", target_os = "android"));

impl Error {
    /// A copy of a session-ending error (the others aren't kept).
    fn same(&self) -> Error {
        match self {
            Error::DeviceRevoked => Error::DeviceRevoked,
            Error::AccountDeleted => Error::AccountDeleted,
            _ => Error::Unauthorized,
        }
    }
}

fn payment_message(p: &Payment) -> String {
    let (code, reason, plan, limit) = (
        p.code.as_str(),
        p.reason.as_deref(),
        p.plan.as_deref(),
        p.limit,
    );
    if code == "upgrade_required" {
        return match plan {
            Some(p) => format!("this needs the {} plan", capitalize(p)),
            None => "this needs a higher plan".into(),
        };
    }
    if code == "team_limit" {
        let teams = match limit {
            Some(1) => "a team".to_owned(),
            Some(n) => format!("{n} teams"),
            None => "the most teams you can".to_owned(),
        };
        if STORE_BUILD {
            return format!(
                "you own {teams} without a plan, the most you can: delete one before creating another"
            );
        }
        return format!(
            "you own {teams} without a plan: choose a plan for one of them, or delete one, before creating another"
        );
    }
    match (code, reason) {
        ("seats_exceeded", _) if STORE_BUILD => "every seat of the organization's plan is taken",
        (_, Some("trial_ended")) if STORE_BUILD => "the trial has ended",
        (_, Some("lapsed")) if STORE_BUILD => "the plan has lapsed",
        ("seats_exceeded", _) => {
            "every seat of the organization's plan is taken: the owner can add seats in the account portal"
        }
        (_, Some("trial_ended")) => "the trial has ended: choose a plan in the account portal",
        (_, Some("lapsed")) => "the plan has lapsed: renew it in the account portal",
        _ => "subscription inactive",
    }
    .into()
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}

/// An error response as [`Error`], keeping the server's `{code, message}`.
async fn error(resp: reqwest::Response) -> Error {
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    let body: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
    let field = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_owned);
    match status {
        // `410` is also `invite_expired`: only a vault's lost history means "resync".
        StatusCode::GONE if field("code").is_none_or(|c| c == "gone") => Error::Gone,
        StatusCode::PAYMENT_REQUIRED => Error::PaymentRequired(Box::new(Payment {
            code: field("code").unwrap_or_else(|| "payment_required".into()),
            reason: field("reason"),
            billing_url: field("billing_url"),
            plan: field("plan"),
            feature: field("feature"),
            limit: body
                .get("limit")
                .and_then(|v| v.as_u64())
                .and_then(|n| u32::try_from(n).ok()),
        })),
        StatusCode::FORBIDDEN if field("code").as_deref() == Some("sso_required") => {
            Error::SsoRequired {
                org_id: field("org_id").unwrap_or_default(),
            }
        }
        StatusCode::FORBIDDEN if field("code").as_deref() == Some("device_approval_required") => {
            Error::DeviceApprovalRequired {
                org_id: field("org_id").unwrap_or_default(),
                denied: field("status").as_deref() == Some("denied"),
            }
        }
        _ => Error::Api {
            status: status.as_u16(),
            code: field("code").unwrap_or_else(|| status.as_str().into()),
            message: field("message")
                .unwrap_or_else(|| status.canonical_reason().unwrap_or("error").into()),
        },
    }
}

/// `localhost`, or a loopback address.
fn loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payment_errors_say_what_to_do() {
        let e = |code: &str, reason: Option<&str>, plan: Option<&str>| {
            Error::PaymentRequired(Box::new(Payment {
                code: code.into(),
                reason: reason.map(Into::into),
                billing_url: None,
                plan: plan.map(Into::into),
                feature: None,
                limit: None,
            }))
            .to_string()
        };
        assert!(e("seats_exceeded", None, None).contains("add seats"));
        assert!(e("payment_required", Some("trial_ended"), None).contains("trial has ended"));
        assert!(e("payment_required", Some("lapsed"), None).contains("renew"));
        assert_eq!(e("payment_required", None, None), "subscription inactive");
        let limit = Error::PaymentRequired(Box::new(Payment {
            code: "team_limit".into(),
            reason: None,
            billing_url: None,
            plan: None,
            feature: None,
            limit: Some(3),
        }));
        assert_eq!(
            limit.to_string(),
            "you own 3 teams without a plan: choose a plan for one of them, or delete one, before creating another"
        );
        assert_eq!(
            e("upgrade_required", None, Some("business")),
            "this needs the Business plan"
        );
    }

    #[test]
    fn plain_http_only_to_this_computer() {
        for ok in [
            "https://sync.example.com",
            "http://127.0.0.1:8443",
            "http://localhost:8443/",
            "http://[::1]:8443",
        ] {
            assert!(SyncClient::new(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://sync.example.com",
            "http://192.168.1.5:8443",
            "ftp://sync.example.com",
            "https://me:pw@sync.example.com",
        ] {
            assert!(SyncClient::new(bad).is_err(), "{bad}");
        }
        let c = SyncClient::new("https://sync.example.com/some/path?x=1#frag").unwrap();
        assert_eq!(c.origin(), "https://sync.example.com");
    }
}
