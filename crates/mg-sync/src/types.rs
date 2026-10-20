//! Wire types for `vault-sync/v1` (see `spec/openapi.yaml`). Field names are the JSON names.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const SPEC: &str = "vault-sync";
pub const VERSION: &str = "v1";

/// Binary value carried as base64url without padding.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct B64(pub Vec<u8>);

impl core::fmt::Debug for B64 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "B64({} bytes)", self.0.len())
    }
}

impl From<Vec<u8>> for B64 {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl From<&[u8]> for B64 {
    fn from(v: &[u8]) -> Self {
        Self(v.to_vec())
    }
}

impl Serialize for B64 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for B64 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        URL_SAFE_NO_PAD
            .decode(s.trim_end_matches('='))
            .map(B64)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
    /// With `403 sso_required` and `403 device_approval_required`: the organization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    /// With `403 device_approval_required`: the calling device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// With `403 device_approval_required`: `pending` or `denied`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

impl ApiError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            org_id: None,
            device_id: None,
            status: None,
        }
    }
}

// ------------------------------------------------------------------ discovery

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Capabilities {
    pub spec: String,
    pub versions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<ServerInfo>,
    pub limits: Limits,
    pub features: Features,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    #[serde(default)]
    pub version: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Limits {
    pub max_envelope_bytes: u32,
    pub max_push_items: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_items_per_vault: Option<u32>,
    pub tombstone_retention_days: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Features {
    #[serde(default)]
    pub registration_open: bool,
    /// The terms of use and privacy policy new accounts accept; `None` when the server asks
    /// for none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms: Option<Terms>,
    /// New accounts confirm their address with a mailed code (`POST /auth/register/start`),
    /// and accounts can change address.
    #[serde(default)]
    pub email_verification: bool,
    #[serde(default)]
    pub sse: bool,
    #[serde(default)]
    pub totp: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing: Option<Billing>,
    /// Organizations, members and shared vaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sharing: Option<Sharing>,
    /// Encrypted session logs and attachments (`/vaults/{id}/blobs`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blobs: Option<BlobFeatures>,
    /// Organizations can put their vaults behind their identity provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sso: Option<SsoFeatures>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobFeatures {
    pub max_blob_bytes: u64,
    /// Shared by everything one owner has: an account's personal vaults, or an organization's.
    pub quota_bytes: u64,
    /// `attachment`, `session_log`.
    pub kinds: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsoFeatures {
    /// `oidc`, `saml`.
    pub protocols: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Sharing {
    /// 0 = no limit.
    #[serde(default)]
    pub max_members_per_org: u32,
    /// 0 = no limit.
    #[serde(default)]
    pub max_vaults_per_org: u32,
    /// The server emails invite links. Otherwise the inviting admin gets the invite token to
    /// pass on.
    #[serde(default)]
    pub mails_invites: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Billing {
    pub portal_url: String,
    /// `POST /account/web-session` hands out single-use links into the account portal.
    #[serde(default)]
    pub web_session: bool,
    /// Vaults without a usable plan refuse pushes (402).
    #[serde(default)]
    pub plans_enforced: bool,
}

/// The terms of use and privacy policy a server asks accounts to accept.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Terms {
    pub version: String,
    pub terms_url: String,
    pub privacy_url: String,
}

/// The terms an account accepted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedTerms {
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcceptTermsRequest {
    pub accepted_terms: String,
}

// ------------------------------------------------------------------ auth

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub alg: String,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    pub salt: B64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    pub platform: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_version: Option<String>,
    pub public_key: B64,
}

/// What a device says about itself after signing in (`PATCH /devices/{id}`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceUpdate {
    pub name: String,
    pub platform: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_version: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    #[serde(flatten)]
    pub info: DeviceInfo,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<String>,
    #[serde(default)]
    pub current: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountKeys {
    pub enc_public_key: B64,
    pub sign_public_key: B64,
    pub wrapped_private_keys: B64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryMaterial {
    pub wrapped_private_keys_rk: B64,
    pub recovery_proof: B64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub kdf: KdfParams,
    pub auth_key: B64,
    pub keys: AccountKeys,
    pub recovery: RecoveryMaterial,
    pub device: DeviceInfo,
    /// The code mailed by `POST /auth/register/start`, on servers with `email_verification`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_code: Option<String>,
    /// The version of the server's terms the person accepted (`features.terms`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_terms: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterStartRequest {
    pub email: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreloginRequest {
    pub email: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub auth_key: B64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
    pub device: DeviceInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    #[serde(flatten)]
    pub tokens: Tokens,
    pub account_id: String,
    pub keys: AccountKeys,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub email: String,
    pub kdf: KdfParams,
    pub keys: AccountKeys,
    /// Account keys wrapped under the recovery key, so every device can offer local recovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped_private_keys_rk: Option<B64>,
    #[serde(default)]
    pub totp_enabled: bool,
    /// Whether the address was proven with a mailed code; absent on servers that don't check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// Hosted only: the plan this account is on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entitlement: Option<Entitlement>,
    /// The terms this account accepted, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms: Option<AcceptedTerms>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entitlement {
    pub plan: String,
    /// `trialing`, `active`, `grace`, `lapsed` or `canceled`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// While `grace`: until when it keeps syncing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grace_ends_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seats: Option<u32>,
    /// `mor`, `stripe`, `apple`, `google`, `manual`, or `team_seat`: a personal plan in grace
    /// because the team seat that covered it ended (then `team` names the team).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team: Option<String>,
    /// An organization's plan features (`sso`, `scim`, `session_logs`, `audit_stream`,
    /// `device_approval`): what apps offer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmailChangeStartRequest {
    pub new_email: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmailChangeRequest {
    pub new_email: String,
    pub code: String,
    pub auth_key: B64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TotpStartRequest {
    pub auth_key: B64,
}

/// A new authenticator secret, pending until a code from it comes back.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TotpSetup {
    /// Base32, for typing into an authenticator app.
    pub secret: String,
    /// `otpauth://` URI, for a QR code.
    pub uri: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TotpEnableRequest {
    pub code: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TotpDisableRequest {
    pub auth_key: B64,
    pub code: String,
}

/// A single-use link that signs this account in to the server's web portal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebSession {
    pub url: String,
    pub expires_in: u64,
}

/// `POST /account/web-session`: the portal page the link lands on (`/account` without one).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WebSessionRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RotateCredentialsRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_auth_key: Option<B64>,
    pub new_kdf: KdfParams,
    pub new_auth_key: B64,
    pub wrapped_private_keys: B64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<RecoveryMaterial>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoverRequest {
    pub email: String,
    pub recovery_proof: B64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoverResponse {
    pub wrapped_private_keys_rk: B64,
    /// Short-lived, only valid for `PUT /account/keys`.
    pub access_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeleteAccountRequest {
    pub auth_key: B64,
}

// ------------------------------------------------------------------ vaults & items

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vault {
    pub id: String,
    /// The current key generation, and the caller's copy of it.
    pub key_id: B64,
    pub wrapped_vault_key: B64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<B64>,
    pub head_rev: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_count: Option<i64>,
    pub created_at: String,
    // `sharing` servers:
    /// Owning organization; absent for a personal vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    /// The account that created the vault (and signed its `meta`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission: Option<Permission>,
    /// The caller's copy of every key generation still in the ring, oldest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<KeyGeneration>,
    /// Someone lost access: an app with `manage` should rotate the key.
    #[serde(default, skip_serializing_if = "is_false")]
    pub rotation_due: bool,
    /// Live items still under an older key generation (a rotation not finished yet).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items_on_old_keys: Option<i64>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateVault {
    pub id: String,
    pub key_id: B64,
    /// The caller's copy of the vault key.
    pub wrapped_vault_key: B64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<B64>,
    // `sharing` servers:
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    /// For an organization vault: the key sealed to every owner and admin, the caller included
    /// (its entry repeats `wrapped_vault_key`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<SealedFor>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub id: String,
    pub rev: i64,
    pub deleted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope: Option<B64>,
    pub updated_at: String,
    /// The account that pushed this revision, set by the server. Absent = the vault's owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangePage {
    pub items: Vec<Item>,
    pub head_rev: i64,
    pub has_more: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushItem {
    pub id: String,
    #[serde(default)]
    pub base_rev: i64,
    pub deleted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope: Option<B64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRequest {
    pub items: Vec<PushItem>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PushStatus {
    Accepted,
    Conflict,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushResult {
    pub id: String,
    pub status: PushStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rev: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<Item>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushResponse {
    pub results: Vec<PushResult>,
    pub head_rev: i64,
}

// ------------------------------------------------------------------ sharing

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Admin,
    Member,
}

impl Role {
    /// Owners and admins hold every organization vault key.
    pub fn is_admin(self) -> bool {
        matches!(self, Role::Owner | Role::Admin)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemberStatus {
    /// Joined through an invite; no vault keys until an admin confirms them.
    Accepted,
    Confirmed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    Read,
    Write,
    Manage,
}

/// A signature by another account (`mg_vault::sharing` messages): who signed, and the signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed {
    pub signer_id: String,
    pub sig: B64,
}

/// One owner in an organization's ownership chain. The first is the creator (no certificate);
/// each later one carries an `owner` certificate from the one before.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerLink {
    pub account_id: String,
    pub enc_public_key: B64,
    pub sign_public_key: B64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<Signed>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policies {
    /// Members without TOTP get `403 totp_setup_required` on organization vaults.
    #[serde(default)]
    pub require_totp: bool,
    #[serde(default)]
    pub members_can_create_vaults: bool,
    /// Invites only to these domains; empty = any.
    #[serde(default)]
    pub allowed_email_domains: Vec<String>,
    /// The server deletes `session_log` blobs older than this many days; 0 keeps them.
    #[serde(default)]
    pub session_log_retention_days: u32,
    /// Vaults answer `403 sso_required` until the device has signed in at the organization's
    /// identity provider (no effect without one).
    #[serde(default)]
    pub require_sso: bool,
    /// New devices get `403 device_approval_required` on the organization's vaults until an
    /// owner or admin, or the member from one of their approved devices, approves them.
    #[serde(default)]
    pub require_device_approval: bool,
    /// Members publish the SSH public keys they use on the organization's hosts (in the member
    /// key directory), so offboarding can find them; apps remind those who haven't. `None`: the
    /// server doesn't say (and isn't sent it, since servers may refuse policies they don't know).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_member_keys: Option<bool>,
}

/// A confirmed member's `member` certificate, signed again by the caller (an owner or admin).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberCertificate {
    pub member_cert: B64,
}

/// A device's request to open an organization's vaults, and its decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceApproval {
    pub account_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_version: Option<String>,
    /// `pending`, `approved` or `denied`.
    pub status: String,
    pub requested_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<String>,
    /// The account that decided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Org {
    pub id: String,
    /// Plaintext: invites and emails show it.
    pub name: String,
    pub owner_id: String,
    pub owner_chain: Vec<OwnerLink>,
    #[serde(default)]
    pub policies: Policies,
    pub created_at: String,
    /// Hosted only: the organization's plan (`seats` = seats bought).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entitlement: Option<Entitlement>,
}

/// An organization in the caller's list (`GET /orgs`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgMembership {
    pub id: String,
    pub name: String,
    pub role: Role,
    pub status: MemberStatus,
    /// Changes whenever the organization's details, members, device approvals or who can open
    /// its vaults change: a client that saw this value can keep what it fetched then. Servers
    /// without it leave it out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rev: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateOrg {
    /// ULID, client-generated (certificates bind it).
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateOrg {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policies: Option<Policies>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub account_id: String,
    pub email: String,
    pub role: Role,
    pub status: MemberStatus,
    pub enc_public_key: B64,
    pub sign_public_key: B64,
    /// Present once confirmed (the creator has none: it is the chain's root).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_cert: Option<Signed>,
    /// Present for admins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_cert: Option<Signed>,
    pub joined_at: String,
    /// For an accepted member, to owners and admins: the vault access their invite grants, whose
    /// keys the confirming app seals to them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_vaults: Vec<VaultGrant>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultGrant {
    pub vault_id: String,
    pub permission: Permission,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateInvite {
    pub email: String,
    /// `member` or `admin` (only an owner invites admins).
    pub role: Role,
    /// Vault access the member gets when an admin confirms them.
    #[serde(default)]
    pub vaults: Vec<VaultGrant>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    pub id: String,
    pub org_id: String,
    pub email: String,
    pub role: Role,
    #[serde(default)]
    pub vaults: Vec<VaultGrant>,
    pub created_at: String,
    pub expires_at: String,
    /// Only when the server doesn't mail invites, and only in the response that created it:
    /// the inviting admin passes it on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

/// What an invite token shows before accepting (`GET /invites/{token}`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteInfo {
    pub org_id: String,
    pub org_name: String,
    pub email: String,
    pub role: Role,
    pub inviter_email: String,
    /// The invitee pins the first link and checks the chain to the current owner, whose
    /// fingerprint the app shows.
    pub owner_chain: Vec<OwnerLink>,
    pub expires_at: String,
}

/// A vault key sealed to `account_id`, with the sealer's grant signature (the sealer is the
/// caller).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedFor {
    pub account_id: String,
    pub wrapped_vault_key: B64,
    pub grant_sig: B64,
}

/// A vault key generation sealed to the member being confirmed or promoted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberVaultKey {
    pub vault_id: String,
    pub key_id: B64,
    pub wrapped_vault_key: B64,
    pub grant_sig: B64,
}

/// A key generation sealed to a member being granted a vault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantKey {
    pub key_id: B64,
    pub wrapped_vault_key: B64,
    pub grant_sig: B64,
}

/// The caller's copy of one key generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyGeneration {
    pub key_id: B64,
    pub wrapped_vault_key: B64,
    /// Who sealed it; absent for a personal vault's own key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<Signed>,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmMember {
    /// `member` certificate over the member's keys, by the caller.
    pub member_cert: B64,
    /// Required when the member's role is `admin` (and then the caller must be an owner).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_cert: Option<B64>,
    /// Every key generation of each vault the member gets: the invite's grants, or every
    /// organization vault for an admin.
    #[serde(default)]
    pub vault_keys: Vec<MemberVaultKey>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateMember {
    pub role: Role,
    /// Required when promoting to `admin`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_cert: Option<B64>,
    /// When promoting to `admin`: every organization vault key the member doesn't have yet.
    #[serde(default)]
    pub vault_keys: Vec<MemberVaultKey>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferOrg {
    pub account_id: String,
    pub auth_key: B64,
    /// `owner` certificate over the new owner's keys, by the caller.
    pub owner_cert: B64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeleteOrg {
    pub auth_key: B64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMember {
    pub account_id: String,
    pub permission: Permission,
    /// Owners and admins: access that comes with the role, not a grant.
    #[serde(default, skip_serializing_if = "is_false")]
    pub implicit: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetVaultMember {
    pub permission: Permission,
    /// When granting access: every key generation in the ring, sealed to the member.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<GrantKey>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotateVaultKey {
    pub key_id: B64,
    pub previous_key_id: B64,
    /// The new key sealed to every account with access.
    pub wrapped: Vec<SealedFor>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgEvent {
    pub seq: i64,
    pub at: String,
    /// `member_invited`, `member_confirmed`, `vault_key_rotated`, … (see the spec).
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventPage {
    pub events: Vec<OrgEvent>,
    pub has_more: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_is_url_safe_unpadded_and_lenient_on_input() {
        let v = B64(vec![0xfb, 0xff, 0x00]);
        assert_eq!(serde_json::to_string(&v).unwrap(), "\"-_8A\"");
        let back: B64 = serde_json::from_str("\"-_8A\"").unwrap();
        assert_eq!(back, v);
        let padded: B64 = serde_json::from_str("\"AQ==\"").unwrap();
        assert_eq!(padded.0, [1]);
    }

    #[test]
    fn hosted_extras_are_optional_both_ways() {
        // An older server: none of the new fields.
        let caps: Capabilities = serde_json::from_value(serde_json::json!({
            "spec": "vault-sync", "versions": ["v1"],
            "limits": { "max_envelope_bytes": 65536, "max_push_items": 500, "tombstone_retention_days": 90 },
            "features": { "registration_open": true, "billing": { "portal_url": "https://x" } }
        }))
        .unwrap();
        assert!(!caps.features.email_verification);
        assert!(!caps.features.billing.unwrap().web_session);

        let account: Account = serde_json::from_value(serde_json::json!({
            "id": "01A", "email": "a@example.com",
            "kdf": { "alg": "argon2id", "m_kib": 65536, "t": 2, "p": 1, "salt": "AQ" },
            "keys": { "enc_public_key": "AQ", "sign_public_key": "Ag", "wrapped_private_keys": "Aw" },
            "email_verified": true,
            "entitlement": { "plan": "personal", "status": "trialing", "expires_at": "2026-10-30T12:00:00Z" }
        }))
        .unwrap();
        assert_eq!(account.email_verified, Some(true));
        assert_eq!(
            account.entitlement.unwrap().status.as_deref(),
            Some("trialing")
        );

        // A request without a code doesn't send the field at all.
        let start = serde_json::to_value(RegisterStartRequest {
            email: "a@example.com".into(),
        })
        .unwrap();
        assert_eq!(start, serde_json::json!({ "email": "a@example.com" }));
    }

    #[test]
    fn a_seat_that_ended_reads_as_personal_grace() {
        let e: Entitlement = serde_json::from_value(serde_json::json!({
            "plan": "personal", "status": "grace", "expires_at": "2026-10-20T08:00:00Z",
            "grace_ends_at": "2026-11-03T08:00:00Z", "source": "team_seat", "team": "Acme"
        }))
        .unwrap();
        assert_eq!(e.grace_ends_at.as_deref(), Some("2026-11-03T08:00:00Z"));
        assert_eq!(
            (e.source.as_deref(), e.team.as_deref()),
            (Some("team_seat"), Some("Acme"))
        );
    }

    #[test]
    fn an_organization_may_carry_its_plan() {
        let org: Org = serde_json::from_value(serde_json::json!({
            "id": "01JORG00000000000000000000", "name": "Acme", "owner_id": "A",
            "owner_chain": [], "created_at": "2026-10-16T12:00:00Z",
            "entitlement": { "plan": "team", "status": "trialing", "seats": 5 }
        }))
        .unwrap();
        assert_eq!(org.entitlement.unwrap().seats, Some(5));
        let bare: Org = serde_json::from_value(serde_json::json!({
            "id": "01JORG00000000000000000000", "name": "Acme", "owner_id": "A",
            "owner_chain": [], "created_at": "2026-10-16T12:00:00Z"
        }))
        .unwrap();
        assert!(bare.entitlement.is_none());
        assert!(
            !serde_json::to_string(&bare)
                .unwrap()
                .contains("entitlement")
        );
    }

    #[test]
    fn sharing_fields_are_optional_both_ways() {
        // A server without sharing: vaults and items as before.
        let v: Vault = serde_json::from_value(serde_json::json!({
            "id": "01V", "key_id": "AQ", "wrapped_vault_key": "Ag", "head_rev": 3,
            "created_at": "2026-10-16T12:00:00Z"
        }))
        .unwrap();
        assert!(
            v.org_id.is_none() && v.keys.is_empty() && !v.rotation_due && v.permission.is_none()
        );
        let i: Item = serde_json::from_value(serde_json::json!({
            "id": "01I", "rev": 1, "deleted": false, "updated_at": "2026-10-16T12:00:00Z"
        }))
        .unwrap();
        assert!(i.author_id.is_none());
        let f: Features =
            serde_json::from_value(serde_json::json!({ "registration_open": true })).unwrap();
        assert!(f.sharing.is_none());

        // A personal vault doesn't grow sharing fields on the wire.
        let out = serde_json::to_value(&v).unwrap();
        for key in ["org_id", "keys", "rotation_due", "permission", "created_by"] {
            assert!(out.get(key).is_none(), "{key}");
        }
        let perm: Permission = serde_json::from_value(serde_json::json!("manage")).unwrap();
        assert!(perm > Permission::Write && Permission::Write > Permission::Read);
        assert!(Role::Owner.is_admin() && !Role::Member.is_admin());
    }

    #[test]
    fn session_flattens_tokens() {
        let s: Session = serde_json::from_value(serde_json::json!({
            "access_token": "a", "refresh_token": "r", "expires_in": 900, "account_id": "01A",
            "keys": { "enc_public_key": "AQ", "sign_public_key": "Ag", "wrapped_private_keys": "Aw" }
        }))
        .unwrap();
        assert_eq!(s.tokens.expires_in, 900);
        assert_eq!(s.keys.sign_public_key.0, [2]);
    }
}

// ------------------------------------------------------------------ blobs

/// A blob's metadata: the server stores ciphertext named by its SHA-256.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobInfo {
    /// Lowercase hex SHA-256 of the bytes.
    pub hash: String,
    pub size: u64,
    /// `attachment` or `session_log`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_id: Option<String>,
    pub created_at: String,
}

// ------------------------------------------------------------------ single sign-on

/// `GET /orgs/{id}/sso`: whether the organization uses an identity provider, and this device's
/// session with it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsoStatus {
    pub configured: bool,
    /// `require_sso` is on (and a provider is configured).
    #[serde(default)]
    pub required: bool,
    /// `oidc` or `saml`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// This device's session; absent when it has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_expires_at: Option<String>,
}

/// `POST /orgs/{id}/sso/start`: open `url` in a browser; the sign-in is valid `expires_in`
/// seconds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsoStart {
    pub url: String,
    pub expires_in: u32,
}
