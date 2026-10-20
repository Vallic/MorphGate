//! Organizations, members, invites and shared vaults (the `sharing` capability).
//!
//! The server relays and enforces; it never holds a vault key. Everything that needs one (sealing a
//! key to a new member, rotating) arrives already sealed and signed from an app. The server checks
//! shape and completeness; apps check the signatures.

use std::collections::{BTreeSet, HashMap};

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use mg_sync::*;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

use crate::AppState;
use crate::api::{R, blocking, check_email, require_full};
use crate::auth::{self, Caller};
use crate::util::{Fail, now, now_secs, random, rfc3339, valid_id};

const INVITE_TTL: i64 = 7 * 24 * 3600;
const MAX_NAME: usize = 100;

// ------------------------------------------------------------------ helpers

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

pub(crate) fn perm_str(p: Permission) -> &'static str {
    match p {
        Permission::Read => "read",
        Permission::Write => "write",
        Permission::Manage => "manage",
    }
}

fn parse_perm(s: &str) -> Permission {
    match s {
        "manage" => Permission::Manage,
        "write" => Permission::Write,
        _ => Permission::Read,
    }
}

fn parse_status(s: &str) -> MemberStatus {
    if s == "confirmed" {
        MemberStatus::Confirmed
    } else {
        MemberStatus::Accepted
    }
}

pub(crate) fn not_permitted(message: impl Into<String>) -> Fail {
    Fail::new(StatusCode::FORBIDDEN, "not_permitted", message)
}

fn conflict(code: &str, message: impl Into<String>) -> Fail {
    Fail::new(StatusCode::CONFLICT, code, message)
}

fn incomplete(code: &str, message: impl Into<String>) -> Fail {
    Fail::new(StatusCode::BAD_REQUEST, code, message)
}

fn check_name(name: &str) -> Result<String, Fail> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME {
        return Err(Fail::bad(format!(
            "an organization name has 1 to {MAX_NAME} characters"
        )));
    }
    Ok(name.to_owned())
}

fn check_sig(sig: &B64, what: &str) -> Result<(), Fail> {
    if sig.0.len() == 64 {
        Ok(())
    } else {
        Err(Fail::bad(format!("{what} must be a 64-byte signature")))
    }
}

fn check_wrapped(wrapped: &B64) -> Result<(), Fail> {
    if (1..=1024).contains(&wrapped.0.len()) {
        Ok(())
    } else {
        Err(Fail::bad("malformed sealed vault key"))
    }
}

pub(crate) fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// Records what happened in an organization, which changed it (see [`touch`]).
pub(crate) fn event(
    db: &Connection,
    org: &str,
    kind: &str,
    actor: Option<&str>,
    target: Option<&str>,
    vault: Option<&str>,
    detail: Option<&str>,
) -> rusqlite::Result<()> {
    db.execute(
        "INSERT INTO events (org_id, at, kind, actor_id, target_id, vault_id, detail) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![org, now(), kind, actor, target, vault, detail],
    )?;
    touch(db, org)
}

/// Bumps an organization's `rev` (in `GET /orgs`): something its members' apps fetch changed
/// (its details, members, device approvals, who can open its vaults), so they fetch it again.
/// Changes that record an [`event`] bump it there; the rest call this.
pub(crate) fn touch(db: &Connection, org: &str) -> rusqlite::Result<()> {
    db.execute("UPDATE orgs SET rev = rev + 1 WHERE id = ?1", [org])?;
    Ok(())
}

pub(crate) struct Membership {
    role: Role,
    status: MemberStatus,
}

impl Membership {
    pub(crate) fn is_admin(&self) -> bool {
        self.role.is_admin()
    }
}

fn membership(db: &Connection, org: &str, account: &str) -> rusqlite::Result<Option<Membership>> {
    db.query_row(
        "SELECT role, status FROM members WHERE org_id = ?1 AND account_id = ?2",
        params![org, account],
        |r| {
            Ok(Membership {
                role: parse_role(&r.get::<_, String>(0)?),
                status: parse_status(&r.get::<_, String>(1)?),
            })
        },
    )
    .optional()
}

/// Any member, confirmed or not; others get 404 (organizations are not revealed).
pub(crate) fn require_any_member(
    db: &Connection,
    c: &Caller,
    org: &str,
) -> Result<Membership, Fail> {
    membership(db, org, &c.account)?.ok_or_else(Fail::not_found)
}

pub(crate) fn require_confirmed(
    db: &Connection,
    c: &Caller,
    org: &str,
) -> Result<Membership, Fail> {
    let m = require_any_member(db, c, org)?;
    if m.status != MemberStatus::Confirmed {
        return Err(not_permitted("an admin hasn't confirmed you yet"));
    }
    Ok(m)
}

fn require_admin(db: &Connection, c: &Caller, org: &str) -> Result<Membership, Fail> {
    let m = require_confirmed(db, c, org)?;
    if !m.role.is_admin() {
        return Err(not_permitted("only owners and admins can do this"));
    }
    Ok(m)
}

fn require_owner(db: &Connection, c: &Caller, org: &str) -> Result<Membership, Fail> {
    let m = require_confirmed(db, c, org)?;
    if m.role != Role::Owner {
        return Err(not_permitted("only the owner can do this"));
    }
    Ok(m)
}

pub(crate) fn is_org_admin(db: &Connection, org: &str, account: &str) -> rusqlite::Result<bool> {
    Ok(matches!(
        membership(db, org, account)?,
        Some(m) if m.status == MemberStatus::Confirmed && m.role.is_admin()
    ))
}

/// Confirmed owners and admins.
fn org_admins(db: &Connection, org: &str) -> rusqlite::Result<BTreeSet<String>> {
    let mut stmt = db.prepare(
        "SELECT account_id FROM members WHERE org_id = ?1 AND status = 'confirmed' AND role IN ('owner', 'admin')",
    )?;
    stmt.query_map([org], |r| r.get(0))?.collect()
}

/// Every vault of an organization with its current key generation.
fn org_vaults(db: &Connection, org: &str) -> rusqlite::Result<Vec<(String, Vec<u8>)>> {
    let mut stmt = db.prepare("SELECT id, key_id FROM vaults WHERE org_id = ?1")?;
    stmt.query_map([org], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect()
}

/// The key generations a vault has (current included).
fn ring(db: &Connection, vault: &str) -> rusqlite::Result<BTreeSet<Vec<u8>>> {
    let mut stmt = db.prepare(
        "SELECT key_id FROM vault_keys WHERE vault_id = ?1 UNION SELECT key_id FROM vaults WHERE id = ?1",
    )?;
    stmt.query_map([vault], |r| r.get(0))?.collect()
}

fn store_key(
    db: &Connection,
    vault: &str,
    key_id: &[u8],
    account: &str,
    wrapped: &[u8],
    signer: Option<&str>,
    sig: Option<&[u8]>,
) -> rusqlite::Result<()> {
    db.execute(
        "INSERT INTO vault_keys (vault_id, key_id, account_id, wrapped, signer_id, sig, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT (vault_id, key_id, account_id) DO UPDATE SET wrapped = excluded.wrapped,
             signer_id = excluded.signer_id, sig = excluded.sig",
        params![vault, key_id, account, wrapped, signer, sig, now()],
    )?;
    Ok(())
}

/// What the caller may do with a vault.
pub(crate) struct VaultAccess {
    pub org_id: Option<String>,
    pub permission: Permission,
}

pub(crate) fn vault_access(
    db: &Connection,
    account: &str,
    vault: &str,
) -> rusqlite::Result<Option<VaultAccess>> {
    let row: Option<(String, Option<String>)> = db
        .query_row(
            "SELECT account_id, org_id FROM vaults WHERE id = ?1",
            [vault],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((owner, org)) = row else {
        return Ok(None);
    };
    let Some(org) = org else {
        return Ok((owner == account).then_some(VaultAccess {
            org_id: None,
            permission: Permission::Manage,
        }));
    };
    let permission = match membership(db, &org, account)? {
        Some(m) if m.status == MemberStatus::Confirmed && m.role.is_admin() => {
            Some(Permission::Manage)
        }
        Some(m) if m.status == MemberStatus::Confirmed => db
            .query_row(
                "SELECT permission FROM vault_members WHERE vault_id = ?1 AND account_id = ?2",
                params![vault, account],
                |r| Ok(parse_perm(&r.get::<_, String>(0)?)),
            )
            .optional()?,
        _ => None,
    };
    Ok(permission.map(|permission| VaultAccess {
        org_id: Some(org),
        permission,
    }))
}

/// The vault if the caller has at least `needed`; 404 without any access, 403 with too little.
pub(crate) fn require_vault(
    db: &Connection,
    c: &Caller,
    vault: &str,
    needed: Permission,
) -> Result<VaultAccess, Fail> {
    let access = vault_access(db, &c.account, vault)?.ok_or_else(Fail::not_found)?;
    if access.permission < needed {
        return Err(not_permitted(format!(
            "this needs {} access to the vault",
            perm_str(needed)
        )));
    }
    if let Some(org) = &access.org_id {
        crate::sso::gate(db, org, c)?;
        crate::approvals::gate(db, org, c)?;
    }
    Ok(access)
}

/// Accounts that can open a vault: its owner, or the organization's admins plus granted members.
fn vault_accounts(db: &Connection, vault: &str) -> rusqlite::Result<BTreeSet<String>> {
    let (owner, org): (String, Option<String>) = db.query_row(
        "SELECT account_id, org_id FROM vaults WHERE id = ?1",
        [vault],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let Some(org) = org else {
        return Ok(BTreeSet::from([owner]));
    };
    let mut accounts = org_admins(db, &org)?;
    let mut stmt = db.prepare(
        "SELECT vm.account_id FROM vault_members vm
         JOIN members m ON m.org_id = ?2 AND m.account_id = vm.account_id AND m.status = 'confirmed'
         WHERE vm.vault_id = ?1",
    )?;
    for a in stmt.query_map(params![vault, org], |r| r.get::<_, String>(0))? {
        accounts.insert(a?);
    }
    Ok(accounts)
}

/// Checks keys sealed to one member: each vault in `required` needs its current generation, and
/// every entry must be a generation of a vault in `allowed` (which includes `required`).
fn check_member_keys(
    db: &Connection,
    keys: &[MemberVaultKey],
    required: &BTreeSet<String>,
    allowed: &BTreeSet<String>,
) -> Result<(), Fail> {
    let mut rings: HashMap<String, (Vec<u8>, BTreeSet<Vec<u8>>)> = HashMap::new();
    for v in required.union(allowed) {
        let current: Vec<u8> =
            db.query_row("SELECT key_id FROM vaults WHERE id = ?1", [v], |r| r.get(0))?;
        rings.insert(v.clone(), (current, ring(db, v)?));
    }
    for k in keys {
        check_wrapped(&k.wrapped_vault_key)?;
        check_sig(&k.grant_sig, "grant_sig")?;
        let Some((_, ring)) = rings.get(&k.vault_id) else {
            return Err(Fail::bad(format!(
                "no key is wanted for vault {}",
                k.vault_id
            )));
        };
        if !ring.contains(&k.key_id.0) {
            return Err(Fail::bad(format!(
                "key_id is not a key generation of vault {}",
                k.vault_id
            )));
        }
    }
    for (vault, (current, _)) in rings.iter().filter(|(v, _)| required.contains(*v)) {
        if !keys
            .iter()
            .any(|k| &k.vault_id == vault && &k.key_id.0 == current)
        {
            return Err(incomplete(
                "incomplete_keys",
                format!("the current key of vault {vault} is missing"),
            ));
        }
    }
    Ok(())
}

fn owner_chain(db: &Connection, org: &str) -> rusqlite::Result<Vec<OwnerLink>> {
    let mut stmt = db.prepare(
        "SELECT account_id, enc_pub, sign_pub, signer_id, sig FROM owner_chain WHERE org_id = ?1 ORDER BY seq",
    )?;
    stmt.query_map([org], |r| {
        let signer: Option<String> = r.get(3)?;
        let sig: Option<Vec<u8>> = r.get(4)?;
        Ok(OwnerLink {
            account_id: r.get(0)?,
            enc_public_key: B64(r.get(1)?),
            sign_public_key: B64(r.get(2)?),
            cert: signer.zip(sig).map(|(signer_id, sig)| Signed {
                signer_id,
                sig: B64(sig),
            }),
        })
    })?
    .collect()
}

fn load_org(db: &Connection, org: &str) -> Result<Org, Fail> {
    let row: Option<(String, String, String, String)> = db
        .query_row(
            "SELECT name, owner_id, policies, created_at FROM orgs WHERE id = ?1",
            [org],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let (name, owner_id, policies, created_at) = row.ok_or_else(Fail::not_found)?;
    Ok(Org {
        id: org.to_owned(),
        name,
        owner_id,
        owner_chain: owner_chain(db, org)?,
        policies: serde_json::from_str(&policies).unwrap_or_default(),
        created_at,
        // Plans are a hosted matter.
        entitlement: None,
    })
}

pub(crate) fn org_policies(db: &Connection, org: &str) -> rusqlite::Result<Policies> {
    policies(db, org)
}

fn policies(db: &Connection, org: &str) -> rusqlite::Result<Policies> {
    let raw: String = db.query_row("SELECT policies FROM orgs WHERE id = ?1", [org], |r| {
        r.get(0)
    })?;
    Ok(serde_json::from_str(&raw).unwrap_or_default())
}

fn signed(signer: Option<String>, sig: Option<Vec<u8>>) -> Option<Signed> {
    signer.zip(sig).map(|(signer_id, sig)| Signed {
        signer_id,
        sig: B64(sig),
    })
}

fn load_member(db: &Connection, org: &str, account: &str) -> Result<Member, Fail> {
    db.query_row(
        &format!("{MEMBER_SELECT} WHERE m.org_id = ?1 AND m.account_id = ?2"),
        params![org, account],
        member_row,
    )
    .optional()?
    .ok_or_else(Fail::not_found)
}

const MEMBER_SELECT: &str = "SELECT m.account_id, a.email, m.role, m.status, a.enc_pub, a.sign_pub,
    m.member_signer, m.member_sig, m.admin_signer, m.admin_sig, m.joined_at, m.pending_vaults
    FROM members m JOIN accounts a ON a.id = m.account_id";

fn member_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Member> {
    Ok(Member {
        account_id: r.get(0)?,
        email: r.get(1)?,
        role: parse_role(&r.get::<_, String>(2)?),
        status: parse_status(&r.get::<_, String>(3)?),
        enc_public_key: B64(r.get(4)?),
        sign_public_key: B64(r.get(5)?),
        member_cert: signed(r.get(6)?, r.get(7)?),
        admin_cert: signed(r.get(8)?, r.get(9)?),
        joined_at: r.get(10)?,
        pending_vaults: serde_json::from_str(&r.get::<_, String>(11)?).unwrap_or_default(),
    })
}

/// Takes a member out of an organization: their grants and sealed keys go, and every vault they
/// could open wants a new key.
pub(crate) fn remove_member_rows(
    db: &Connection,
    org: &str,
    account: &str,
) -> rusqlite::Result<()> {
    touch(db, org)?;
    let was_confirmed_admin = matches!(
        membership(db, org, account)?,
        Some(m) if m.status == MemberStatus::Confirmed && m.role.is_admin()
    );
    let affected: Vec<String> = if was_confirmed_admin {
        org_vaults(db, org)?.into_iter().map(|(v, _)| v).collect()
    } else {
        let mut stmt = db.prepare(
            "SELECT vm.vault_id FROM vault_members vm JOIN vaults v ON v.id = vm.vault_id
             WHERE v.org_id = ?1 AND vm.account_id = ?2",
        )?;
        stmt.query_map(params![org, account], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?
    };
    for vault in &affected {
        db.execute(
            "DELETE FROM vault_members WHERE vault_id = ?1 AND account_id = ?2",
            params![vault, account],
        )?;
        db.execute(
            "DELETE FROM vault_keys WHERE vault_id = ?1 AND account_id = ?2",
            params![vault, account],
        )?;
        db.execute("UPDATE vaults SET rotation_due = 1 WHERE id = ?1", [vault])?;
    }
    db.execute(
        "DELETE FROM members WHERE org_id = ?1 AND account_id = ?2",
        params![org, account],
    )?;
    crate::sso::end_sessions(db, org, account)?;
    crate::approvals::forget_member(db, org, account)?;
    Ok(())
}

/// Before an account goes: refuse if it owns an organization, else leave every organization
/// (so their vaults get flagged for rotation).
pub(crate) fn leave_all(db: &Connection, account: &str) -> Result<(), Fail> {
    let owns: bool = db.query_row(
        "SELECT EXISTS (SELECT 1 FROM orgs WHERE owner_id = ?1)",
        [account],
        |r| r.get(0),
    )?;
    if owns {
        return Err(conflict(
            "sole_owner",
            "transfer or delete your organizations first",
        ));
    }
    let orgs: Vec<String> = {
        let mut stmt = db.prepare("SELECT org_id FROM members WHERE account_id = ?1")?;
        stmt.query_map([account], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?
    };
    for org in orgs {
        remove_member_rows(db, &org, account)?;
        event(
            db,
            &org,
            "member_left",
            Some(account),
            Some(account),
            None,
            None,
        )?;
    }
    Ok(())
}

// ------------------------------------------------------------------ organizations

pub(crate) async fn list_orgs(State(s): State<AppState>, c: Caller) -> R<Vec<OrgMembership>> {
    require_full(&c)?;
    let db = s.conn()?;
    let mut stmt = db.prepare(
        "SELECT o.id, o.name, m.role, m.status, o.rev FROM members m JOIN orgs o ON o.id = m.org_id
         WHERE m.account_id = ?1 ORDER BY o.name, o.id",
    )?;
    let orgs = stmt
        .query_map([&c.account], |r| {
            Ok(OrgMembership {
                id: r.get(0)?,
                name: r.get(1)?,
                role: parse_role(&r.get::<_, String>(2)?),
                status: parse_status(&r.get::<_, String>(3)?),
                rev: Some(r.get::<_, i64>(4)?.unsigned_abs()),
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Json(orgs))
}

pub(crate) async fn create_org(
    State(s): State<AppState>,
    c: Caller,
    Json(req): Json<CreateOrg>,
) -> Result<(StatusCode, Json<Org>), Fail> {
    require_full(&c)?;
    if !valid_id(&req.id) {
        return Err(Fail::bad("organization id must be a ULID"));
    }
    let name = check_name(&req.name)?;
    let mut db = s.conn()?;
    let tx = db.transaction()?;
    let (enc, sign): (Vec<u8>, Vec<u8>) = tx.query_row(
        "SELECT enc_pub, sign_pub FROM accounts WHERE id = ?1",
        [&c.account],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let stamp = now();
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO orgs (id, name, owner_id, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![req.id, name, c.account, stamp],
    )?;
    if inserted == 0 {
        return Err(conflict("org_exists", "organization id already in use"));
    }
    tx.execute(
        "INSERT INTO owner_chain (org_id, seq, account_id, enc_pub, sign_pub) VALUES (?1, 0, ?2, ?3, ?4)",
        params![req.id, c.account, enc, sign],
    )?;
    tx.execute(
        "INSERT INTO members (org_id, account_id, role, status, joined_at) VALUES (?1, ?2, 'owner', 'confirmed', ?3)",
        params![req.id, c.account, stamp],
    )?;
    event(
        &tx,
        &req.id,
        "org_created",
        Some(&c.account),
        None,
        None,
        Some(&name),
    )?;
    let org = load_org(&tx, &req.id)?;
    tx.commit()?;
    Ok((StatusCode::CREATED, Json(org)))
}

pub(crate) async fn get_org(
    State(s): State<AppState>,
    c: Caller,
    Path(org): Path<String>,
) -> R<Org> {
    require_full(&c)?;
    let db = s.conn()?;
    require_any_member(&db, &c, &org)?;
    Ok(Json(load_org(&db, &org)?))
}

pub(crate) async fn update_org(
    State(s): State<AppState>,
    c: Caller,
    Path(org): Path<String>,
    Json(req): Json<UpdateOrg>,
) -> R<Org> {
    require_full(&c)?;
    let mut db = s.conn()?;
    let tx = db.transaction()?;
    require_admin(&tx, &c, &org)?;
    if let Some(name) = &req.name {
        let name = check_name(name)?;
        tx.execute(
            "UPDATE orgs SET name = ?2 WHERE id = ?1",
            params![org, name],
        )?;
    }
    if let Some(p) = req.policies {
        if p.require_totp {
            return Err(Fail::new(
                StatusCode::NOT_IMPLEMENTED,
                "not_supported",
                "this server has no two-step verification to require",
            ));
        }
        if p.session_log_retention_days > 3650 {
            return Err(Fail::bad("session_log_retention_days is 0 to 3650"));
        }
        let mut domains = Vec::new();
        for d in &p.allowed_email_domains {
            let d = d.trim().trim_start_matches('@').to_ascii_lowercase();
            if d.is_empty() || !d.contains('.') || d.contains('@') || d.len() > 253 {
                return Err(Fail::bad(format!("not a domain: {d}")));
            }
            domains.push(d);
        }
        let p = Policies {
            allowed_email_domains: domains,
            ..p
        };
        // Turning approval on approves the devices members have now, so nobody is locked out.
        if p.require_device_approval && !policies(&tx, &org)?.require_device_approval {
            crate::approvals::approve_existing(&tx, &org, None, &c.account)?;
        }
        let raw = serde_json::to_string(&p).expect("serializable");
        tx.execute(
            "UPDATE orgs SET policies = ?2 WHERE id = ?1",
            params![org, raw],
        )?;
    }
    event(&tx, &org, "org_updated", Some(&c.account), None, None, None)?;
    let out = load_org(&tx, &org)?;
    tx.commit()?;
    Ok(Json(out))
}

pub(crate) async fn delete_org(
    State(s): State<AppState>,
    c: Caller,
    Path(org): Path<String>,
    Json(req): Json<DeleteOrg>,
) -> Result<StatusCode, Fail> {
    require_full(&c)?;
    blocking(&s, move |s| {
        require_owner(&*s.conn()?, &c, &org)?;
        let hash: String = s.conn()?.query_row(
            "SELECT auth_hash FROM accounts WHERE id = ?1",
            [&c.account],
            |r| r.get(0),
        )?;
        if !auth::verify_secret(&req.auth_key.0, &hash) {
            return Err(Fail::unauthorized());
        }
        // Vaults (and their items and keys) go with the organization.
        s.conn()?
            .execute("DELETE FROM orgs WHERE id = ?1", [&org])?;
        tracing::info!(%org, "organization deleted");
        Ok(StatusCode::NO_CONTENT)
    })
    .await
}

pub(crate) async fn transfer_org(
    State(s): State<AppState>,
    c: Caller,
    Path(org): Path<String>,
    Json(req): Json<TransferOrg>,
) -> R<Org> {
    require_full(&c)?;
    check_sig(&req.owner_cert, "owner_cert")?;
    blocking(&s, move |s| {
        let hash: String = s.conn()?.query_row(
            "SELECT auth_hash FROM accounts WHERE id = ?1",
            [&c.account],
            |r| r.get(0),
        )?;
        if !auth::verify_secret(&req.auth_key.0, &hash) {
            return Err(Fail::unauthorized());
        }
        let mut db = s.conn()?;
        let tx = db.transaction()?;
        require_owner(&tx, &c, &org)?;
        match membership(&tx, &org, &req.account_id)? {
            Some(m) if m.status == MemberStatus::Confirmed && m.role == Role::Admin => {}
            _ => {
                return Err(Fail::bad("the new owner must be a confirmed admin"));
            }
        }
        let (enc, sign): (Vec<u8>, Vec<u8>) = tx.query_row(
            "SELECT enc_pub, sign_pub FROM accounts WHERE id = ?1",
            [&req.account_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let seq: i64 = tx.query_row(
            "SELECT COALESCE(MAX(seq), -1) + 1 FROM owner_chain WHERE org_id = ?1",
            [&org],
            |r| r.get(0),
        )?;
        tx.execute(
            "INSERT INTO owner_chain (org_id, seq, account_id, enc_pub, sign_pub, signer_id, sig) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![org, seq, req.account_id, enc, sign, c.account, req.owner_cert.0],
        )?;
        tx.execute("UPDATE orgs SET owner_id = ?2 WHERE id = ?1", params![org, req.account_id])?;
        tx.execute(
            "UPDATE members SET role = 'owner' WHERE org_id = ?1 AND account_id = ?2",
            params![org, req.account_id],
        )?;
        tx.execute(
            "UPDATE members SET role = 'admin' WHERE org_id = ?1 AND account_id = ?2",
            params![org, c.account],
        )?;
        // Organization vaults belong to whoever owns the organization.
        tx.execute("UPDATE vaults SET account_id = ?2 WHERE org_id = ?1", params![org, req.account_id])?;
        event(&tx, &org, "ownership_transferred", Some(&c.account), Some(&req.account_id), None, None)?;
        let out = load_org(&tx, &org)?;
        tx.commit()?;
        Ok(Json(out))
    })
    .await
}

#[derive(serde::Deserialize)]
pub(crate) struct Since {
    #[serde(default)]
    since: i64,
    #[serde(default)]
    limit: Option<u32>,
}

pub(crate) async fn org_events(
    State(s): State<AppState>,
    c: Caller,
    Path(org): Path<String>,
    Query(q): Query<Since>,
) -> R<EventPage> {
    require_full(&c)?;
    let db = s.conn()?;
    require_admin(&db, &c, &org)?;
    let limit = q.limit.unwrap_or(500).clamp(1, 1000);
    let mut stmt = db.prepare(
        "SELECT seq, at, kind, actor_id, target_id, vault_id, detail FROM events
         WHERE org_id = ?1 AND seq > ?2 ORDER BY seq LIMIT ?3",
    )?;
    let mut events = stmt
        .query_map(params![org, q.since, limit + 1], |r| {
            Ok(OrgEvent {
                seq: r.get(0)?,
                at: r.get(1)?,
                kind: r.get(2)?,
                actor_id: r.get(3)?,
                target_id: r.get(4)?,
                vault_id: r.get(5)?,
                detail: r.get(6)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let has_more = events.len() > limit as usize;
    events.truncate(limit as usize);
    Ok(Json(EventPage { events, has_more }))
}

// ------------------------------------------------------------------ members

pub(crate) async fn list_members(
    State(s): State<AppState>,
    c: Caller,
    Path(org): Path<String>,
) -> R<Vec<Member>> {
    require_full(&c)?;
    let db = s.conn()?;
    let me = require_confirmed(&db, &c, &org)?;
    let mut stmt = db.prepare(&format!(
        "{MEMBER_SELECT} WHERE m.org_id = ?1 ORDER BY m.joined_at, m.account_id"
    ))?;
    let mut members = stmt
        .query_map([&org], member_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !me.role.is_admin() {
        // Pending grants are for whoever confirms.
        for m in &mut members {
            m.pending_vaults.clear();
        }
    }
    Ok(Json(members))
}

/// `PUT /orgs/{org}/members/{member}/certificate`: an owner or admin certifies a confirmed
/// member again. When the admin who confirmed them leaves (or stops being an admin), their
/// certificate no longer verifies on devices that never pinned the member.
pub(crate) async fn recertify_member(
    State(s): State<AppState>,
    c: Caller,
    Path((org, account)): Path<(String, String)>,
    Json(req): Json<MemberCertificate>,
) -> R<Member> {
    require_full(&c)?;
    check_sig(&req.member_cert, "member_cert")?;
    let db = s.conn()?;
    require_admin(&db, &c, &org)?;
    let target = membership(&db, &org, &account)?.ok_or_else(Fail::not_found)?;
    if target.status != MemberStatus::Confirmed {
        return Err(conflict(
            "conflict",
            "not confirmed yet: confirm them instead",
        ));
    }
    db.execute(
        "UPDATE members SET member_signer = ?3, member_sig = ?4 WHERE org_id = ?1 AND account_id = ?2",
        params![org, account, c.account, req.member_cert.0],
    )?;
    event(
        &db,
        &org,
        "member_recertified",
        Some(&c.account),
        Some(&account),
        None,
        None,
    )?;
    Ok(Json(load_member(&db, &org, &account)?))
}

pub(crate) async fn confirm_member(
    State(s): State<AppState>,
    c: Caller,
    Path((org, account)): Path<(String, String)>,
    Json(req): Json<ConfirmMember>,
) -> R<Member> {
    require_full(&c)?;
    check_sig(&req.member_cert, "member_cert")?;
    let mut db = s.conn()?;
    let tx = db.transaction()?;
    let me = require_admin(&tx, &c, &org)?;
    let target = membership(&tx, &org, &account)?.ok_or_else(Fail::not_found)?;
    if target.status == MemberStatus::Confirmed {
        return Err(conflict("conflict", "already confirmed"));
    }
    let pending: String = tx.query_row(
        "SELECT pending_vaults FROM members WHERE org_id = ?1 AND account_id = ?2",
        params![org, account],
        |r| r.get(0),
    )?;
    let pending: Vec<VaultGrant> = serde_json::from_str(&pending).unwrap_or_default();
    let org_vault_ids: BTreeSet<String> =
        org_vaults(&tx, &org)?.into_iter().map(|(v, _)| v).collect();
    let required: BTreeSet<String> = if target.role.is_admin() {
        if me.role != Role::Owner {
            return Err(not_permitted("only the owner confirms an admin"));
        }
        let cert = req
            .admin_cert
            .as_ref()
            .ok_or_else(|| Fail::bad("confirming an admin needs admin_cert"))?;
        check_sig(cert, "admin_cert")?;
        org_vault_ids.clone()
    } else {
        // Grants for vaults deleted since the invite are dropped.
        pending
            .iter()
            .map(|g| g.vault_id.clone())
            .filter(|v| org_vault_ids.contains(v))
            .collect()
    };
    check_member_keys(&tx, &req.vault_keys, &required, &required)?;
    tx.execute(
        "UPDATE members SET status = 'confirmed', member_signer = ?3, member_sig = ?4,
             admin_signer = ?5, admin_sig = ?6, pending_vaults = '[]'
         WHERE org_id = ?1 AND account_id = ?2",
        params![
            org,
            account,
            c.account,
            req.member_cert.0,
            req.admin_cert.as_ref().map(|_| c.account.clone()),
            req.admin_cert.as_ref().map(|c| c.0.clone())
        ],
    )?;
    if !target.role.is_admin() {
        for g in pending.iter().filter(|g| required.contains(&g.vault_id)) {
            tx.execute(
                "INSERT OR REPLACE INTO vault_members (vault_id, account_id, permission) VALUES (?1, ?2, ?3)",
                params![g.vault_id, account, perm_str(g.permission)],
            )?;
        }
    }
    for k in &req.vault_keys {
        store_key(
            &tx,
            &k.vault_id,
            &k.key_id.0,
            &account,
            &k.wrapped_vault_key.0,
            Some(&c.account),
            Some(&k.grant_sig.0),
        )?;
    }
    event(
        &tx,
        &org,
        "member_confirmed",
        Some(&c.account),
        Some(&account),
        None,
        None,
    )?;
    // The devices they joined with are theirs; the confirming admin checked.
    crate::approvals::approve_existing(&tx, &org, Some(&account), &c.account)?;
    let out = load_member(&tx, &org, &account)?;
    tx.commit()?;
    Ok(Json(out))
}

pub(crate) async fn update_member(
    State(s): State<AppState>,
    c: Caller,
    Path((org, account)): Path<(String, String)>,
    Json(req): Json<UpdateMember>,
) -> R<Member> {
    require_full(&c)?;
    let mut db = s.conn()?;
    let tx = db.transaction()?;
    require_owner(&tx, &c, &org)?;
    let target = membership(&tx, &org, &account)?.ok_or_else(Fail::not_found)?;
    if target.status != MemberStatus::Confirmed {
        return Err(Fail::bad("confirm the member first"));
    }
    if target.role == Role::Owner || req.role == Role::Owner {
        return Err(Fail::bad("ownership changes hands through /transfer"));
    }
    match (target.role, req.role) {
        (Role::Member, Role::Admin) => {
            let cert = req
                .admin_cert
                .as_ref()
                .ok_or_else(|| Fail::bad("promoting to admin needs admin_cert"))?;
            check_sig(cert, "admin_cert")?;
            // Every organization vault they can't open yet.
            let mut missing = BTreeSet::new();
            for (vault, current) in org_vaults(&tx, &org)? {
                let has: bool = tx.query_row(
                    "SELECT EXISTS (SELECT 1 FROM vault_keys WHERE vault_id = ?1 AND key_id = ?2 AND account_id = ?3)",
                    params![vault, current, account],
                    |r| r.get(0),
                )?;
                if !has {
                    missing.insert(vault);
                }
            }
            // Keys for vaults they can already open are accepted (and replaced) too.
            let all: BTreeSet<String> =
                org_vaults(&tx, &org)?.into_iter().map(|(v, _)| v).collect();
            check_member_keys(&tx, &req.vault_keys, &missing, &all)?;
            for k in &req.vault_keys {
                store_key(
                    &tx,
                    &k.vault_id,
                    &k.key_id.0,
                    &account,
                    &k.wrapped_vault_key.0,
                    Some(&c.account),
                    Some(&k.grant_sig.0),
                )?;
            }
            tx.execute(
                "UPDATE members SET role = 'admin', admin_signer = ?3, admin_sig = ?4 WHERE org_id = ?1 AND account_id = ?2",
                params![org, account, c.account, cert.0],
            )?;
        }
        (Role::Admin, Role::Member) => {
            // They keep only vaults granted to them; the rest want a new key.
            for (vault, _) in org_vaults(&tx, &org)? {
                let granted: bool = tx.query_row(
                    "SELECT EXISTS (SELECT 1 FROM vault_members WHERE vault_id = ?1 AND account_id = ?2)",
                    params![vault, account],
                    |r| r.get(0),
                )?;
                if !granted {
                    tx.execute(
                        "DELETE FROM vault_keys WHERE vault_id = ?1 AND account_id = ?2",
                        params![vault, account],
                    )?;
                    tx.execute("UPDATE vaults SET rotation_due = 1 WHERE id = ?1", [&vault])?;
                }
            }
            tx.execute(
                "UPDATE members SET role = 'member', admin_signer = NULL, admin_sig = NULL WHERE org_id = ?1 AND account_id = ?2",
                params![org, account],
            )?;
        }
        _ => {}
    }
    event(
        &tx,
        &org,
        "role_changed",
        Some(&c.account),
        Some(&account),
        None,
        Some(role_str(req.role)),
    )?;
    let out = load_member(&tx, &org, &account)?;
    tx.commit()?;
    Ok(Json(out))
}

pub(crate) async fn remove_member(
    State(s): State<AppState>,
    c: Caller,
    Path((org, account)): Path<(String, String)>,
) -> Result<StatusCode, Fail> {
    require_full(&c)?;
    let mut db = s.conn()?;
    let tx = db.transaction()?;
    let me = require_any_member(&tx, &c, &org)?;
    let target = membership(&tx, &org, &account)?.ok_or_else(Fail::not_found)?;
    if target.role == Role::Owner {
        return Err(conflict(
            "sole_owner",
            "the owner can't leave or be removed; transfer ownership or delete the organization",
        ));
    }
    let leaving = account == c.account;
    if !leaving {
        if me.status != MemberStatus::Confirmed || !me.role.is_admin() {
            return Err(not_permitted("only owners and admins remove members"));
        }
        if target.role == Role::Admin && me.role != Role::Owner {
            return Err(not_permitted("only the owner removes an admin"));
        }
    }
    remove_member_rows(&tx, &org, &account)?;
    let kind = if leaving {
        "member_left"
    } else {
        "member_removed"
    };
    event(
        &tx,
        &org,
        kind,
        Some(&c.account),
        Some(&account),
        None,
        None,
    )?;
    tx.commit()?;
    Ok(StatusCode::NO_CONTENT)
}

// ------------------------------------------------------------------ invites

fn invite_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Invite> {
    Ok(Invite {
        id: r.get(0)?,
        org_id: r.get(1)?,
        email: r.get(2)?,
        role: parse_role(&r.get::<_, String>(3)?),
        vaults: serde_json::from_str(&r.get::<_, String>(4)?).unwrap_or_default(),
        created_at: r.get(5)?,
        expires_at: rfc3339(r.get(6)?),
        token: None,
    })
}

const INVITE_COLS: &str = "id, org_id, email, role, vaults, created_at, expires_at";

/// Stores an invite from `created_by` and returns its id and token. A new invite to the same
/// address replaces the old one. `actor` goes in the audit log (`None` for provisioning).
pub(crate) fn insert_invite(
    db: &Connection,
    org: &str,
    email: &str,
    role: Role,
    vaults: &[VaultGrant],
    created_by: &str,
    actor: Option<&str>,
) -> rusqlite::Result<(String, String)> {
    db.execute(
        "UPDATE invites SET closed = 1 WHERE org_id = ?1 AND email = ?2 AND closed = 0",
        params![org, email],
    )?;
    let id = ulid::Ulid::generate().to_string();
    let token = URL_SAFE_NO_PAD.encode(random::<32>());
    let created = now_secs();
    db.execute(
        "INSERT INTO invites (id, org_id, email, role, vaults, token_hash, created_by, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            id,
            org,
            email,
            role_str(role),
            serde_json::to_string(vaults).expect("serializable"),
            token_hash(&token),
            created_by,
            rfc3339(created),
            created + INVITE_TTL
        ],
    )?;
    event(db, org, "member_invited", actor, None, None, Some(email))?;
    Ok((id, token))
}

pub(crate) async fn create_invite(
    State(s): State<AppState>,
    c: Caller,
    Path(org): Path<String>,
    Json(req): Json<CreateInvite>,
) -> Result<(StatusCode, Json<Invite>), Fail> {
    require_full(&c)?;
    let email = check_email(&req.email)?;
    let mut db = s.conn()?;
    let tx = db.transaction()?;
    let me = require_admin(&tx, &c, &org)?;
    match req.role {
        Role::Owner => return Err(Fail::bad("invite as member or admin")),
        Role::Admin if me.role != Role::Owner => {
            return Err(not_permitted("only the owner invites admins"));
        }
        _ => {}
    }
    let p = policies(&tx, &org)?;
    if !p.allowed_email_domains.is_empty() {
        let domain = email
            .rsplit('@')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !p.allowed_email_domains.contains(&domain) {
            return Err(not_permitted(format!(
                "invites go only to {}",
                p.allowed_email_domains.join(", ")
            )));
        }
    }
    let member: bool = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM members m JOIN accounts a ON a.id = m.account_id WHERE m.org_id = ?1 AND a.email = ?2)",
        params![org, email],
        |r| r.get(0),
    )?;
    if member {
        return Err(conflict(
            "already_member",
            "that account is already a member",
        ));
    }
    let org_vault_ids: BTreeSet<String> =
        org_vaults(&tx, &org)?.into_iter().map(|(v, _)| v).collect();
    let mut seen = BTreeSet::new();
    for g in &req.vaults {
        if !org_vault_ids.contains(&g.vault_id) || !seen.insert(g.vault_id.clone()) {
            return Err(Fail::bad(format!(
                "not a vault of this organization: {}",
                g.vault_id
            )));
        }
    }
    let (id, token) = insert_invite(
        &tx,
        &org,
        &email,
        req.role,
        &req.vaults,
        &c.account,
        Some(&c.account),
    )?;
    let mut invite = tx.query_row(
        &format!("SELECT {INVITE_COLS} FROM invites WHERE id = ?1"),
        [&id],
        invite_row,
    )?;
    tx.commit()?;
    // This server sends no mail: the admin passes the token on.
    invite.token = Some(token);
    Ok((StatusCode::CREATED, Json(invite)))
}

pub(crate) async fn list_invites(
    State(s): State<AppState>,
    c: Caller,
    Path(org): Path<String>,
) -> R<Vec<Invite>> {
    require_full(&c)?;
    let db = s.conn()?;
    require_admin(&db, &c, &org)?;
    let mut stmt = db.prepare(&format!(
        "SELECT {INVITE_COLS} FROM invites WHERE org_id = ?1 AND closed = 0 AND expires_at > ?2 ORDER BY created_at"
    ))?;
    let invites = stmt
        .query_map(params![org, now_secs()], invite_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Json(invites))
}

pub(crate) async fn cancel_invite(
    State(s): State<AppState>,
    c: Caller,
    Path((org, invite)): Path<(String, String)>,
) -> Result<StatusCode, Fail> {
    require_full(&c)?;
    let db = s.conn()?;
    require_admin(&db, &c, &org)?;
    let n = db.execute(
        "UPDATE invites SET closed = 1 WHERE id = ?1 AND org_id = ?2 AND closed = 0",
        params![invite, org],
    )?;
    if n == 0 {
        return Err(Fail::not_found());
    }
    event(
        &db,
        &org,
        "invite_cancelled",
        Some(&c.account),
        None,
        None,
        None,
    )?;
    Ok(StatusCode::NO_CONTENT)
}

/// An open invite by token; `410 invite_expired` once used, cancelled or too old.
fn open_invite(db: &Connection, token: &str) -> Result<(Invite, String), Fail> {
    let row: Option<(Invite, i64, String)> = db
        .query_row(
            &format!("SELECT {INVITE_COLS}, closed, created_by FROM invites WHERE token_hash = ?1"),
            [token_hash(token)],
            |r| Ok((invite_row(r)?, r.get(7)?, r.get(8)?)),
        )
        .optional()?;
    let (invite, closed, created_by) = row.ok_or_else(Fail::not_found)?;
    let expires: i64 = db.query_row(
        "SELECT expires_at FROM invites WHERE id = ?1",
        [&invite.id],
        |r| r.get(0),
    )?;
    if closed != 0 || expires <= now_secs() {
        return Err(Fail::new(
            StatusCode::GONE,
            "invite_expired",
            "this invite was used, cancelled or is older than 7 days",
        ));
    }
    Ok((invite, created_by))
}

pub(crate) async fn invite_info(
    State(s): State<AppState>,
    Path(token): Path<String>,
) -> R<InviteInfo> {
    let db = s.conn()?;
    let (invite, created_by) = open_invite(&db, &token)?;
    let org = load_org(&db, &invite.org_id)?;
    let inviter_email: String = db
        .query_row(
            "SELECT email FROM accounts WHERE id = ?1",
            [&created_by],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or_default();
    Ok(Json(InviteInfo {
        org_id: org.id,
        org_name: org.name,
        email: invite.email,
        role: invite.role,
        inviter_email,
        owner_chain: org.owner_chain,
        expires_at: invite.expires_at,
    }))
}

pub(crate) async fn accept_invite(
    State(s): State<AppState>,
    c: Caller,
    Path(token): Path<String>,
) -> R<OrgMembership> {
    require_full(&c)?;
    let mut db = s.conn()?;
    let tx = db.transaction()?;
    let (invite, _) = open_invite(&tx, &token)?;
    let email: String = tx.query_row(
        "SELECT email FROM accounts WHERE id = ?1",
        [&c.account],
        |r| r.get(0),
    )?;
    if !email.eq_ignore_ascii_case(&invite.email) {
        return Err(Fail::new(
            StatusCode::FORBIDDEN,
            "invite_email_mismatch",
            format!("this invite is for {}", invite.email),
        ));
    }
    if membership(&tx, &invite.org_id, &c.account)?.is_some() {
        return Err(conflict("already_member", "you are already a member"));
    }
    tx.execute(
        "INSERT INTO members (org_id, account_id, role, status, pending_vaults, joined_at) VALUES (?1, ?2, ?3, 'accepted', ?4, ?5)",
        params![
            invite.org_id,
            c.account,
            role_str(invite.role),
            serde_json::to_string(&invite.vaults).expect("serializable"),
            now()
        ],
    )?;
    tx.execute("UPDATE invites SET closed = 1 WHERE id = ?1", [&invite.id])?;
    event(
        &tx,
        &invite.org_id,
        "member_accepted",
        Some(&c.account),
        Some(&c.account),
        None,
        None,
    )?;
    let name: String = tx.query_row(
        "SELECT name FROM orgs WHERE id = ?1",
        [&invite.org_id],
        |r| r.get(0),
    )?;
    tx.commit()?;
    Ok(Json(OrgMembership {
        id: invite.org_id,
        name,
        role: invite.role,
        status: MemberStatus::Accepted,
        rev: None,
    }))
}

// ------------------------------------------------------------------ vault members and keys

pub(crate) async fn vault_members(
    State(s): State<AppState>,
    c: Caller,
    Path(vault): Path<String>,
) -> R<Vec<VaultMember>> {
    require_full(&c)?;
    let db = s.conn()?;
    require_vault(&db, &c, &vault, Permission::Manage)?;
    let org: Option<String> =
        db.query_row("SELECT org_id FROM vaults WHERE id = ?1", [&vault], |r| {
            r.get(0)
        })?;
    let mut out = Vec::new();
    match org {
        None => out.push(VaultMember {
            account_id: c.account.clone(),
            permission: Permission::Manage,
            implicit: true,
        }),
        Some(org) => {
            for a in org_admins(&db, &org)? {
                out.push(VaultMember {
                    account_id: a,
                    permission: Permission::Manage,
                    implicit: true,
                });
            }
            let mut stmt = db.prepare(
                "SELECT vm.account_id, vm.permission FROM vault_members vm
                 JOIN members m ON m.org_id = ?2 AND m.account_id = vm.account_id AND m.status = 'confirmed'
                 WHERE vm.vault_id = ?1 ORDER BY vm.account_id",
            )?;
            for row in stmt.query_map(params![vault, org], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })? {
                let (account_id, permission) = row?;
                if !out.iter().any(|m| m.account_id == account_id) {
                    out.push(VaultMember {
                        account_id,
                        permission: parse_perm(&permission),
                        implicit: false,
                    });
                }
            }
        }
    }
    Ok(Json(out))
}

pub(crate) async fn set_vault_member(
    State(s): State<AppState>,
    c: Caller,
    Path((vault, account)): Path<(String, String)>,
    Json(req): Json<SetVaultMember>,
) -> R<VaultMember> {
    require_full(&c)?;
    let mut db = s.conn()?;
    let tx = db.transaction()?;
    let access = require_vault(&tx, &c, &vault, Permission::Manage)?;
    let org = access
        .org_id
        .ok_or_else(|| Fail::bad("only organization vaults are shared"))?;
    match membership(&tx, &org, &account)? {
        Some(m) if m.status == MemberStatus::Confirmed && m.role.is_admin() => {
            return Err(conflict(
                "conflict",
                "owners and admins already manage every vault",
            ));
        }
        Some(m) if m.status == MemberStatus::Confirmed => {}
        _ => return Err(Fail::bad("grant vaults to confirmed members")),
    }
    let existing: Option<String> = tx
        .query_row(
            "SELECT permission FROM vault_members WHERE vault_id = ?1 AND account_id = ?2",
            params![vault, account],
            |r| r.get(0),
        )
        .optional()?;
    if existing.is_none() || !req.keys.is_empty() {
        let keys: Vec<MemberVaultKey> = req
            .keys
            .iter()
            .map(|k| MemberVaultKey {
                vault_id: vault.clone(),
                key_id: k.key_id.clone(),
                wrapped_vault_key: k.wrapped_vault_key.clone(),
                grant_sig: k.grant_sig.clone(),
            })
            .collect();
        let this = BTreeSet::from([vault.clone()]);
        check_member_keys(&tx, &keys, &this, &this)?;
        for k in &keys {
            store_key(
                &tx,
                &vault,
                &k.key_id.0,
                &account,
                &k.wrapped_vault_key.0,
                Some(&c.account),
                Some(&k.grant_sig.0),
            )?;
        }
    }
    tx.execute(
        "INSERT INTO vault_members (vault_id, account_id, permission) VALUES (?1, ?2, ?3)
         ON CONFLICT (vault_id, account_id) DO UPDATE SET permission = excluded.permission",
        params![vault, account, perm_str(req.permission)],
    )?;
    let kind = if existing.is_some() {
        "vault_access_changed"
    } else {
        "vault_access_granted"
    };
    event(
        &tx,
        &org,
        kind,
        Some(&c.account),
        Some(&account),
        Some(&vault),
        Some(perm_str(req.permission)),
    )?;
    tx.commit()?;
    Ok(Json(VaultMember {
        account_id: account,
        permission: req.permission,
        implicit: false,
    }))
}

pub(crate) async fn revoke_vault_member(
    State(s): State<AppState>,
    c: Caller,
    Path((vault, account)): Path<(String, String)>,
) -> Result<StatusCode, Fail> {
    require_full(&c)?;
    let mut db = s.conn()?;
    let tx = db.transaction()?;
    let access = require_vault(&tx, &c, &vault, Permission::Manage)?;
    let org = access.org_id.ok_or_else(Fail::not_found)?;
    let n = tx.execute(
        "DELETE FROM vault_members WHERE vault_id = ?1 AND account_id = ?2",
        params![vault, account],
    )?;
    if n == 0 {
        return Err(Fail::not_found());
    }
    tx.execute(
        "DELETE FROM vault_keys WHERE vault_id = ?1 AND account_id = ?2",
        params![vault, account],
    )?;
    tx.execute("UPDATE vaults SET rotation_due = 1 WHERE id = ?1", [&vault])?;
    event(
        &tx,
        &org,
        "vault_access_revoked",
        Some(&c.account),
        Some(&account),
        Some(&vault),
        None,
    )?;
    tx.commit()?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn rotate_vault_key(
    State(s): State<AppState>,
    c: Caller,
    Path(vault): Path<String>,
    Json(req): Json<RotateVaultKey>,
) -> R<Vault> {
    require_full(&c)?;
    if req.key_id.0.len() != 16 || req.previous_key_id.0.len() != 16 {
        return Err(Fail::bad("key ids are 16 bytes"));
    }
    let mut db = s.conn()?;
    let tx = db.transaction()?;
    let access = require_vault(&tx, &c, &vault, Permission::Manage)?;
    let current: Vec<u8> =
        tx.query_row("SELECT key_id FROM vaults WHERE id = ?1", [&vault], |r| {
            r.get(0)
        })?;
    if req.previous_key_id.0 != current {
        return Err(conflict(
            "conflict",
            "the vault's key changed; reload and rotate again",
        ));
    }
    if ring(&tx, &vault)?.contains(&req.key_id.0) {
        return Err(Fail::bad("key_id must be new"));
    }
    let needed = vault_accounts(&tx, &vault)?;
    let mut given = BTreeSet::new();
    for w in &req.wrapped {
        check_wrapped(&w.wrapped_vault_key)?;
        check_sig(&w.grant_sig, "grant_sig")?;
        if !needed.contains(&w.account_id) {
            return Err(Fail::bad(format!(
                "{} has no access to this vault",
                w.account_id
            )));
        }
        given.insert(w.account_id.clone());
    }
    if given != needed {
        return Err(incomplete(
            "incomplete_rotation",
            format!(
                "the new key must be sealed to all {} accounts with access",
                needed.len()
            ),
        ));
    }
    for w in &req.wrapped {
        store_key(
            &tx,
            &vault,
            &req.key_id.0,
            &w.account_id,
            &w.wrapped_vault_key.0,
            Some(&c.account),
            Some(&w.grant_sig.0),
        )?;
    }
    tx.execute(
        "UPDATE vaults SET key_id = ?2, rotation_due = 0 WHERE id = ?1",
        params![vault, req.key_id.0],
    )?;
    if let Some(org) = &access.org_id {
        event(
            &tx,
            org,
            "vault_key_rotated",
            Some(&c.account),
            None,
            Some(&vault),
            None,
        )?;
    }
    let out = crate::api::vault_view(&tx, &c.account, &vault)?;
    tx.commit()?;
    Ok(Json(out))
}

/// `POST /vaults` for an organization: who may, and every owner and admin gets the key.
pub(crate) fn create_org_vault(
    db: &Connection,
    c: &Caller,
    org: &str,
    req: &CreateVault,
) -> Result<(), Fail> {
    let me = require_confirmed(db, c, org)?;
    if !me.role.is_admin() && !policies(db, org)?.members_can_create_vaults {
        return Err(not_permitted(
            "only owners and admins create organization vaults",
        ));
    }
    let mut needed = org_admins(db, org)?;
    needed.insert(c.account.clone());
    let mut given = BTreeSet::new();
    for k in &req.keys {
        check_wrapped(&k.wrapped_vault_key)?;
        check_sig(&k.grant_sig, "grant_sig")?;
        if !needed.contains(&k.account_id) {
            return Err(Fail::bad(format!(
                "{} is not an owner or admin",
                k.account_id
            )));
        }
        given.insert(k.account_id.clone());
    }
    if given != needed {
        return Err(incomplete(
            "incomplete_keys",
            "an organization vault's key must be sealed to every owner and admin",
        ));
    }
    let owner: String = db.query_row("SELECT owner_id FROM orgs WHERE id = ?1", [org], |r| {
        r.get(0)
    })?;
    db.execute(
        "INSERT INTO vaults (id, account_id, key_id, wrapped_vault_key, meta, created_at, org_id, created_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![req.id, owner, req.key_id.0, req.wrapped_vault_key.0, req.meta.as_ref().map(|m| m.0.clone()), now(), org, c.account],
    )?;
    for k in &req.keys {
        store_key(
            db,
            &req.id,
            &req.key_id.0,
            &k.account_id,
            &k.wrapped_vault_key.0,
            Some(&c.account),
            Some(&k.grant_sig.0),
        )?;
    }
    if !me.role.is_admin() {
        db.execute(
            "INSERT INTO vault_members (vault_id, account_id, permission) VALUES (?1, ?2, 'manage')",
            params![req.id, c.account],
        )?;
    }
    event(
        db,
        org,
        "vault_created",
        Some(&c.account),
        None,
        Some(&req.id),
        None,
    )?;
    Ok(())
}
