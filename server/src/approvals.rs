//! Device approval (`require_device_approval`): a new device can't open an organization's
//! vaults until an owner or admin, or the member from one of their own approved devices,
//! approves it, so a stolen master password isn't enough on someone else's machine. Devices
//! that exist when the policy is turned on, and a member's devices when an admin confirms them,
//! are approved straight away. Signing a device out forgets its approvals.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use mg_sync::{ApiError, DeviceApproval};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;

use crate::AppState;
use crate::api::{R, RECOVERY_DEVICE, require_full};
use crate::auth::Caller;
use crate::sharing::{self, not_permitted};
use crate::util::{Fail, now_secs, rfc3339};

fn required(db: &Connection, org: &str) -> rusqlite::Result<bool> {
    Ok(sharing::org_policies(db, org)?.require_device_approval)
}

/// `pending`, `approved` or `denied`; `None` when the device never asked.
fn decision(
    db: &Connection,
    org: &str,
    account: &str,
    device: &str,
) -> rusqlite::Result<Option<String>> {
    db.query_row(
        "SELECT status FROM device_approvals WHERE org_id = ?1 AND account_id = ?2 AND device_id = ?3",
        params![org, account, device],
        |r| r.get(0),
    )
    .optional()
}

fn device_name(db: &Connection, account: &str, device: &str) -> rusqlite::Result<String> {
    Ok(db
        .query_row(
            "SELECT name FROM devices WHERE account_id = ?1 AND id = ?2",
            params![account, device],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or_else(|| device.to_owned()))
}

/// Refuses (`403 device_approval_required`) a device the organization hasn't approved. The
/// first refusal files the request.
pub(crate) fn gate(db: &Connection, org: &str, c: &Caller) -> Result<(), Fail> {
    if !required(db, org)? {
        return Ok(());
    }
    let status = match decision(db, org, &c.account, &c.device)? {
        Some(s) if s == "approved" => return Ok(()),
        Some(s) => s,
        None => {
            db.execute(
                "INSERT INTO device_approvals (org_id, account_id, device_id, status, requested)
                 VALUES (?1, ?2, ?3, 'pending', ?4)",
                params![org, c.account, c.device, now_secs()],
            )?;
            let name = device_name(db, &c.account, &c.device)?;
            sharing::event(
                db,
                org,
                "device_approval_requested",
                Some(&c.account),
                Some(&c.account),
                None,
                Some(&name),
            )?;
            "pending".into()
        }
    };
    let mut e = ApiError::new(
        "device_approval_required",
        "an admin of this organization, or one of your approved devices, has to approve this device first",
    );
    e.org_id = Some(org.into());
    e.device_id = Some(c.device.clone());
    e.status = Some(status);
    Err(Fail(StatusCode::FORBIDDEN, Box::new(e)))
}

/// Approves signed-in devices without a decision: every confirmed member's (the policy was
/// turned on), or one account's (an admin confirmed them; the devices they joined with are
/// theirs).
pub(crate) fn approve_existing(
    db: &Connection,
    org: &str,
    account: Option<&str>,
    by: &str,
) -> rusqlite::Result<()> {
    db.execute(
        "INSERT OR IGNORE INTO device_approvals
             (org_id, account_id, device_id, status, requested, decided, decided_by)
         SELECT ?1, d.account_id, d.id, 'approved', ?2, ?2, ?3 FROM devices d
         JOIN members m ON m.org_id = ?1 AND m.account_id = d.account_id
         WHERE d.revoked = 0 AND d.id <> ?4
           AND ((?5 IS NULL AND m.status = 'confirmed') OR d.account_id = ?5)",
        params![org, now_secs(), by, RECOVERY_DEVICE, account],
    )?;
    sharing::touch(db, org)
}

/// A member left or was removed.
pub(crate) fn forget_member(db: &Connection, org: &str, account: &str) -> rusqlite::Result<()> {
    db.execute(
        "DELETE FROM device_approvals WHERE org_id = ?1 AND account_id = ?2",
        params![org, account],
    )?;
    sharing::touch(db, org)
}

/// A device (`None`: every device of the account) was signed out: approve it again after the
/// next sign-in.
pub(crate) fn forget_device(
    db: &Connection,
    account: &str,
    device: Option<&str>,
) -> rusqlite::Result<()> {
    db.execute(
        "UPDATE orgs SET rev = rev + 1 WHERE id IN (SELECT org_id FROM device_approvals
         WHERE account_id = ?1 AND (?2 IS NULL OR device_id = ?2))",
        params![account, device],
    )?;
    db.execute(
        "DELETE FROM device_approvals WHERE account_id = ?1 AND (?2 IS NULL OR device_id = ?2)",
        params![account, device],
    )?;
    Ok(())
}

fn rows(
    db: &Connection,
    org: &str,
    account: Option<&str>,
    device: Option<&str>,
    status: Option<&str>,
) -> rusqlite::Result<Vec<DeviceApproval>> {
    let mut stmt = db.prepare(
        "SELECT x.account_id, a.email, x.device_id, d.name, d.platform, d.client_version,
                x.status, x.requested, x.decided, x.decided_by
         FROM device_approvals x JOIN accounts a ON a.id = x.account_id
         LEFT JOIN devices d ON d.account_id = x.account_id AND d.id = x.device_id
         WHERE x.org_id = ?1 AND (?2 IS NULL OR x.account_id = ?2)
           AND (?3 IS NULL OR x.device_id = ?3) AND (?4 IS NULL OR x.status = ?4)
         ORDER BY x.requested DESC, x.device_id",
    )?;
    stmt.query_map(params![org, account, device, status], |r| {
        Ok(DeviceApproval {
            account_id: r.get(0)?,
            email: r.get(1)?,
            device_id: r.get(2)?,
            name: r.get(3)?,
            platform: r.get(4)?,
            client_version: r.get(5)?,
            status: r.get(6)?,
            requested_at: rfc3339(r.get(7)?),
            decided_at: r.get::<_, Option<i64>>(8)?.map(rfc3339),
            decided_by: r.get(9)?,
        })
    })?
    .collect()
}

#[derive(Deserialize)]
pub(crate) struct ListQuery {
    status: Option<String>,
}

/// `GET /orgs/{org}/devices?status=`: owners and admins see everyone's, members their own.
pub(crate) async fn list(
    State(s): State<AppState>,
    c: Caller,
    Path(org): Path<String>,
    Query(q): Query<ListQuery>,
) -> R<Vec<DeviceApproval>> {
    require_full(&c)?;
    let db = s.conn()?;
    let m = sharing::require_confirmed(&db, &c, &org)?;
    let mine = (!m.is_admin()).then_some(c.account.as_str());
    let status = q
        .status
        .as_deref()
        .filter(|s| matches!(*s, "pending" | "approved" | "denied"));
    Ok(Json(rows(&db, &org, mine, None, status)?))
}

/// `POST /orgs/{org}/members/{member}/devices/{device}/approve`.
pub(crate) async fn approve(
    State(s): State<AppState>,
    c: Caller,
    Path((org, member, device)): Path<(String, String, String)>,
) -> R<DeviceApproval> {
    require_full(&c)?;
    Ok(Json(decide(&*s.conn()?, &c, &org, &member, &device, true)?))
}

/// `POST /orgs/{org}/members/{member}/devices/{device}/deny`.
pub(crate) async fn deny(
    State(s): State<AppState>,
    c: Caller,
    Path((org, member, device)): Path<(String, String, String)>,
) -> R<DeviceApproval> {
    require_full(&c)?;
    Ok(Json(decide(
        &*s.conn()?,
        &c,
        &org,
        &member,
        &device,
        false,
    )?))
}

/// Owners and admins decide for anyone, members for their own other devices; while the policy
/// is on, only from a device the organization approved.
fn decide(
    db: &Connection,
    c: &Caller,
    org: &str,
    account: &str,
    device: &str,
    approve: bool,
) -> Result<DeviceApproval, Fail> {
    let m = sharing::require_confirmed(db, c, org)?;
    let own = account == c.account;
    if !m.is_admin() && !own {
        return Err(not_permitted(
            "only owners, admins and the device's owner decide",
        ));
    }
    if own && device == c.device {
        return Err(not_permitted(
            "another of your approved devices has to approve this one",
        ));
    }
    if required(db, org)?
        && decision(db, org, &c.account, &c.device)?.as_deref() != Some("approved")
    {
        return Err(not_permitted(
            "approve from a device this organization has approved",
        ));
    }
    if decision(db, org, account, device)?.is_none() {
        return Err(Fail::not_found());
    }
    db.execute(
        "UPDATE device_approvals SET status = ?4, decided = ?5, decided_by = ?6
         WHERE org_id = ?1 AND account_id = ?2 AND device_id = ?3",
        params![
            org,
            account,
            device,
            if approve { "approved" } else { "denied" },
            now_secs(),
            c.account
        ],
    )?;
    let name = device_name(db, account, device)?;
    sharing::event(
        db,
        org,
        if approve {
            "device_approved"
        } else {
            "device_denied"
        },
        Some(&c.account),
        Some(account),
        None,
        Some(&name),
    )?;
    Ok(rows(db, org, Some(account), Some(device), None)?.remove(0))
}
