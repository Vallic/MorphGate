//! `GET /orgs/{org}/events/export`: the whole audit log as a download for owners and admins, as
//! CSV (the default) or JSON lines, in the hosted backend's columns.

use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use rusqlite::params;
use serde::Deserialize;
use serde_json::json;

use crate::AppState;
use crate::api::require_full;
use crate::auth::Caller;
use crate::sharing::{self, not_permitted};
use crate::util::{Fail, now};

const COLUMNS: [&str; 9] = [
    "seq",
    "at",
    "kind",
    "actor_id",
    "actor_email",
    "target_id",
    "target_email",
    "vault_id",
    "detail",
];

#[derive(Deserialize)]
pub(crate) struct ExportQuery {
    format: Option<String>,
}

pub(crate) async fn export(
    State(s): State<AppState>,
    c: Caller,
    Path(org): Path<String>,
    Query(q): Query<ExportQuery>,
) -> Result<Response, Fail> {
    require_full(&c)?;
    let jsonl = match q.format.as_deref() {
        None | Some("csv") => false,
        Some("jsonl") => true,
        Some(other) => return Err(Fail::bad(format!("format is csv or jsonl, not {other}"))),
    };
    let db = s.conn()?;
    if !sharing::require_confirmed(&db, &c, &org)?.is_admin() {
        return Err(not_permitted("only owners and admins can do this"));
    }
    let mut stmt = db.prepare(
        "SELECT e.seq, e.at, e.kind, e.actor_id, a.email, e.target_id, t.email, e.vault_id, e.detail
         FROM events e
         LEFT JOIN accounts a ON a.id = e.actor_id
         LEFT JOIN accounts t ON t.id = e.target_id
         WHERE e.org_id = ?1 ORDER BY e.seq",
    )?;
    let rows = stmt
        .query_map(params![org], |r| {
            Ok([
                Some(r.get::<_, i64>(0)?.to_string()),
                Some(r.get::<_, String>(1)?),
                Some(r.get::<_, String>(2)?),
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, Option<String>>(7)?,
                r.get::<_, Option<String>>(8)?,
            ])
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut body = String::new();
    if jsonl {
        for row in &rows {
            let mut event = serde_json::Map::new();
            event.insert("org_id".into(), json!(org));
            for (column, value) in COLUMNS.iter().zip(row) {
                if let Some(v) = value {
                    let v = if *column == "seq" {
                        json!(v.parse::<i64>().unwrap_or_default())
                    } else {
                        json!(v)
                    };
                    event.insert((*column).into(), v);
                }
            }
            body.push_str(&serde_json::Value::Object(event).to_string());
            body.push('\n');
        }
    } else {
        body.push_str(&COLUMNS.join(","));
        body.push_str("\r\n");
        for row in &rows {
            let cells: Vec<String> = row
                .iter()
                .map(|v| csv_cell(v.as_deref().unwrap_or_default()))
                .collect();
            body.push_str(&cells.join(","));
            body.push_str("\r\n");
        }
    }
    let name = format!(
        "morphgate-activity-{org}-{}.{}",
        &now()[..10],
        if jsonl { "jsonl" } else { "csv" }
    );
    Ok((
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                if jsonl {
                    "application/x-ndjson"
                } else {
                    "text/csv; charset=utf-8"
                }
                .to_owned(),
            ),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
            (header::CACHE_CONTROL, "no-store, private".to_owned()),
        ],
        body,
    )
        .into_response())
}

/// A CSV cell that no spreadsheet runs as a formula, quoted when it needs to be.
fn csv_cell(value: &str) -> String {
    let value = if value.starts_with(['=', '+', '-', '@']) {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cells() {
        assert_eq!(csv_cell("plain"), "plain");
        assert_eq!(csv_cell("=SUM(A1)"), "'=SUM(A1)");
        assert_eq!(csv_cell("a, \"b\""), "\"a, \"\"b\"\"\"");
    }
}
