//! Files kept with a host: sealed into an `attachment` blob that sync uploads, and fetched from
//! the sync server when another device saves one.

use mg_store::{BlobKind, BlobState, Item, ItemData};
use serde::Serialize;
use tauri::ipc::{InvokeBody, Request};
use tauri::{AppHandle, State};

use crate::orgs::with_client;
use crate::sync::SyncState;
use crate::vault::VaultState;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentView {
    id: String,
    host_id: Option<String>,
    name: String,
    size: u64,
    /// `local` (here and uploaded), `uploading`, `remote` (added elsewhere, fetched when saved)
    /// or `failed` (the server refused it; `problem` says why).
    state: &'static str,
    problem: Option<String>,
    upgrade_url: Option<String>,
}

fn view(v: &mg_store::LocalVault, item: Item) -> Option<AttachmentView> {
    let ItemData::Attachment(a) = item.data else {
        return None;
    };
    let (state, problem, upgrade_url) = match v.blob_state(&item.vault_id, &a.blob).ok().flatten() {
        Some(BlobState::Uploaded) => ("local", None, None),
        Some(BlobState::Pending) => ("uploading", None, None),
        Some(BlobState::Failed(r)) => ("failed", Some(r.reason), r.upgrade_url),
        None => ("remote", None, None),
    };
    Some(AttachmentView {
        id: item.id,
        host_id: a.host_ref,
        name: a.name,
        size: a.size,
        state,
        problem,
        upgrade_url,
    })
}

/// A host's attachments, by name.
#[tauri::command]
pub fn attachments(
    vault: State<'_, VaultState>,
    host_id: String,
) -> Result<Vec<AttachmentView>, String> {
    let v = vault.guard()?;
    let mut out: Vec<AttachmentView> = v
        .items()
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|i| matches!(&i.data, ItemData::Attachment(a) if a.host_ref.as_deref() == Some(host_id.as_str())))
        .filter_map(|i| view(&v, i))
        .collect();
    out.sort_by_key(|a| a.name.to_lowercase());
    Ok(out)
}

/// Attaches a file to a host, in the host's vault. The body is the file's bytes; headers
/// `x-host-id` and `x-file-name` (percent-encoded) say where and what.
#[tauri::command]
pub fn attachment_add(
    vault: State<'_, VaultState>,
    request: Request<'_>,
) -> Result<AttachmentView, String> {
    let InvokeBody::Raw(bytes) = request.body() else {
        return Err("send the file's bytes".into());
    };
    let header = |name: &str| {
        request
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(percent_decode)
            .ok_or_else(|| format!("missing {name}"))
    };
    let (host_id, name) = (header("x-host-id")?, header("x-file-name")?);
    let name = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned();
    let mut v = vault.guard()?;
    let host = v.item(&host_id).map_err(|e| e.to_string())?;
    if !matches!(host.data, ItemData::Host(_)) {
        return Err("attachments go with a host".into());
    }
    let id = v
        .attach(&host.vault_id, Some(&host_id), &name, bytes)
        .map_err(|e| e.to_string())?;
    let item = v.item(&id).map_err(|e| e.to_string())?;
    let out = view(&v, item).ok_or("not an attachment")?;
    drop(v);
    vault.changed();
    Ok(out)
}

/// Saves an attachment in the downloads folder (fetching it from the sync server if it was added
/// on another device); returns where.
#[tauri::command]
pub async fn attachment_save(
    app: AppHandle,
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    id: String,
) -> Result<String, String> {
    let (vault_id, a) = {
        let item = vault.guard()?.item(&id).map_err(|e| e.to_string())?;
        let ItemData::Attachment(a) = item.data else {
            return Err("not an attachment".into());
        };
        (item.vault_id, a)
    };
    let local = vault
        .guard()?
        .open_blob(&vault_id, BlobKind::Attachment, &a.blob)
        .map_err(|e| e.to_string())?;
    let plain = match local {
        Some(p) => p,
        None => {
            let (v, h) = (vault_id.clone(), a.blob.clone());
            let bytes = with_client(&sync, &vault, async |c| Ok(c.blob(&v, &h).await?))
                .await
                .map_err(|e| {
                    if e.contains("(not_found)") || e.contains("404") {
                        "this file is not on the sync server (yet): the device that added it uploads it when it syncs".to_owned()
                    } else {
                        e
                    }
                })?;
            let mut g = vault.guard()?;
            g.store_blob(&vault_id, BlobKind::Attachment, &a.blob, &bytes)
                .map_err(|e| e.to_string())?;
            g.open_blob(&vault_id, BlobKind::Attachment, &a.blob)
                .map_err(|e| e.to_string())?
                .ok_or("the file could not be stored")?
        }
    };
    let (stem, ext) = match a.name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem.to_owned(), ext.to_owned()),
        _ => (a.name.clone(), String::new()),
    };
    let path = if ext.is_empty() {
        crate::util::download_path(&app, &stem, "bin")?
    } else {
        crate::util::download_path(&app, &stem, &ext)?
    };
    std::fs::write(&path, plain.as_slice()).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(crate::util::saved(&path))
}

#[tauri::command]
pub fn attachment_delete(vault: State<'_, VaultState>, id: String) -> Result<(), String> {
    let mut v = vault.guard()?;
    match v.item(&id).map_err(|e| e.to_string())?.data {
        ItemData::Attachment(_) => {}
        _ => return Err("not an attachment".into()),
    }
    v.delete(&id).map_err(|e| e.to_string())?;
    drop(v);
    vault.changed();
    Ok(())
}

/// `%XX` escapes (what `encodeURIComponent` makes) back to text.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        match (
            bytes[i],
            bytes.get(i + 1).copied().and_then(hex),
            bytes.get(i + 2).copied().and_then(hex),
        ) {
            (b'%', Some(h), Some(l)) => {
                out.push((h * 16 + l) as u8);
                i += 3;
            }
            (b, _, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_survive_the_header() {
        assert_eq!(percent_decode("run%20book%20%C3%A9.md"), "run book é.md");
        assert_eq!(percent_decode("100%"), "100%");
    }
}
