//! Moving and copying items to another vault (mg-store's `moving`): the plan for the user to check,
//! then the move. Attachments added on another device are fetched first: a move seals their files
//! again for the other vault.

use std::collections::BTreeMap;

use mg_store::{BlobKind, Carry, ItemData, MovePlan, Moved};
use tauri::State;

use crate::orgs::with_client;
use crate::sync::SyncState;
use crate::vault::VaultState;

#[tauri::command]
pub fn items_move_plan(
    vault: State<'_, VaultState>,
    ids: Vec<String>,
    to: String,
    choices: BTreeMap<String, Carry>,
) -> Result<MovePlan, String> {
    vault
        .guard()?
        .plan_move(&ids, &to, &choices)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn items_move(
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    ids: Vec<String>,
    to: String,
    choices: BTreeMap<String, Carry>,
) -> Result<Moved, String> {
    // Files this device doesn't have yet, as (vault, blob).
    let missing: Vec<(String, String)> = {
        let v = vault.guard()?;
        let plan = v
            .plan_move(&ids, &to, &choices)
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for p in plan.items.iter().filter(|p| p.carry != Carry::Leave) {
            if let ItemData::Attachment(a) = v.item(&p.id).map_err(|e| e.to_string())?.data
                && v.open_blob(&plan.from, BlobKind::Attachment, &a.blob)
                    .map_err(|e| e.to_string())?
                    .is_none()
            {
                out.push((plan.from.clone(), a.blob));
            }
        }
        out
    };
    for (vault_id, hash) in missing {
        let (v, h) = (vault_id.clone(), hash.clone());
        let bytes = with_client(&sync, &vault, async |c| Ok(c.blob(&v, &h).await?))
            .await
            .map_err(|e| format!("fetching an attached file to move it: {e}"))?;
        vault
            .guard()?
            .store_blob(&vault_id, BlobKind::Attachment, &hash, &bytes)
            .map_err(|e| e.to_string())?;
    }
    let moved = vault
        .guard()?
        .move_items(&ids, &to, &choices)
        .map_err(|e| e.to_string())?;
    vault.changed();
    Ok(moved)
}
