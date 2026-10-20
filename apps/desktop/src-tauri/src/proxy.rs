//! A host's proxy command (OpenSSH's `ProxyCommand`): which ones this device runs.
//!
//! A vault syncs, and a shared one is written by others: a command in it runs on this device only
//! once this device has allowed it. Saving a host with a new command (typed here), or importing
//! one from this device's `~/.ssh/config`, allows it; a command that arrived some other way waits
//! for "Allow on this device" in the host's editor, which shows it. What was allowed is kept in
//! the device's settings (never synced), by the command's SHA-256: a changed command asks again.

use mg_store::{ItemData, LocalVault};
use sha2::{Digest, Sha256};
use tauri::State;

use crate::vault::{HostView, VaultState};

fn key(command: &str) -> String {
    let hex: String = Sha256::digest(command.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("proxy-allowed:{hex}")
}

/// This device has allowed `command`.
pub(crate) fn allowed(v: &LocalVault, command: &str) -> bool {
    matches!(v.setting(&key(command)), Ok(Some(_)))
}

pub(crate) fn allow(v: &LocalVault, command: &str) -> Result<(), String> {
    v.set_setting(&key(command), Some("1"))
        .map_err(|e| e.to_string())
}

/// Lets this device run the host's proxy command (the one it has now).
#[tauri::command]
pub fn host_allow_proxy(vault: State<'_, VaultState>, id: String) -> Result<HostView, String> {
    let v = vault.guard()?;
    let item = v.item(&id).map_err(|e| e.to_string())?;
    let ItemData::Host(h) = &item.data else {
        return Err("not a host".into());
    };
    let command = h
        .proxy_command
        .as_deref()
        .ok_or("the host has no proxy command")?;
    allow(&v, command)?;
    HostView::of(&v, item).ok_or_else(|| "not a host".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mg_vault::KdfParams;

    #[test]
    fn a_command_is_allowed_as_it_is() {
        let mut v = LocalVault::open_in_memory().unwrap().with_kdf_cost(
            KdfParams::MIN_M_KIB,
            KdfParams::MIN_T,
            1,
        );
        v.create("correct horse battery").unwrap();
        assert!(!allowed(&v, "nc %h %p"));
        allow(&v, "nc %h %p").unwrap();
        assert!(allowed(&v, "nc %h %p"));
        // Changed, even by a space: asked again.
        assert!(!allowed(&v, "nc %h  %p"));
    }
}
