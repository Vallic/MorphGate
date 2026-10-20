//! Session logs. A saved host with `record_sessions` has its terminal output recorded as an
//! asciicast v2 stream, deflated and sealed into blobs of the host's vault, listed by a
//! `session_log` item there. Sync uploads the blobs; the player fetches the ones recorded
//! elsewhere and reads them back.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use mg_store::{BlobKind, BlobState, ItemData, LogChunk, SessionLog};
use serde::Serialize;
use tauri::{AppHandle, Manager, State};

use crate::orgs::with_client;
use crate::sync::SyncState;
use crate::vault::VaultState;

/// Plaintext gathered before a chunk is sealed (deflated, logs shrink to a tenth or less).
const CHUNK_BYTES: usize = 512 * 1024;
/// A quiet session still gets its output saved this often.
const FLUSH_EVERY: std::time::Duration = std::time::Duration::from_secs(60);

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn dim(n: u32) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX).max(1)
}

fn deflate(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut e = DeflateEncoder::new(Vec::new(), Compression::default());
    e.write_all(data)?;
    e.finish()
}

fn inflate(data: &[u8]) -> std::io::Result<String> {
    let mut out = String::new();
    DeflateDecoder::new(data).read_to_string(&mut out)?;
    Ok(out)
}

/// Records one session.
pub(crate) struct Recorder {
    app: AppHandle,
    vault_id: String,
    item_id: String,
    log: SessionLog,
    started: Instant,
    /// asciicast lines not sealed yet (the header first).
    events: String,
    /// The start of a UTF-8 sequence split across reads.
    carry: Vec<u8>,
    flushed_at: Instant,
    /// Saving failed once (vault locked, say): the rest isn't recorded.
    stopped: bool,
}

pub(crate) type SharedRecorder = Arc<Mutex<Recorder>>;

impl Recorder {
    /// Starts recording a session with the saved host `host_id`; `None` when it isn't recorded
    /// (or this device can't write to its vault).
    pub(crate) fn start(app: &AppHandle, host_id: &str, cols: u32, rows: u32) -> Option<Self> {
        let (cols, rows) = (dim(cols), dim(rows));
        let state = app.state::<VaultState>();
        let mut v = state.guard().ok()?;
        let host = v.item(host_id).ok()?;
        let ItemData::Host(h) = host.data else {
            return None;
        };
        if !h.record_sessions {
            return None;
        }
        let log = SessionLog {
            host_ref: Some(host_id.into()),
            title: h.label.clone(),
            address: format!("{}@{}:{}", h.user, h.hostname, h.port),
            started_at: now_ms(),
            ended_at: None,
            cols,
            rows,
            chunks: Vec::new(),
            output_bytes: 0,
            device: crate::sync::device_name(),
        };
        let item = match v.upsert_in(&host.vault_id, None, ItemData::SessionLog(log.clone())) {
            Ok(item) => item,
            Err(e) => {
                tracing::warn!("not recording {}: {e}", h.label);
                return None;
            }
        };
        drop(v);
        state.changed();
        let header = serde_json::json!({
            "version": 2,
            "width": cols,
            "height": rows,
            "timestamp": log.started_at / 1000,
            "title": h.label,
            "env": { "TERM": "xterm-256color" },
        });
        Some(Self {
            app: app.clone(),
            vault_id: host.vault_id,
            item_id: item.id,
            log,
            started: Instant::now(),
            events: format!("{header}\n"),
            carry: Vec::new(),
            flushed_at: Instant::now(),
            stopped: false,
        })
    }

    pub(crate) fn item_id(&self) -> &str {
        &self.item_id
    }

    fn event(&mut self, code: &str, data: &str) {
        let t = self.started.elapsed().as_secs_f64();
        let line = serde_json::json!([(t * 1_000_000.0).round() / 1_000_000.0, code, data]);
        self.events.push_str(&line.to_string());
        self.events.push('\n');
    }

    /// Terminal output, as the session printed it.
    pub(crate) fn output(&mut self, bytes: &[u8]) {
        if self.stopped {
            return;
        }
        self.log.output_bytes += bytes.len() as u64;
        let mut data = std::mem::take(&mut self.carry);
        data.extend_from_slice(bytes);
        // Keep an incomplete trailing sequence for the next read.
        let complete = match std::str::from_utf8(&data) {
            Ok(_) => data.len(),
            Err(e) if e.error_len().is_none() => e.valid_up_to(),
            Err(_) => data.len(),
        };
        self.carry = data.split_off(complete);
        if !data.is_empty() {
            let text = String::from_utf8_lossy(&data).into_owned();
            self.event("o", &text);
        }
        if self.events.len() >= CHUNK_BYTES || self.flushed_at.elapsed() >= FLUSH_EVERY {
            self.flush();
        }
    }

    pub(crate) fn resize(&mut self, cols: u32, rows: u32) {
        if !self.stopped {
            self.event("r", &format!("{}x{}", dim(cols), dim(rows)));
        }
    }

    /// Seals what was gathered as the next chunk and updates the item.
    fn flush(&mut self) {
        self.flushed_at = Instant::now();
        if self.stopped {
            return;
        }
        let state = self.app.state::<VaultState>();
        let saved = (|| -> Result<(), String> {
            if !self.events.is_empty() {
                let chunk = deflate(self.events.as_bytes()).map_err(|e| e.to_string())?;
                let blob = state
                    .guard()?
                    .add_blob(&self.vault_id, BlobKind::SessionLog, &chunk)
                    .map_err(|e| e.to_string())?;
                self.log.chunks.push(LogChunk {
                    hash: blob.hash,
                    size: blob.size,
                });
                self.events.clear();
            }
            state
                .guard()?
                .upsert(Some(&self.item_id), ItemData::SessionLog(self.log.clone()))
                .map_err(|e| e.to_string())?;
            Ok(())
        })();
        match saved {
            Ok(()) => state.changed(),
            Err(e) => {
                tracing::warn!("stopped recording {}: {e}", self.log.title);
                self.stopped = true;
            }
        }
    }

    /// The session closed: saves the rest and when it ended.
    pub(crate) fn finish(&mut self) {
        if !self.carry.is_empty() {
            let rest = String::from_utf8_lossy(&std::mem::take(&mut self.carry)).into_owned();
            self.event("o", &rest);
        }
        self.log.ended_at = Some(now_ms());
        self.flush();
        self.stopped = true;
    }
}

// ------------------------------------------------------------------ commands

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionLogView {
    id: String,
    vault_id: String,
    host_id: Option<String>,
    title: String,
    address: String,
    started_at: i64,
    ended_at: Option<i64>,
    output_bytes: u64,
    /// Sealed size of the recording.
    size: u64,
    device: String,
    /// `local` (all here and uploaded), `uploading`, `remote` (recorded elsewhere, fetched
    /// when played), or `failed` (the server refused it; `problem` says why).
    state: &'static str,
    problem: Option<String>,
    /// Where the plan that takes it is bought, when that's why it was refused.
    upgrade_url: Option<String>,
}

#[tauri::command]
pub fn session_logs(
    vault: State<'_, VaultState>,
    host_id: Option<String>,
) -> Result<Vec<SessionLogView>, String> {
    let v = vault.guard()?;
    let mut logs: Vec<SessionLogView> = v
        .items()
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter_map(|i| match i.data {
            ItemData::SessionLog(l)
                if host_id.is_none() || l.host_ref.as_deref() == host_id.as_deref() =>
            {
                let mut state = "local";
                let mut refusal = None;
                for c in &l.chunks {
                    match v.blob_state(&i.vault_id, &c.hash).ok().flatten() {
                        Some(BlobState::Failed(why)) => {
                            state = "failed";
                            refusal = Some(why);
                        }
                        Some(BlobState::Pending) if state != "failed" => state = "uploading",
                        None if state == "local" => state = "remote",
                        _ => {}
                    }
                }
                Some(SessionLogView {
                    id: i.id,
                    vault_id: i.vault_id,
                    host_id: l.host_ref,
                    title: l.title,
                    address: l.address,
                    started_at: l.started_at,
                    ended_at: l.ended_at,
                    output_bytes: l.output_bytes,
                    size: l.chunks.iter().map(|c| c.size).sum(),
                    device: l.device,
                    state,
                    problem: refusal.as_ref().map(|r| r.reason.clone()),
                    upgrade_url: refusal.and_then(|r| r.upgrade_url),
                })
            }
            _ => None,
        })
        .collect();
    logs.sort_by_key(|l| std::cmp::Reverse(l.started_at));
    Ok(logs)
}

/// The recording as an asciicast v2 file, fetching chunks recorded on other devices.
#[tauri::command]
pub async fn session_log_cast(
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    id: String,
) -> Result<String, String> {
    let (vault_id, log) = {
        let item = vault.guard()?.item(&id).map_err(|e| e.to_string())?;
        let ItemData::SessionLog(log) = item.data else {
            return Err("not a session log".into());
        };
        (item.vault_id, log)
    };
    let mut cast = String::new();
    for chunk in &log.chunks {
        let local = vault
            .guard()?
            .open_blob(&vault_id, BlobKind::SessionLog, &chunk.hash)
            .map_err(|e| e.to_string())?;
        let plain = match local {
            Some(p) => p,
            None => {
                let (v, h) = (vault_id.clone(), chunk.hash.clone());
                let bytes = with_client(&sync, &vault, async |c| Ok(c.blob(&v, &h).await?))
                    .await
                    .map_err(|e| {
                        if e.contains("(not_found)") || e.contains("404") {
                            "part of this recording is no longer on the sync server (the team's retention policy may have removed it)".to_owned()
                        } else {
                            e
                        }
                    })?;
                let mut g = vault.guard()?;
                g.store_blob(&vault_id, BlobKind::SessionLog, &chunk.hash, &bytes)
                    .map_err(|e| e.to_string())?;
                g.open_blob(&vault_id, BlobKind::SessionLog, &chunk.hash)
                    .map_err(|e| e.to_string())?
                    .ok_or("the recording could not be stored")?
            }
        };
        cast.push_str(&inflate(&plain).map_err(|e| format!("damaged recording: {e}"))?);
    }
    Ok(cast)
}

/// Saves the recording as a `.cast` file in Downloads; returns its path.
#[tauri::command]
pub async fn session_log_save(
    app: AppHandle,
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    id: String,
) -> Result<String, String> {
    let title = match vault.guard()?.item(&id).map_err(|e| e.to_string())?.data {
        ItemData::SessionLog(l) => l.title,
        _ => return Err("not a session log".into()),
    };
    let cast = session_log_cast(vault, sync, id.clone()).await?;
    let path = crate::util::download_path(
        &app,
        &format!("{title}-{}", id[..10].to_lowercase()),
        "cast",
    )?;
    std::fs::write(&path, cast).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(crate::util::saved(&path))
}

#[tauri::command]
pub fn session_log_delete(vault: State<'_, VaultState>, id: String) -> Result<(), String> {
    match vault.guard()?.item(&id).map_err(|e| e.to_string())?.data {
        ItemData::SessionLog(_) => {}
        _ => return Err("not a session log".into()),
    }
    vault.guard()?.delete(&id).map_err(|e| e.to_string())?;
    vault.changed();
    Ok(())
}

/// Uploads refused recordings again (after the plan changed, say).
#[tauri::command]
pub fn session_logs_retry(vault: State<'_, VaultState>) -> Result<usize, String> {
    let n = vault
        .guard()?
        .retry_failed_blobs()
        .map_err(|e| e.to_string())?;
    vault.changed();
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deflate_round_trip() {
        let text = "{\"version\":2}\n[0.5,\"o\",\"$ ls\\r\\n\"]\n".repeat(200);
        let packed = deflate(text.as_bytes()).unwrap();
        assert!(packed.len() < text.len() / 10);
        assert_eq!(inflate(&packed).unwrap(), text);
    }
}
