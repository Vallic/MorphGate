//! SFTP tabs: each tab has its own SSH connection (saved credentials, jump hosts and VPN apply
//! as for a terminal), a remote file browser, the local file browser, and transfers with
//! progress and cancel.

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use mg_ssh::sftp::{Entry, Progress, TransferOptions, TransferSummary, list_local};
use mg_ssh::{Connection, Sftp};
use serde::Serialize;
use tauri::ipc::Channel;
use tauri::{AppHandle, State};
use tokio::sync::Mutex;

use crate::ssh::{Resolved, SshState, Target, resolve};
use crate::util::expand_home;
use crate::vault::VaultState;

const PROGRESS_EVERY: Duration = Duration::from_millis(120);

#[derive(Default)]
pub struct SftpState {
    conns: Mutex<HashMap<u64, Arc<Sftp>>>,
    transfers: Arc<Mutex<HashMap<u64, Arc<AtomicBool>>>>,
    next: AtomicU64,
}

impl SftpState {
    fn id(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed) + 1
    }

    async fn get(&self, id: u64) -> Result<Arc<Sftp>, String> {
        self.conns
            .lock()
            .await
            .get(&id)
            .cloned()
            .ok_or_else(|| "the SFTP connection is closed".into())
    }

    /// Lock: stop transfers and drop every connection.
    pub(crate) async fn close_all(&self) {
        for (_, cancel) in self.transfers.lock().await.drain() {
            cancel.store(true, Ordering::Relaxed);
        }
        self.conns.lock().await.clear();
    }
}

fn err(e: mg_ssh::Error) -> String {
    e.to_string()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Opened {
    id: u64,
    home: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Listing {
    /// The directory, made absolute.
    path: String,
    entries: Vec<Entry>,
}

#[tauri::command]
pub async fn sftp_open(
    app: AppHandle,
    ssh: State<'_, SshState>,
    vault: State<'_, VaultState>,
    vpns: State<'_, crate::vpn::VpnManager>,
    sftp: State<'_, SftpState>,
    target: Target,
) -> Result<Opened, String> {
    crate::renew::before_connect(&vault, &target).await?;
    let Resolved {
        target,
        jumps,
        vpn,
        proxy,
    } = resolve(target, &vault)?;
    let dialer = crate::ssh::first_hop(&app, &vault, &vpns, vpn, proxy).await?;
    crate::host_cas::trust(&vault, &ssh.known_hosts);
    let conn = Connection::open(
        target,
        jumps,
        dialer,
        Duration::from_secs(15),
        ssh.known_hosts.clone(),
        ssh.prompt(app.clone()),
    )
    .await
    .map_err(|e| crate::ssh::connect_error(&app, e))?;
    let session = Sftp::open(Arc::new(conn)).await.map_err(err)?;
    let home = session.home().await.map_err(err)?;
    let id = sftp.id();
    sftp.conns.lock().await.insert(id, Arc::new(session));
    Ok(Opened { id, home })
}

#[tauri::command]
pub async fn sftp_close(sftp: State<'_, SftpState>, id: u64) -> Result<(), String> {
    sftp.conns.lock().await.remove(&id);
    Ok(())
}

#[tauri::command]
pub async fn sftp_list(
    sftp: State<'_, SftpState>,
    id: u64,
    path: String,
) -> Result<Listing, String> {
    let s = sftp.get(id).await?;
    let path = s.canonicalize(&path).await.map_err(err)?;
    let entries = s.list(&path).await.map_err(err)?;
    Ok(Listing { path, entries })
}

#[tauri::command]
pub async fn sftp_mkdir(sftp: State<'_, SftpState>, id: u64, path: String) -> Result<(), String> {
    sftp.get(id).await?.mkdir(&path).await.map_err(err)
}

#[tauri::command]
pub async fn sftp_rename(
    sftp: State<'_, SftpState>,
    id: u64,
    from: String,
    to: String,
) -> Result<(), String> {
    sftp.get(id).await?.rename(&from, &to).await.map_err(err)
}

#[tauri::command]
pub async fn sftp_remove(
    sftp: State<'_, SftpState>,
    id: u64,
    paths: Vec<String>,
) -> Result<(), String> {
    let s = sftp.get(id).await?;
    for p in paths {
        s.remove(&p).await.map_err(err)?;
    }
    Ok(())
}

#[tauri::command]
pub async fn sftp_chmod(
    sftp: State<'_, SftpState>,
    id: u64,
    path: String,
    mode: u32,
) -> Result<(), String> {
    sftp.get(id).await?.chmod(&path, mode).await.map_err(err)
}

#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum TransferEvent {
    Progress(Progress),
    Done(TransferSummary),
    #[serde(rename_all = "camelCase")]
    Failed {
        message: String,
        /// Set when the destination already exists (the UI offers to replace).
        exists: Option<String>,
    },
    Cancelled,
}

/// Sends progress at most every [`PROGRESS_EVERY`], plus the first and the last.
fn throttled(events: Channel<TransferEvent>) -> impl FnMut(&Progress) {
    let mut last = Instant::now() - PROGRESS_EVERY;
    move |p: &Progress| {
        let finished = p.files_done == p.files_total && p.bytes_done == p.bytes_total;
        if finished || last.elapsed() >= PROGRESS_EVERY {
            last = Instant::now();
            let _ = events.send(TransferEvent::Progress(p.clone()));
        }
    }
}

fn outcome(result: mg_ssh::Result<TransferSummary>) -> TransferEvent {
    match result {
        Ok(summary) => TransferEvent::Done(summary),
        Err(mg_ssh::Error::Cancelled) => TransferEvent::Cancelled,
        Err(mg_ssh::Error::Exists(name)) => TransferEvent::Failed {
            message: format!("{name} already exists"),
            exists: Some(name),
        },
        Err(e) => TransferEvent::Failed {
            message: e.to_string(),
            exists: None,
        },
    }
}

/// Registers a transfer (for cancel) and runs it in the background, reporting on `events`.
async fn start_transfer<F>(
    sftp: &SftpState,
    overwrite: bool,
    events: Channel<TransferEvent>,
    run: impl FnOnce(TransferOptions, Channel<TransferEvent>) -> F,
) -> u64
where
    F: Future<Output = mg_ssh::Result<TransferSummary>> + Send + 'static,
{
    let id = sftp.id();
    let opts = TransferOptions {
        overwrite,
        ..Default::default()
    };
    sftp.transfers.lock().await.insert(id, opts.cancel.clone());
    let transfers = sftp.transfers.clone();
    let work = run(opts, events.clone());
    tauri::async_runtime::spawn(async move {
        let result = work.await;
        transfers.lock().await.remove(&id);
        let _ = events.send(outcome(result));
    });
    id
}

/// Copies remote files/directories into a local directory. Returns the transfer id.
#[tauri::command]
pub async fn sftp_download(
    sftp: State<'_, SftpState>,
    id: u64,
    paths: Vec<String>,
    local_dir: String,
    overwrite: bool,
    on_event: Channel<TransferEvent>,
) -> Result<u64, String> {
    let s = sftp.get(id).await?;
    let to = expand_home(&local_dir);
    Ok(
        start_transfer(&sftp, overwrite, on_event, |opts, events| async move {
            s.download(&paths, &to, &opts, throttled(events)).await
        })
        .await,
    )
}

/// Copies local files/directories into a remote directory. Returns the transfer id.
#[tauri::command]
pub async fn sftp_upload(
    sftp: State<'_, SftpState>,
    id: u64,
    paths: Vec<String>,
    remote_dir: String,
    overwrite: bool,
    on_event: Channel<TransferEvent>,
) -> Result<u64, String> {
    let s = sftp.get(id).await?;
    let paths: Vec<PathBuf> = paths.iter().map(|p| expand_home(p)).collect();
    Ok(
        start_transfer(&sftp, overwrite, on_event, |opts, events| async move {
            s.upload(&paths, &remote_dir, &opts, throttled(events))
                .await
        })
        .await,
    )
}

#[tauri::command]
pub async fn sftp_cancel(sftp: State<'_, SftpState>, transfer: u64) -> Result<(), String> {
    if let Some(c) = sftp.transfers.lock().await.remove(&transfer) {
        c.store(true, Ordering::Relaxed);
    }
    Ok(())
}

// ------------------------------------------------------------------ local side

#[tauri::command]
pub fn local_home() -> Result<String, String> {
    std::env::home_dir()
        .map(|h| h.display().to_string())
        .ok_or_else(|| "no home directory".into())
}

#[tauri::command]
pub async fn local_list(path: String) -> Result<Listing, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let dir = expand_home(&path)
            .canonicalize()
            .map_err(|e| format!("{path}: {e}"))?;
        let entries = list_local(&dir).map_err(err)?;
        Ok(Listing {
            path: dir.display().to_string(),
            entries,
        })
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub fn local_mkdir(path: String) -> Result<(), String> {
    let p = expand_home(&path);
    std::fs::create_dir(&p).map_err(|e| format!("{}: {e}", p.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipc_shapes_match_the_frontend() {
        let p = TransferEvent::Progress(Progress {
            bytes_done: 1,
            bytes_total: 2,
            files_done: 0,
            files_total: 1,
            current: "a".into(),
        });
        assert_eq!(
            serde_json::to_value(p).unwrap(),
            serde_json::json!({"kind": "progress", "bytesDone": 1, "bytesTotal": 2, "filesDone": 0, "filesTotal": 1, "current": "a"})
        );
        let f = outcome(Err(mg_ssh::Error::Exists("x".into())));
        assert_eq!(
            serde_json::to_value(f).unwrap(),
            serde_json::json!({"kind": "failed", "message": "x already exists", "exists": "x"})
        );
        let d = outcome(Ok(TransferSummary {
            bytes: 3,
            files: 1,
            skipped: vec![],
        }));
        assert_eq!(
            serde_json::to_value(d).unwrap(),
            serde_json::json!({"kind": "done", "bytes": 3, "files": 1, "skipped": []})
        );
        let e = list_local(std::path::Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
        let cargo = e.iter().find(|e| e.name == "Cargo.toml").unwrap();
        let v = serde_json::to_value(cargo).unwrap();
        assert_eq!(v["kind"], "file");
        assert!(v.get("linkDir").is_some() && v.get("modified").is_some());
    }
}
