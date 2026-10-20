//! SFTP over a [`Connection`]: browse and manage remote files, and copy files and directory
//! trees in both directions with progress and cancellation.
//!
//! Remote paths are POSIX strings. Downloads land in a `.part` file that is renamed when
//! complete, so an interrupted download never looks finished; uploads that may not overwrite
//! are created exclusively, so they can't clobber a file that appeared meanwhile.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::UNIX_EPOCH;

use russh_sftp::client::error::Error as SftpError;
use russh_sftp::client::{RawSftpSession, SftpSession};
use russh_sftp::protocol::{FileAttributes, FileType, OpenFlags, Packet, StatusCode};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{Connection, Error, Result};

const CHUNK: usize = 256 * 1024;
const PART: &str = ".mgpart";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    Dir,
    File,
    Symlink,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub name: String,
    pub kind: EntryKind,
    pub size: u64,
    /// Unix seconds.
    pub modified: Option<i64>,
    /// Permission bits (`0o755`), when known.
    pub mode: Option<u32>,
    /// A symlink that points at a directory (the UI can open it).
    pub link_dir: bool,
}

impl Entry {
    pub fn is_dir(&self) -> bool {
        self.kind == EntryKind::Dir || self.link_dir
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub files_done: u32,
    pub files_total: u32,
    /// The file being copied (relative to the transfer's destination).
    pub current: String,
}

/// How a transfer behaves.
#[derive(Clone, Default)]
pub struct TransferOptions {
    /// Replace files that exist at the destination (and merge into existing directories).
    pub overwrite: bool,
    /// Set to stop the transfer; the file in progress is removed.
    pub cancel: Arc<AtomicBool>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferSummary {
    pub bytes: u64,
    pub files: u32,
    /// Symlinked directories that were not followed.
    pub skipped: Vec<String>,
}

pub fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_owned()
    } else if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// The last component of a POSIX path.
pub fn base_name(path: &str) -> &str {
    path.trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(path)
}

fn kind(t: FileType) -> EntryKind {
    match t {
        FileType::Dir => EntryKind::Dir,
        FileType::File => EntryKind::File,
        FileType::Symlink => EntryKind::Symlink,
        FileType::Other => EntryKind::Other,
    }
}

fn entry(name: String, m: &FileAttributes) -> Entry {
    Entry {
        name,
        kind: kind(m.file_type()),
        size: m.len(),
        modified: m.mtime.map(i64::from),
        mode: m.permissions.map(|p| p & 0o7777),
        link_dir: false,
    }
}

fn map_err(path: &str, e: SftpError) -> Error {
    match &e {
        SftpError::Status(s) => match s.status_code {
            StatusCode::NoSuchFile => Error::Sftp(format!("{path}: no such file or directory")),
            StatusCode::PermissionDenied => Error::Sftp(format!("{path}: permission denied")),
            _ if s.error_message.is_empty() => Error::Sftp(format!("{path}: {}", s.status_code)),
            _ => Error::Sftp(format!("{path}: {}", s.error_message)),
        },
        _ => Error::Sftp(format!("{path}: {e}")),
    }
}

fn local_err(path: &Path, e: std::io::Error) -> Error {
    Error::Local {
        path: path.display().to_string(),
        source: e,
    }
}

fn check(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}

/// One file of a transfer plan.
struct Item {
    from: String,
    /// Destination relative to the transfer's target directory, `/`-separated.
    rel: String,
    size: u64,
    mode: Option<u32>,
}

#[derive(Default)]
struct Plan {
    /// Directories to create (relative), parents first.
    dirs: Vec<String>,
    files: Vec<Item>,
    skipped: Vec<String>,
    /// Top-level destination names, to check for conflicts.
    roots: Vec<String>,
}

impl Plan {
    fn total(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }
}

pub struct Sftp {
    session: SftpSession,
    conn: Arc<Connection>,
}

/// OpenSSH's atomic rename over an existing file (plain SFTP rename refuses to replace).
const POSIX_RENAME: &str = "posix-rename@openssh.com";

impl Sftp {
    /// Starts the `sftp` subsystem on its own channel of `conn`.
    pub async fn open(conn: Arc<Connection>) -> Result<Self> {
        let channel = conn.handle.channel_open_session().await?;
        channel.request_subsystem(true, "sftp").await?;
        let cfg = russh_sftp::client::Config {
            max_concurrent_reads: 32,
            max_concurrent_writes: 32,
            request_timeout_secs: 30,
            ..Default::default()
        };
        let session = SftpSession::new_with_config(channel.into_stream(), cfg)
            .await
            .map_err(|e| Error::Sftp(format!("the server has no SFTP subsystem ({e})")))?;
        Ok(Self { session, conn })
    }

    /// The directory a login starts in.
    pub async fn home(&self) -> Result<String> {
        self.session
            .canonicalize(".")
            .await
            .map_err(|e| map_err(".", e))
    }

    pub async fn canonicalize(&self, path: &str) -> Result<String> {
        self.session
            .canonicalize(path)
            .await
            .map_err(|e| map_err(path, e))
    }

    /// Directory contents, directories first, then by name.
    pub async fn list(&self, path: &str) -> Result<Vec<Entry>> {
        let dir = self
            .session
            .read_dir(path)
            .await
            .map_err(|e| map_err(path, e))?;
        let mut out = Vec::new();
        for d in dir {
            let mut e = entry(d.file_name(), &d.metadata());
            if e.kind == EntryKind::Symlink
                && let Ok(target) = self.session.metadata(d.path()).await
            {
                e.link_dir = target.file_type() == FileType::Dir;
                if !e.link_dir {
                    e.size = target.len();
                }
            }
            out.push(e);
        }
        out.sort_by(|a, b| {
            b.is_dir()
                .cmp(&a.is_dir())
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        Ok(out)
    }

    pub async fn stat(&self, path: &str) -> Result<Entry> {
        let m = self
            .session
            .symlink_metadata(path)
            .await
            .map_err(|e| map_err(path, e))?;
        Ok(entry(base_name(path).to_owned(), &m))
    }

    pub async fn exists(&self, path: &str) -> Result<bool> {
        match self.session.symlink_metadata(path).await {
            Ok(_) => Ok(true),
            Err(SftpError::Status(s)) if s.status_code == StatusCode::NoSuchFile => Ok(false),
            Err(e) => Err(map_err(path, e)),
        }
    }

    pub async fn mkdir(&self, path: &str) -> Result<()> {
        self.session
            .create_dir(path)
            .await
            .map_err(|e| map_err(path, e))
    }

    pub async fn rename(&self, from: &str, to: &str) -> Result<()> {
        if self.exists(to).await? {
            return Err(Error::Exists(to.to_owned()));
        }
        self.session
            .rename(from, to)
            .await
            .map_err(|e| map_err(from, e))
    }

    /// A small file's contents, or `None` when there is no such file.
    pub async fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>> {
        if !self.exists(path).await? {
            return Ok(None);
        }
        self.session
            .read(path)
            .await
            .map(Some)
            .map_err(|e| map_err(path, e))
    }

    /// Replaces (or creates) `path` atomically: the contents go to a temporary file beside it,
    /// which takes `mode` and is then renamed over `path` with OpenSSH's `posix-rename`. A server
    /// without it gets an error rather than a moment with no file or half a file.
    pub async fn replace_file(&self, path: &str, data: &[u8], mode: u32) -> Result<()> {
        let mut suffix = [0u8; 6];
        getrandom::fill(&mut suffix).map_err(|e| Error::Sftp(format!("random: {e}")))?;
        let tmp = format!(
            "{path}.morphgate-{}",
            suffix
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let written = async {
            let mut f = self
                .session
                .open_with_flags(
                    &tmp,
                    OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
                )
                .await
                .map_err(|e| map_err(&tmp, e))?;
            f.write_all(data)
                .await
                .map_err(|e| Error::Sftp(format!("{tmp}: {e}")))?;
            // Best effort: not every server offers fsync@openssh.com.
            let _ = f.sync_all().await;
            f.shutdown()
                .await
                .map_err(|e| Error::Sftp(format!("{tmp}: {e}")))?;
            self.chmod(&tmp, mode).await?;
            self.posix_rename(&tmp, path).await
        }
        .await;
        if written.is_err() {
            let _ = self.session.remove_file(&tmp).await;
        }
        written
    }

    async fn posix_rename(&self, from: &str, to: &str) -> Result<()> {
        let channel = self.conn.handle.channel_open_session().await?;
        channel.request_subsystem(true, "sftp").await?;
        let raw = RawSftpSession::new(channel.into_stream());
        let version = raw.init().await.map_err(|e| map_err(to, e))?;
        if version.extensions.get(POSIX_RENAME).map(String::as_str) != Some("1") {
            let _ = raw.close_session();
            return Err(Error::Sftp(format!(
                "{to}: this server can't replace files atomically (no {POSIX_RENAME})"
            )));
        }
        let mut data = Vec::with_capacity(8 + from.len() + to.len());
        for s in [from, to] {
            data.extend_from_slice(&(s.len() as u32).to_be_bytes());
            data.extend_from_slice(s.as_bytes());
        }
        let reply = raw.extended(POSIX_RENAME, data).await;
        let _ = raw.close_session();
        match reply.map_err(|e| map_err(to, e))? {
            Packet::Status(s) if s.status_code == StatusCode::Ok => Ok(()),
            Packet::Status(s) => Err(Error::Sftp(format!("{to}: {}", s.error_message))),
            _ => Err(Error::Sftp(format!(
                "{to}: unexpected reply to {POSIX_RENAME}"
            ))),
        }
    }

    pub async fn chmod(&self, path: &str, mode: u32) -> Result<()> {
        let mut attrs = FileAttributes::empty();
        attrs.permissions = Some(mode & 0o7777);
        self.session
            .set_metadata(path, attrs)
            .await
            .map_err(|e| map_err(path, e))
    }

    /// Removes files, symlinks and whole directory trees (symlinks are removed, never followed).
    pub async fn remove(&self, path: &str) -> Result<()> {
        let m = self
            .session
            .symlink_metadata(path)
            .await
            .map_err(|e| map_err(path, e))?;
        if m.file_type() != FileType::Dir {
            return self
                .session
                .remove_file(path)
                .await
                .map_err(|e| map_err(path, e));
        }
        // Depth-first without recursion: list, then remove children before parents.
        let mut stack = vec![(path.to_owned(), false)];
        while let Some((dir, listed)) = stack.pop() {
            if listed {
                self.session
                    .remove_dir(&dir)
                    .await
                    .map_err(|e| map_err(&dir, e))?;
                continue;
            }
            stack.push((dir.clone(), true));
            let entries = self
                .session
                .read_dir(&dir)
                .await
                .map_err(|e| map_err(&dir, e))?;
            for d in entries {
                let child = join(&dir, &d.file_name());
                if d.file_type() == FileType::Dir {
                    stack.push((child, false));
                } else {
                    self.session
                        .remove_file(&child)
                        .await
                        .map_err(|e| map_err(&child, e))?;
                }
            }
        }
        Ok(())
    }

    // -------------------------------------------------------------- download

    async fn plan_remote(&self, paths: &[String], cancel: &AtomicBool) -> Result<Plan> {
        let mut plan = Plan::default();
        for path in paths {
            check(cancel)?;
            let name = base_name(path).to_owned();
            let m = self
                .session
                .metadata(path)
                .await
                .map_err(|e| map_err(path, e))?;
            plan.roots.push(name.clone());
            if m.file_type() != FileType::Dir {
                plan.files.push(Item {
                    from: path.clone(),
                    rel: name,
                    size: m.len(),
                    mode: m.permissions,
                });
                continue;
            }
            plan.dirs.push(name.clone());
            let mut queue = vec![(path.clone(), name)];
            while let Some((dir, rel)) = queue.pop() {
                check(cancel)?;
                let entries = self
                    .session
                    .read_dir(&dir)
                    .await
                    .map_err(|e| map_err(&dir, e))?;
                for d in entries {
                    let (from, child) = (join(&dir, &d.file_name()), join(&rel, &d.file_name()));
                    let mut meta = d.metadata();
                    if d.file_type() == FileType::Symlink {
                        match self.session.metadata(&from).await {
                            Ok(t) if t.file_type() == FileType::Dir => {
                                plan.skipped.push(child);
                                continue;
                            }
                            Ok(t) => meta = t,
                            // A dangling link: nothing to copy.
                            Err(_) => {
                                plan.skipped.push(child);
                                continue;
                            }
                        }
                    }
                    match meta.file_type() {
                        FileType::Dir => {
                            plan.dirs.push(child.clone());
                            queue.push((from, child));
                        }
                        FileType::File => plan.files.push(Item {
                            from,
                            rel: child,
                            size: meta.len(),
                            mode: meta.permissions,
                        }),
                        _ => plan.skipped.push(child),
                    }
                }
            }
        }
        Ok(plan)
    }

    /// Copies remote files and directory trees into the local directory `to`.
    pub async fn download(
        &self,
        paths: &[String],
        to: &Path,
        opts: &TransferOptions,
        mut progress: impl FnMut(&Progress),
    ) -> Result<TransferSummary> {
        let cancel = &opts.cancel;
        let plan = self.plan_remote(paths, cancel).await?;
        if !opts.overwrite {
            for root in &plan.roots {
                if to.join(root).symlink_metadata().is_ok() {
                    return Err(Error::Exists(root.clone()));
                }
            }
        }
        for dir in &plan.dirs {
            let p = to.join(dir);
            match std::fs::create_dir(&p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && p.is_dir() => {}
                Err(e) => return Err(local_err(&p, e)),
            }
        }
        let mut p = Progress {
            bytes_total: plan.total(),
            files_total: plan.files.len() as u32,
            ..Default::default()
        };
        progress(&p);
        let mut buf = vec![0u8; CHUNK];
        for item in &plan.files {
            check(cancel)?;
            p.current = item.rel.clone();
            progress(&p);
            let dest = to.join(&item.rel);
            let part = PathBuf::from(format!("{}{PART}", dest.display()));
            let result = async {
                let mut remote = self
                    .session
                    .open(&item.from)
                    .await
                    .map_err(|e| map_err(&item.from, e))?;
                let mut local = tokio::fs::File::create(&part)
                    .await
                    .map_err(|e| local_err(&part, e))?;
                loop {
                    check(cancel)?;
                    let n = remote
                        .read(&mut buf)
                        .await
                        .map_err(|e| Error::Sftp(format!("{}: {e}", item.from)))?;
                    if n == 0 {
                        break;
                    }
                    local
                        .write_all(&buf[..n])
                        .await
                        .map_err(|e| local_err(&part, e))?;
                    p.bytes_done += n as u64;
                    progress(&p);
                }
                local.flush().await.map_err(|e| local_err(&part, e))?;
                drop(local);
                #[cfg(unix)]
                if let Some(mode) = item.mode {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        &part,
                        std::fs::Permissions::from_mode(mode & 0o777),
                    );
                }
                std::fs::rename(&part, &dest).map_err(|e| local_err(&dest, e))
            }
            .await;
            if let Err(e) = result {
                let _ = std::fs::remove_file(&part);
                return Err(e);
            }
            p.files_done += 1;
            progress(&p);
        }
        Ok(TransferSummary {
            bytes: p.bytes_done,
            files: p.files_done,
            skipped: plan.skipped,
        })
    }

    // -------------------------------------------------------------- upload

    fn plan_local(paths: &[PathBuf], cancel: &AtomicBool) -> Result<Plan> {
        let mut plan = Plan::default();
        for path in paths {
            check(cancel)?;
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .ok_or_else(|| local_err(path, std::io::ErrorKind::InvalidInput.into()))?;
            let m = std::fs::metadata(path).map_err(|e| local_err(path, e))?;
            plan.roots.push(name.clone());
            if !m.is_dir() {
                plan.files.push(Item {
                    from: path.display().to_string(),
                    rel: name,
                    size: m.len(),
                    mode: mode_of(&m),
                });
                continue;
            }
            plan.dirs.push(name.clone());
            let mut queue = vec![(path.clone(), name)];
            while let Some((dir, rel)) = queue.pop() {
                check(cancel)?;
                let mut entries: Vec<_> = std::fs::read_dir(&dir)
                    .map_err(|e| local_err(&dir, e))?
                    .filter_map(|e| e.ok())
                    .collect();
                entries.sort_by_key(|e| e.file_name());
                for e in entries {
                    let from = e.path();
                    let child = join(&rel, &e.file_name().to_string_lossy());
                    let link = e.file_type().is_ok_and(|t| t.is_symlink());
                    let Ok(meta) = std::fs::metadata(&from) else {
                        plan.skipped.push(child);
                        continue;
                    };
                    if meta.is_dir() {
                        if link {
                            plan.skipped.push(child);
                            continue;
                        }
                        plan.dirs.push(child.clone());
                        queue.push((from, child));
                    } else if meta.is_file() {
                        plan.files.push(Item {
                            from: from.display().to_string(),
                            rel: child,
                            size: meta.len(),
                            mode: mode_of(&meta),
                        });
                    } else {
                        plan.skipped.push(child);
                    }
                }
            }
        }
        Ok(plan)
    }

    /// Copies local files and directory trees into the remote directory `to`.
    pub async fn upload(
        &self,
        paths: &[PathBuf],
        to: &str,
        opts: &TransferOptions,
        mut progress: impl FnMut(&Progress),
    ) -> Result<TransferSummary> {
        let cancel = &opts.cancel;
        let plan = {
            let paths = paths.to_vec();
            let cancel = cancel.clone();
            tokio::task::spawn_blocking(move || Self::plan_local(&paths, &cancel))
                .await
                .map_err(|e| Error::Sftp(e.to_string()))??
        };
        if !opts.overwrite {
            for root in &plan.roots {
                if self.exists(&join(to, root)).await? {
                    return Err(Error::Exists(root.clone()));
                }
            }
        }
        for dir in &plan.dirs {
            let path = join(to, dir);
            if let Err(e) = self.session.create_dir(&path).await {
                match self.session.metadata(&path).await {
                    Ok(m) if m.file_type() == FileType::Dir => {}
                    _ => return Err(map_err(&path, e)),
                }
            }
        }
        let mut p = Progress {
            bytes_total: plan.total(),
            files_total: plan.files.len() as u32,
            ..Default::default()
        };
        progress(&p);
        let mut buf = vec![0u8; CHUNK];
        for item in &plan.files {
            check(cancel)?;
            p.current = item.rel.clone();
            progress(&p);
            let dest = join(to, &item.rel);
            let flags = if opts.overwrite {
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE
            } else {
                OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE
            };
            let mut remote = match self.session.open_with_flags(&dest, flags).await {
                Ok(f) => f,
                Err(e) if !opts.overwrite && self.exists(&dest).await.unwrap_or(false) => {
                    tracing::debug!(%e, "upload target exists");
                    return Err(Error::Exists(item.rel.clone()));
                }
                Err(e) => return Err(map_err(&dest, e)),
            };
            let result = async {
                let from = PathBuf::from(&item.from);
                let mut local = tokio::fs::File::open(&from)
                    .await
                    .map_err(|e| local_err(&from, e))?;
                loop {
                    check(cancel)?;
                    let n = local
                        .read(&mut buf)
                        .await
                        .map_err(|e| local_err(&from, e))?;
                    if n == 0 {
                        break;
                    }
                    remote
                        .write_all(&buf[..n])
                        .await
                        .map_err(|e| Error::Sftp(format!("{dest}: {e}")))?;
                    p.bytes_done += n as u64;
                    progress(&p);
                }
                remote
                    .shutdown()
                    .await
                    .map_err(|e| Error::Sftp(format!("{dest}: {e}")))?;
                Ok(())
            }
            .await;
            if let Err(e) = result {
                drop(remote);
                let _ = self.session.remove_file(&dest).await;
                return Err(e);
            }
            drop(remote);
            if let Some(mode) = item.mode {
                let _ = self.chmod(&dest, mode).await;
            }
            p.files_done += 1;
            progress(&p);
        }
        Ok(TransferSummary {
            bytes: p.bytes_done,
            files: p.files_done,
            skipped: plan.skipped,
        })
    }

    pub async fn close(self) -> Result<()> {
        self.session
            .close()
            .await
            .map_err(|e| Error::Sftp(e.to_string()))
    }
}

#[cfg(unix)]
fn mode_of(m: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(m.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
fn mode_of(_: &std::fs::Metadata) -> Option<u32> {
    None
}

/// Unix seconds of a local file's modification time.
pub fn local_mtime(m: &std::fs::Metadata) -> Option<i64> {
    m.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
}

/// A local directory's contents, in the same shape and order as [`Sftp::list`].
pub fn list_local(dir: &Path) -> Result<Vec<Entry>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).map_err(|e| local_err(dir, e))? {
        let Ok(e) = e else { continue };
        let name = e.file_name().to_string_lossy().into_owned();
        let link = e.file_type().is_ok_and(|t| t.is_symlink());
        let meta = std::fs::metadata(e.path()).or_else(|_| e.metadata());
        let Ok(meta) = meta else { continue };
        out.push(Entry {
            name,
            kind: if link {
                EntryKind::Symlink
            } else if meta.is_dir() {
                EntryKind::Dir
            } else if meta.is_file() {
                EntryKind::File
            } else {
                EntryKind::Other
            },
            size: if meta.is_file() { meta.len() } else { 0 },
            modified: local_mtime(&meta),
            mode: mode_of(&meta),
            link_dir: link && meta.is_dir(),
        });
    }
    out.sort_by(|a, b| {
        b.is_dir()
            .cmp(&a.is_dir())
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posix_paths() {
        assert_eq!(join("/home/u", "a"), "/home/u/a");
        assert_eq!(join("/", "a"), "/a");
        assert_eq!(join("", "a"), "a");
        assert_eq!(base_name("/home/u/dir/"), "dir");
        assert_eq!(base_name("file"), "file");
        assert_eq!(base_name("/"), "/");
    }

    #[test]
    fn local_listing_puts_directories_first() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("b.txt"), b"hello").unwrap();
        std::fs::create_dir(d.path().join("Zdir")).unwrap();
        std::fs::write(d.path().join("A.txt"), b"x").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(d.path().join("Zdir"), d.path().join("link")).unwrap();
        let l = list_local(d.path()).unwrap();
        let names: Vec<_> = l.iter().map(|e| e.name.as_str()).collect();
        #[cfg(unix)]
        assert_eq!(names, vec!["link", "Zdir", "A.txt", "b.txt"]);
        let b = l.iter().find(|e| e.name == "b.txt").unwrap();
        assert_eq!((b.kind, b.size), (EntryKind::File, 5));
    }
}
