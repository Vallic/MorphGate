//! SSH agents: where one listens, the keys it holds, and a stream to it (for signing in, and for
//! forwarding it to a server). Keys stay in the agent: 1Password, Bitwarden, KeePassXC,
//! Secretive, gpg-agent or OpenSSH's own, security keys (`sk-`) included.

use std::path::PathBuf;

use russh::keys::HashAlg;
use russh::keys::agent::AgentIdentity;
use russh::keys::agent::client::{AgentClient, AgentStream};

use crate::{Error, Result};

/// Where an agent listens.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum AgentSource {
    /// `$SSH_AUTH_SOCK`; on Windows, OpenSSH's pipe (`\\.\pipe\openssh-ssh-agent`), which
    /// 1Password and Bitwarden take over there.
    #[default]
    System,
    /// A Unix socket, or a Windows named pipe (`\\.\pipe\…`).
    Path(PathBuf),
    /// PuTTY's Pageant (Windows).
    Pageant,
}

/// The Windows pipe OpenSSH's agent listens on.
#[cfg(windows)]
const OPENSSH_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

/// A key an agent holds, as the UI shows it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentKey {
    /// `SHA256:…`
    pub fingerprint: String,
    /// `ssh-ed25519`, `sk-ssh-ed25519@openssh.com`, …
    pub algorithm: String,
    pub comment: String,
    /// The agent holds a certificate for this key.
    pub certificate: bool,
    /// A FIDO2 security key: signing waits for a touch.
    pub security_key: bool,
}

pub(crate) type Stream = Box<dyn AgentStream + Send + Unpin>;
pub(crate) type Client = AgentClient<Stream>;

/// A connection to the agent at `source`.
pub(crate) async fn stream(source: &AgentSource) -> Result<Stream> {
    match source {
        #[cfg(unix)]
        AgentSource::System => {
            let path = std::env::var_os("SSH_AUTH_SOCK")
                .filter(|p| !p.is_empty())
                .ok_or_else(|| {
                    Error::Agent("no agent is running here (SSH_AUTH_SOCK isn't set)".into())
                })?;
            let s = tokio::net::UnixStream::connect(&path)
                .await
                .map_err(|e| cant_reach(&PathBuf::from(path), e))?;
            Ok(Box::new(s))
        }
        #[cfg(windows)]
        AgentSource::System => pipe(OPENSSH_PIPE.as_ref()).await,
        #[cfg(unix)]
        AgentSource::Path(path) => {
            let s = tokio::net::UnixStream::connect(path)
                .await
                .map_err(|e| cant_reach(path, e))?;
            Ok(Box::new(s))
        }
        #[cfg(windows)]
        AgentSource::Path(path) => pipe(path.as_os_str()).await,
        #[cfg(windows)]
        AgentSource::Pageant => {
            let s = russh::keys::agent::client::AgentClient::connect_pageant()
                .await
                .map_err(|e| Error::Agent(format!("Pageant: {e}")))?;
            Ok(s.into_inner())
        }
        #[cfg(not(windows))]
        AgentSource::Pageant => Err(Error::Agent("Pageant runs on Windows only".into())),
        #[cfg(not(any(unix, windows)))]
        _ => Err(Error::Agent(
            "SSH agents aren't supported on this platform".into(),
        )),
    }
}

#[cfg(unix)]
fn cant_reach(path: &std::path::Path, e: std::io::Error) -> Error {
    Error::Agent(format!("{}: {e}", path.display()))
}

#[cfg(windows)]
async fn pipe(name: &std::ffi::OsStr) -> Result<Stream> {
    let c = AgentClient::connect_named_pipe(name)
        .await
        .map_err(|e| Error::Agent(format!("{}: {e}", name.to_string_lossy())))?;
    Ok(c.into_inner())
}

/// A client for the agent at `source`.
pub(crate) async fn client(source: &AgentSource) -> Result<Client> {
    Ok(AgentClient::connect(stream(source).await?))
}

/// The keys the agent at `source` holds.
pub async fn keys(source: &AgentSource) -> Result<Vec<AgentKey>> {
    let mut agent = client(source).await?;
    let ids = agent
        .request_identities()
        .await
        .map_err(|e| Error::Agent(e.to_string()))?;
    Ok(ids.iter().map(key_of).collect())
}

pub(crate) fn key_of(id: &AgentIdentity) -> AgentKey {
    let (key, comment, certificate) = match id {
        AgentIdentity::PublicKey { key, comment } => (key.clone(), comment.clone(), false),
        AgentIdentity::Certificate {
            certificate,
            comment,
        } => (
            russh::keys::PublicKey::new(certificate.public_key().clone(), ""),
            comment.clone(),
            true,
        ),
    };
    let algorithm = key.algorithm().as_str().to_owned();
    AgentKey {
        fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
        security_key: algorithm.starts_with("sk-"),
        algorithm,
        comment,
        certificate,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// Stops the agent however the test ends.
    struct Stop(std::process::Child);
    impl Drop for Stop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// A real `ssh-agent` holding one generated key (skipped where OpenSSH isn't installed).
    fn agent_with_key() -> Option<(tempfile::TempDir, Stop, PathBuf, String)> {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        let child = Stop(
            std::process::Command::new("ssh-agent")
                .arg("-D")
                .arg("-a")
                .arg(&sock)
                .stdout(std::process::Stdio::null())
                .spawn()
                .ok()?,
        );
        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let (pem, info) = crate::keys::generate_ed25519("agent-test").unwrap();
        let key = dir.path().join("id");
        std::fs::write(&key, pem.as_bytes()).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let added = std::process::Command::new("ssh-add")
            .arg(&key)
            .env("SSH_AUTH_SOCK", &sock)
            .stderr(std::process::Stdio::null())
            .status()
            .ok()?;
        assert!(added.success());
        Some((dir, child, sock, info.fingerprint))
    }

    #[tokio::test]
    async fn lists_the_keys_an_agent_holds() {
        let Some((_dir, _agent, sock, fingerprint)) = agent_with_key() else {
            eprintln!("no ssh-agent here: skipped");
            return;
        };
        let keys = keys(&AgentSource::Path(sock.clone())).await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].fingerprint, fingerprint);
        assert_eq!(keys[0].algorithm, "ssh-ed25519");
        assert_eq!(keys[0].comment, "agent-test");
        assert!(!keys[0].security_key && !keys[0].certificate);
    }

    #[tokio::test]
    async fn a_missing_socket_says_where() {
        let err = keys(&AgentSource::Path("/nonexistent/agent.sock".into()))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("/nonexistent/agent.sock"), "{err}");
    }
}
