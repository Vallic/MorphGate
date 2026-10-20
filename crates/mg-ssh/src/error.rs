use crate::HostKeyInfo;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("could not connect to {0}: timed out")]
    Timeout(String),
    #[error("could not connect to {addr}: {source}")]
    Connect {
        addr: String,
        source: std::io::Error,
    },
    #[error(
        "REMOTE HOST KEY CHANGED for {}:{} ({} {}). Someone may be intercepting the connection; \
         remove the old entry from {} line {} only if you know the key was rotated.",
        .0.host, .0.port, .0.algorithm, .0.fingerprint, .0.changed_in.as_ref().map(|c| c.0.display().to_string()).unwrap_or_default(),
        .0.changed_in.as_ref().map(|c| c.1).unwrap_or_default()
    )]
    HostKeyChanged(Box<HostKeyInfo>),
    #[error("host key for {}:{} was not accepted", .0.host, .0.port)]
    HostKeyRejected(Box<HostKeyInfo>),
    /// A host certificate where a CA is trusted for the host, that the CA didn't sign for it.
    #[error("the host certificate of {host}:{port} isn't accepted: {why}")]
    HostCertificate {
        host: String,
        port: u16,
        why: String,
    },
    #[error("could not listen on {addr}: {source}")]
    Bind {
        addr: String,
        source: std::io::Error,
    },
    #[error("could not reach {addr}: {reason}")]
    Unreachable { addr: String, reason: String },
    #[error("via jump host {host}: {source}")]
    Jump { host: String, source: Box<Error> },
    #[error("authentication failed")]
    AuthFailed,
    #[error("private key is encrypted; a passphrase is required")]
    KeyNeedsPassphrase,
    #[error("could not load private key: {0}")]
    Key(String),
    #[error("ssh agent: {0}")]
    Agent(String),
    #[error("known_hosts: {0}")]
    KnownHosts(String),
    #[error("ssh config: {0}")]
    Config(String),
    #[error("ssh: {0}")]
    Ssh(#[from] russh::Error),
    #[error("sftp: {0}")]
    Sftp(String),
    #[error("{path}: {source}")]
    Local {
        path: String,
        source: std::io::Error,
    },
    #[error("{0} already exists")]
    Exists(String),
    #[error("cancelled")]
    Cancelled,
}
