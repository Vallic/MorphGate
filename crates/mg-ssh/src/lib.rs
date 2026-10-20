//! MorphGate SSH session layer on top of `russh`.
//!
//! One [`Session`] = one TCP connection + one interactive PTY shell. Output is delivered as
//! [`SessionEvent`]s on a bounded channel so a slow UI applies back-pressure to the SSH window.

pub mod agent;
pub mod authorized_keys;
mod command_stream;
mod connection;
mod error;
pub mod forward;
pub mod keys;
mod known_hosts;
mod proxy_command;
mod session;
pub mod sftp;
pub mod ssh_config;

pub use agent::{AgentKey, AgentSource};
pub use connection::{AsyncStream, Auth, BoxedStream, Connection, Dialer, Hop, HostKeyPrompt};
pub use error::Error;
pub use forward::{Forward, Tunnel};
pub use keys::KeyInfo;
pub use known_hosts::{HostAuthority, HostKeyCheck, HostKeyInfo, KnownHosts};
pub use proxy_command::ProxyCommand;
pub use session::{ConnectOptions, Session, SessionEvent, TermSize};
pub use sftp::Sftp;

pub type Result<T> = core::result::Result<T, Error>;
