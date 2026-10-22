use std::sync::Arc;
use std::time::Duration;

use russh::client::Msg;
use russh::{ChannelMsg, ChannelWriteHalf};
use tokio::sync::mpsc;

use crate::connection::{Auth, Connection, Hop, HostKeyPrompt};
use crate::{KnownHosts, Result};

const EVENT_BUFFER: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct TermSize {
    pub cols: u32,
    pub rows: u32,
}

pub struct ConnectOptions {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: Auth,
    pub term: String,
    pub size: TermSize,
    /// Per hop: TCP connect / tunnel open plus handshake, excluding time spent in the host-key prompt.
    pub connect_timeout: Duration,
    /// Jump hosts (OpenSSH `ProxyJump`), nearest first. Empty for a direct connection.
    pub jumps: Vec<Hop>,
    /// How the last jump host carries the target: a command it runs (see [`Hop::via_command`]).
    pub via_command: Option<String>,
    /// The target's host keys, where its feed lists them (see [`Hop::listed_keys`]).
    pub listed_keys: Option<crate::ListedKeys>,
    /// Opens the first hop's TCP connection (e.g. through a per-host VPN); `None` = the OS.
    pub dialer: Option<Arc<dyn crate::Dialer>>,
    /// Forward this agent to the server (OpenSSH `ForwardAgent`): programs there can sign with
    /// its keys while the session is open.
    pub forward_agent: Option<crate::AgentSource>,
}

#[derive(Debug)]
pub enum SessionEvent {
    Output(Vec<u8>),
    Exit { status: u32 },
    Closed,
}

pub struct Session {
    conn: Connection,
    writer: ChannelWriteHalf<Msg>,
}

impl Session {
    /// A terminal with the user's login shell.
    pub async fn connect(
        opts: ConnectOptions,
        known_hosts: Arc<KnownHosts>,
        prompt: Arc<dyn HostKeyPrompt>,
    ) -> Result<(Self, mpsc::Receiver<SessionEvent>)> {
        Self::open(opts, None, known_hosts, prompt).await
    }

    /// A terminal that runs `command` (through the user's shell, as `ssh host command` does),
    /// e.g. attaching to a tmux session.
    pub async fn connect_running(
        opts: ConnectOptions,
        command: &str,
        known_hosts: Arc<KnownHosts>,
        prompt: Arc<dyn HostKeyPrompt>,
    ) -> Result<(Self, mpsc::Receiver<SessionEvent>)> {
        Self::open(opts, Some(command), known_hosts, prompt).await
    }

    async fn open(
        opts: ConnectOptions,
        command: Option<&str>,
        known_hosts: Arc<KnownHosts>,
        prompt: Arc<dyn HostKeyPrompt>,
    ) -> Result<(Self, mpsc::Receiver<SessionEvent>)> {
        let target = Hop {
            host: opts.host,
            port: opts.port,
            user: opts.user,
            auth: opts.auth,
            via_command: opts.via_command,
            listed_keys: opts.listed_keys,
        };
        let conn = Connection::open(
            target,
            opts.jumps,
            opts.dialer,
            opts.connect_timeout,
            known_hosts,
            prompt,
        )
        .await?;

        let channel = conn.handle.channel_open_session().await?;
        if let Some(source) = opts.forward_agent {
            conn.allow_agent_forwarding(source);
            channel.agent_forward(false).await?;
        }
        channel
            .request_pty(false, &opts.term, opts.size.cols, opts.size.rows, 0, 0, &[])
            .await?;
        match command {
            Some(command) => channel.exec(false, command).await?,
            None => channel.request_shell(false).await?,
        }
        let (mut reader, writer) = channel.split();

        let (tx, rx) = mpsc::channel(EVENT_BUFFER);
        tokio::spawn(async move {
            while let Some(msg) = reader.wait().await {
                let event = match msg {
                    ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                        SessionEvent::Output(data.to_vec())
                    }
                    ChannelMsg::ExitStatus { exit_status } => SessionEvent::Exit {
                        status: exit_status,
                    },
                    ChannelMsg::Close => break,
                    _ => continue,
                };
                if tx.send(event).await.is_err() {
                    return;
                }
            }
            let _ = tx.send(SessionEvent::Closed).await;
        });

        Ok((Self { conn, writer }, rx))
    }

    pub async fn write(&self, data: &[u8]) -> Result<()> {
        Ok(self.writer.data_bytes(data.to_vec()).await?)
    }

    pub async fn resize(&self, size: TermSize) -> Result<()> {
        Ok(self
            .writer
            .window_change(size.cols, size.rows, 0, 0)
            .await?)
    }

    pub async fn close(&self) -> Result<()> {
        let _ = self.writer.close().await;
        self.conn.close().await
    }
}
