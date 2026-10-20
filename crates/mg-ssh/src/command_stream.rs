//! A command's stdin and stdout as a byte stream, as ssh's ProxyCommand uses one, keeping what
//! it writes to stderr: where it refuses (`jump web-9`: "no machine called …"), that's the
//! only account of why, and russh's own channel stream drops it.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use russh::client::Msg;
use russh::{Channel, ChannelMsg};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// Enough for a message; a command that writes more to stderr is cut, not stalled.
const STDERR_LIMIT: usize = 4096;

pub(crate) struct CommandStream {
    stdout: DuplexStream,
    stdin: Pin<Box<dyn AsyncWrite + Send>>,
    /// Dropped with the stream: the pump closes the channel.
    _open: oneshot::Sender<()>,
}

/// What the command wrote to stderr, readable once the stream has failed.
pub(crate) struct Stderr {
    text: Arc<Mutex<Vec<u8>>>,
    pump: JoinHandle<()>,
}

/// Adds `bytes` to a command's kept stderr, up to [`STDERR_LIMIT`].
pub(crate) fn keep(text: &Mutex<Vec<u8>>, bytes: &[u8]) {
    let mut t = text.lock().expect("not poisoned");
    let room = STDERR_LIMIT.saturating_sub(t.len());
    t.extend_from_slice(&bytes[..bytes.len().min(room)]);
}

impl Stderr {
    /// What `pump` keeps in `text` (with [`keep`]) until the command's stderr ends.
    pub(crate) fn new(text: Arc<Mutex<Vec<u8>>>, pump: JoinHandle<()>) -> Self {
        Self { text, pump }
    }

    /// The command's stderr, trimmed; empty for none. Waits a moment for the command to finish,
    /// so a message sent just before it exits isn't missed.
    pub(crate) async fn text(self) -> String {
        let _ = tokio::time::timeout(Duration::from_secs(1), self.pump).await;
        let bytes = self.text.lock().expect("not poisoned");
        String::from_utf8_lossy(&bytes).trim().to_owned()
    }
}

/// Makes a session channel running a command into a stream, and the command's stderr.
pub(crate) fn command_stream(channel: Channel<Msg>) -> (CommandStream, Stderr) {
    let (mut read, write) = channel.split();
    let stdin = Box::pin(write.make_writer());
    let (stdout, mut into_stdout) = tokio::io::duplex(64 * 1024);
    let (open, mut closed) = oneshot::channel::<()>();
    let text = Arc::new(Mutex::new(Vec::new()));
    let kept = text.clone();
    let pump = tokio::spawn(async move {
        loop {
            tokio::select! {
                msg = read.wait() => match msg {
                    Some(ChannelMsg::Data { data }) => {
                        if into_stdout.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    Some(ChannelMsg::ExtendedData { data, ext: 1 }) => keep(&kept, &data),
                    Some(ChannelMsg::Eof | ChannelMsg::Close) | None => break,
                    Some(_) => {}
                },
                // The stream was dropped.
                _ = &mut closed => break,
            }
        }
        let _ = into_stdout.shutdown().await;
        let _ = write.close().await;
    });
    (
        CommandStream {
            stdout,
            stdin,
            _open: open,
        },
        Stderr { text, pump },
    )
}

impl AsyncRead for CommandStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdout).poll_read(cx, buf)
    }
}

impl AsyncWrite for CommandStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.stdin.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stdin.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stdin.as_mut().poll_shutdown(cx)
    }
}
