//! A command run on this device whose stdin and stdout are the first hop's connection, as
//! OpenSSH's `ProxyCommand`: AWS Session Manager, EC2 Instance Connect Endpoints, Google's IAP
//! tunnel, `nc -X 5 -x proxy:1080 %h %p`. What it writes to stderr is the error when the
//! connection through it fails. Also `%h`, `%p` and `%r`, for it and for the jump command.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

use crate::command_stream::Stderr;
use crate::connection::{BoxedStream, Dialer};

/// A host name as a command may be given it: letters, digits, `.`, `-`, `_`, `:` and the
/// brackets of an IPv6 address. A host name or user from a vault goes into a shell command, so
/// one that could be read as more than a word (`;`, `$(…)`, a space) is refused, as OpenSSH does
/// for `%h` and `%r` since 9.6.
fn plain_host(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-_:[]".contains(c))
}

/// A user name as a command may be given it: letters, digits, `.`, `-`, `_` and `@`.
fn plain_user(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-_@".contains(c))
}

/// `%h`, `%p`, `%r` and `%%` in a command, refusing a host or user that isn't a plain word (see
/// [`plain_host`]). Another `%` and what follows it stay as they are.
pub(crate) fn expand(command: &str, host: &str, port: u16, user: &str) -> Result<String, String> {
    let mut out = String::with_capacity(command.len());
    let mut chars = command.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('h') if plain_host(host) => out.push_str(host),
            Some('h') => {
                return Err(format!(
                    "the host name {host:?} can't be given to a command (%h)"
                ));
            }
            Some('p') => out.push_str(&port.to_string()),
            Some('r') if plain_user(user) => out.push_str(user),
            Some('r') => {
                return Err(format!(
                    "the user name {user:?} can't be given to a command (%r)"
                ));
            }
            Some('%') => out.push('%'),
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    Ok(out)
}

/// Runs `command` through this system's shell.
fn shell(command: &str) -> Command {
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let mut c = Command::new("cmd");
        // As typed: cmd doesn't split its command line the way programs' argv is quoted.
        c.raw_arg("/D /S /C \"").raw_arg(command).raw_arg("\"");
        c.creation_flags(CREATE_NO_WINDOW);
        c
    }
    #[cfg(not(windows))]
    {
        let mut c = Command::new("sh");
        c.arg("-c").arg(command);
        c
    }
}

/// The first hop's connection through a command on this device.
pub struct ProxyCommand {
    command: String,
    user: String,
    /// The last run's stderr, for [`Dialer::failure`].
    stderr: Mutex<Option<Stderr>>,
}

impl ProxyCommand {
    /// `command` with `%h`, `%p` and `%r` for the hop it carries; `user` is that hop's user.
    pub fn new(command: impl Into<String>, user: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            user: user.into(),
            stderr: Mutex::new(None),
        }
    }

    async fn run(&self, host: &str, port: u16) -> io::Result<BoxedStream> {
        let command = expand(&self.command, host, port, &self.user)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut child = shell(&command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let (Some(stdin), Some(stdout), Some(mut err)) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take())
        else {
            return Err(io::Error::other("the command's stdio wasn't piped"));
        };
        let text = Arc::new(Mutex::new(Vec::new()));
        let kept = text.clone();
        let pump = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            while let Ok(n @ 1..) = err.read(&mut buf).await {
                crate::command_stream::keep(&kept, &buf[..n]);
            }
        });
        *self.stderr.lock().expect("not poisoned") = Some(Stderr::new(text, pump));
        Ok(Box::new(ChildStream {
            _child: child,
            stdin,
            stdout,
        }))
    }
}

impl Dialer for ProxyCommand {
    fn dial<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<BoxedStream>> + Send + 'a>> {
        Box::pin(self.run(host, port))
    }

    fn describe(&self) -> String {
        format!("the proxy command `{}`", self.command)
    }

    fn failure(&self) -> Pin<Box<dyn Future<Output = Option<String>> + Send + '_>> {
        let stderr = self.stderr.lock().expect("not poisoned").take();
        Box::pin(async move {
            let said = stderr?.text().await;
            (!said.is_empty()).then_some(said)
        })
    }
}

/// A child's stdout and stdin as one stream; the child is killed when it's dropped.
struct ChildStream {
    _child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

impl AsyncRead for ChildStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdout).poll_read(cx, buf)
    }
}

impl AsyncWrite for ChildStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stdin).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdin).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdin).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn tokens_expand() {
        assert_eq!(
            expand("nc %h %p", "db.internal", 2222, "ops").unwrap(),
            "nc db.internal 2222"
        );
        assert_eq!(
            expand("prod jump web-2 # %r 100%% %x %", "h", 22, "ops").unwrap(),
            "prod jump web-2 # ops 100% %x %"
        );
        assert_eq!(
            expand("nc %h %p", "[fe80::1]", 22, "ops").unwrap(),
            "nc [fe80::1] 22"
        );
    }

    #[test]
    fn a_host_or_user_that_isnt_a_word_is_refused() {
        assert!(expand("nc %h %p", "x; rm -rf ~", 22, "ops").is_err());
        assert!(expand("nc %h %p", "$(id)", 22, "ops").is_err());
        assert!(expand("ssh -l %r jump", "h", 22, "-oProxyCommand=x").is_err());
        assert!(expand("ssh -l %r jump", "h", 22, "a b").is_err());
        // Not used: not checked.
        assert_eq!(
            expand("aws ssm start-session", "x; y", 22, "a b").unwrap(),
            "aws ssm start-session"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn carries_bytes_both_ways() {
        let proxy = ProxyCommand::new("printf 'banner %h:%p\\n'; exec cat", "ops");
        let mut stream = proxy.dial("db.internal", 2222).await.unwrap();
        stream.write_all(b"echoed\n").await.unwrap();
        stream.flush().await.unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 64];
        while !String::from_utf8_lossy(&got).contains("echoed") {
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0, "ended early: {:?}", String::from_utf8_lossy(&got));
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(
            String::from_utf8_lossy(&got),
            "banner db.internal:2222\nechoed\n"
        );
        assert_eq!(proxy.failure().await, None);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn says_what_the_command_said() {
        let proxy = ProxyCommand::new(
            "echo 'SessionManagerPlugin is not found' >&2; exit 255",
            "ops",
        );
        let mut stream = proxy.dial("i-0abc", 22).await.unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(stream.read(&mut buf).await.unwrap(), 0);
        assert_eq!(
            proxy.failure().await.as_deref(),
            Some("SessionManagerPlugin is not found")
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn refuses_a_host_name_that_isnt_a_word() {
        let proxy = ProxyCommand::new("nc %h %p", "ops");
        let e = proxy.dial("x;touch /tmp/pwned", 22).await.err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    }
}
