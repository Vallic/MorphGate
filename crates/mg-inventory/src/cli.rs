//! A cloud provider's CLI (`aws`, `gcloud`, `az`), run as the person has set it up: its sign-in
//! (SSO, MFA, profiles) is theirs, and MorphGate keeps no cloud credentials. What it prints on
//! stdout is JSON; what it says on stderr when it fails (an expired session: run `aws sso login`)
//! is the error, as it said it.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::de::DeserializeOwned;
use tokio::process::Command;

use crate::{Error, Result};

/// A listing across every AWS region takes a while.
const TIMEOUT: Duration = Duration::from_secs(60);

/// One of the CLIs, found on this device.
#[derive(Clone, Debug)]
pub struct Cli {
    program: PathBuf,
    timeout: Duration,
}

/// Where the installers put each CLI besides `PATH`: an app started from a menu or Finder doesn't
/// get the shell's `PATH`.
fn places(name: &str) -> Vec<PathBuf> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from);
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(home) = &home {
        dirs.push(home.join(".local/bin"));
        dirs.push(home.join("google-cloud-sdk/bin"));
        dirs.push(home.join("bin"));
    }
    for d in [
        "/usr/local/bin",
        "/opt/homebrew/bin",
        "/usr/bin",
        "/snap/bin",
        "/opt/google-cloud-sdk/bin",
        "/usr/lib/google-cloud-sdk/bin",
    ] {
        dirs.push(PathBuf::from(d));
    }
    if cfg!(windows) {
        for var in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
            if let Some(base) = std::env::var_os(var).map(PathBuf::from) {
                dirs.push(base.join("Amazon/AWSCLIV2"));
                dirs.push(base.join("Google/Cloud SDK/google-cloud-sdk/bin"));
                dirs.push(base.join("Microsoft SDKs/Azure/CLI2/wbin"));
            }
        }
    }
    let files: &[String] = &if cfg!(windows) {
        vec![format!("{name}.exe"), format!("{name}.cmd")]
    } else {
        vec![name.to_owned()]
    };
    // A test's stand-ins first, then PATH, then the installers' places.
    let mut out = Vec::new();
    let path = std::env::var_os("PATH").unwrap_or_default();
    let search = std::env::var_os("MORPHGATE_CLOUD_CLI_DIR")
        .map(PathBuf::from)
        .into_iter()
        .chain(std::env::split_paths(&path))
        .chain(dirs);
    for dir in search {
        for f in files {
            out.push(dir.join(f));
        }
    }
    out
}

fn runnable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

impl Cli {
    /// `name` (`aws`, `gcloud`, `az`) at `configured` where the source names a path, else
    /// wherever it's found.
    pub fn find(name: &str, configured: Option<&Path>) -> Result<Self> {
        let program = match configured {
            Some(p) if runnable(p) => p.to_owned(),
            Some(p) => {
                return Err(Error::Cli(format!(
                    "{}: not a program that can be run",
                    p.display()
                )));
            }
            None => places(name)
                .into_iter()
                .find(|p| runnable(p))
                .ok_or_else(|| Error::NotInstalled(name.to_owned()))?,
        };
        Ok(Self {
            program,
            timeout: TIMEOUT,
        })
    }

    pub fn program(&self) -> &Path {
        &self.program
    }

    /// Runs it with `args` and reads what it prints as JSON.
    pub async fn json<T: DeserializeOwned>(&self, args: &[&str]) -> Result<T> {
        let out = self.output(args).await?;
        serde_json::from_slice(&out).map_err(|e| {
            Error::Cli(format!(
                "`{} {}` printed something this version can't read: {e}",
                self.name(),
                args.join(" ")
            ))
        })
    }

    /// Runs it with `args` and returns what it prints.
    pub async fn text(&self, args: &[&str]) -> Result<String> {
        Ok(String::from_utf8_lossy(&self.output(args).await?).into_owned())
    }

    fn name(&self) -> String {
        self.program
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    async fn output(&self, args: &[&str]) -> Result<Vec<u8>> {
        let name = self.name();
        let mut command = Command::new(&self.program);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        // No prompts, no colors, no pager: a program reads this.
        command
            .env("AWS_PAGER", "")
            .env("CLOUDSDK_CORE_DISABLE_PROMPTS", "1")
            .env("AZURE_CORE_ONLY_SHOW_ERRORS", "1")
            .env("AZURE_CORE_NO_COLOR", "1");
        #[cfg(windows)]
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        let output = tokio::time::timeout(self.timeout, command.output())
            .await
            .map_err(|_| {
                Error::Cli(format!(
                    "`{name} {}` took longer than {} s",
                    args.join(" "),
                    self.timeout.as_secs()
                ))
            })?
            .map_err(|e| Error::Cli(format!("{}: {e}", self.program.display())))?;
        if !output.status.success() {
            let said = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            return Err(Error::Cli(if said.is_empty() {
                format!("`{name} {}` failed ({})", args.join(" "), output.status)
            } else {
                said
            }));
        }
        Ok(output.stdout)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[tokio::test]
    async fn reads_json_and_passes_on_what_it_says() {
        let dir = tempfile::tempdir().unwrap();
        let ok = Cli::find(
            "aws",
            Some(&script(dir.path(), "aws", r#"echo '{"Account": "123"}'"#)),
        )
        .unwrap();
        let v: serde_json::Value = ok.json(&["sts", "get-caller-identity"]).await.unwrap();
        assert_eq!(v["Account"], "123");

        let expired = Cli::find(
            "aws",
            Some(&script(
                dir.path(),
                "aws-expired",
                "echo 'The SSO session associated with this profile has expired. To refresh this SSO session run aws sso login with the corresponding profile.' >&2; exit 255",
            )),
        )
        .unwrap();
        let e = expired
            .json::<serde_json::Value>(&["ec2", "describe-instances"])
            .await
            .unwrap_err()
            .to_string();
        assert!(e.starts_with("The SSO session"), "{e}");
    }

    #[test]
    fn a_missing_cli_says_which() {
        let e = Cli::find("no-such-cloud-cli", None).unwrap_err();
        assert!(matches!(e, Error::NotInstalled(ref n) if n == "no-such-cloud-cli"));
    }
}
