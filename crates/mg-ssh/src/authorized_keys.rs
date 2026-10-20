//! `~/.ssh/authorized_keys` on a server: finding, adding and removing public keys (offboarding,
//! replacing a shared key), and replacing the file atomically over SFTP.
//!
//! Edits keep every other byte of the file as it was: other keys, options, comments, blank lines
//! and line endings.

use russh::keys::PublicKey;
/// A public key, compared by its key material (not its comment).
pub use russh::keys::ssh_key::public::KeyData;

use crate::sftp::Sftp;
use crate::{Error, Result};

/// The file, relative to where an SFTP session starts (the login's home directory).
pub const PATH: &str = ".ssh/authorized_keys";

/// The key on one `authorized_keys` line (options and comment aside), if it has one.
pub fn line_key(line: &str) -> Option<KeyData> {
    let line = line.trim_start();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    // Either `type base64 [comment]`, or `options type base64 [comment]`, where options may
    // contain quoted spaces.
    parse_key(line).or_else(|| parse_key(skip_options(line)?))
}

fn parse_key(s: &str) -> Option<KeyData> {
    let mut parts = s.split_ascii_whitespace();
    let (kind, body) = (parts.next()?, parts.next()?);
    PublicKey::from_openssh(&format!("{kind} {body}"))
        .ok()
        .map(|k| k.key_data().clone())
}

/// What follows the options field: it ends at the first whitespace outside double quotes.
fn skip_options(line: &str) -> Option<&str> {
    let mut quoted = false;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            c if c.is_ascii_whitespace() && !quoted => return Some(line[i..].trim_start()),
            _ => {}
        }
    }
    None
}

/// The key of an OpenSSH public key line (`type base64 [comment]`).
pub fn public_key(openssh: &str) -> Option<KeyData> {
    parse_key(openssh.trim())
}

/// The lines (0-based) that authorize any of `keys`.
pub fn find(contents: &str, keys: &[KeyData]) -> Vec<usize> {
    contents
        .lines()
        .enumerate()
        .filter(|(_, l)| line_key(l).is_some_and(|k| keys.contains(&k)))
        .map(|(i, _)| i)
        .collect()
}

/// `contents` without the lines that authorize any of `keys`, and how many were removed.
pub fn remove(contents: &str, keys: &[KeyData]) -> (String, usize) {
    let mut out = String::with_capacity(contents.len());
    let mut removed = 0;
    for line in contents.split_inclusive('\n') {
        if line_key(line.trim_end_matches(['\n', '\r'])).is_some_and(|k| keys.contains(&k)) {
            removed += 1;
        } else {
            out.push_str(line);
        }
    }
    (out, removed)
}

/// `contents` with `line` appended, unless its key is already there (then `None`).
pub fn add(contents: &str, line: &str) -> Option<String> {
    let key = public_key(line)?;
    if !find(contents, std::slice::from_ref(&key)).is_empty() {
        return None;
    }
    let mut out = contents.to_owned();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(line.trim());
    out.push('\n');
    Some(out)
}

/// The file's contents on the server (empty when there is none).
pub async fn read(sftp: &Sftp, path: &str) -> Result<String> {
    match sftp.read_file(path).await? {
        None => Ok(String::new()),
        Some(bytes) => {
            String::from_utf8(bytes).map_err(|_| Error::Sftp(format!("{path}: not a text file")))
        }
    }
}

/// Replaces the file atomically, keeping its permissions (`0600` for a new file, in a `0700`
/// directory created if needed: sshd refuses files others can write).
pub async fn write(sftp: &Sftp, path: &str, contents: &str) -> Result<()> {
    let mode = match sftp.stat(path).await {
        Ok(e) => e.mode.map_or(0o600, |m| m & 0o777),
        Err(_) => {
            if let Some((dir, _)) = path.rsplit_once('/')
                && !dir.is_empty()
                && !sftp.exists(dir).await?
            {
                sftp.mkdir(dir).await?;
                sftp.chmod(dir, 0o700).await?;
            }
            0o600
        }
    };
    sftp.replace_file(path, contents.as_bytes(), mode).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOV7rBdWTkUnX8JssaOJ30xGH0VcTQeQdLyitXAAZJnd alice@laptop";
    const BOB: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICzE0dEBoxASjK71bvsNSZNl2ebpWyECnWZm7fsbrIwX bob";

    fn key(line: &str) -> KeyData {
        public_key(line).unwrap()
    }

    #[test]
    fn finds_keys_behind_options_and_comments() {
        let body = BOB.split(' ').nth(1).unwrap();
        let file = format!(
            "# deploy keys\n\n{ALICE}\n\
             command=\"echo \\\"hi there\\\"\",no-pty ssh-ed25519 {body} bob@work\n\
             from=\"10.0.0.0/8\" {BOB}\n\
             garbage line\n"
        );
        assert_eq!(find(&file, &[key(BOB)]), [3, 4]);
        assert_eq!(find(&file, &[key(ALICE)]), [2]);
        assert_eq!(find(&file, &[key(ALICE), key(BOB)]), [2, 3, 4]);
        // The comment doesn't matter, only the key.
        let other_comment = BOB.replace(" bob", " someone-else");
        assert_eq!(find(&file, &[key(&other_comment)]), [3, 4]);
    }

    #[test]
    fn removes_only_those_lines_and_keeps_every_other_byte() {
        let file = format!("# keys\r\n{ALICE}\r\n{BOB}\r\n\nfrom=\"*\" {BOB}");
        let (out, removed) = remove(&file, &[key(BOB)]);
        assert_eq!(removed, 2);
        assert_eq!(out, format!("# keys\r\n{ALICE}\r\n\n"));
        let (same, none) = remove(&out, &[key(BOB)]);
        assert_eq!((same.as_str(), none), (out.as_str(), 0));
    }

    #[test]
    fn adds_a_key_once() {
        let out = add(ALICE, BOB).unwrap();
        assert_eq!(out, format!("{ALICE}\n{BOB}\n"));
        assert_eq!(add(&out, BOB), None);
        assert_eq!(add("", ALICE).unwrap(), format!("{ALICE}\n"));
        assert_eq!(add("", "not a key"), None);
    }
}
