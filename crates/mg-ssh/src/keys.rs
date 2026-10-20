//! Private key import and generation for the vault's `ssh_key` items.

use russh::keys::ssh_key::LineEnding;
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::{HashAlg, PrivateKey, PublicKey};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Public facts about a private key, safe to show in the UI.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct KeyInfo {
    pub algorithm: String,
    /// `SHA256:…`
    pub fingerprint: String,
    /// OpenSSH `authorized_keys` line.
    pub public_key: String,
    /// Whether the stored PEM itself is passphrase-protected.
    pub encrypted: bool,
}

/// Parses an OpenSSH/PEM private key or a PuTTY key (`.ppk`), checking the passphrase if the
/// key is encrypted.
pub fn inspect(private_key: &str, passphrase: Option<&str>) -> Result<KeyInfo> {
    let key = decode(private_key, passphrase)?;
    let encrypted = russh::keys::decode_secret_key(private_key, None).is_err();
    info(&key, encrypted)
}

/// New Ed25519 key, returned as an unencrypted OpenSSH PEM (the vault encrypts it at rest).
pub fn generate_ed25519(comment: &str) -> Result<(Zeroizing<String>, KeyInfo)> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut())
        .map_err(|e| Error::Key(format!("random number generator: {e}")))?;
    let mut key = PrivateKey::from(Ed25519Keypair::from_seed(&seed));
    key.set_comment(comment);
    let pem = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| Error::Key(e.to_string()))?;
    let info = info(&key, false)?;
    Ok((pem, info))
}

/// What an OpenSSH user certificate says, for the UI.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertInfo {
    /// The certificate as one line (`…-cert-v01@openssh.com AAAA… [comment]`).
    pub certificate: String,
    /// Who issued it for what (step-ca and Vault put the user or a request id here).
    pub key_id: String,
    /// The users it signs in as; empty: any the server allows.
    pub principals: Vec<String>,
    /// Unix seconds. `valid_before` is `u64::MAX` for a certificate that never expires.
    pub valid_after: u64,
    pub valid_before: u64,
    /// The CA that signed it (`SHA256:…`).
    pub ca: String,
}

/// Reads an OpenSSH user certificate (the line of a `…-cert.pub` file), and checks that it
/// certifies `public_key` (an `authorized_keys` line).
pub fn certificate(text: &str, public_key: &str) -> Result<CertInfo> {
    use russh::keys::ssh_key::certificate::CertType;
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .ok_or_else(|| Error::Key("no certificate".into()))?;
    let cert = russh::keys::Certificate::from_openssh(line)
        .map_err(|e| Error::Key(format!("not an OpenSSH certificate: {e}")))?;
    if cert.cert_type() != CertType::User {
        return Err(Error::Key(
            "a host certificate, not one for signing in".into(),
        ));
    }
    let key = PublicKey::from_openssh(public_key.trim())
        .map_err(|e| Error::Key(format!("public key: {e}")))?;
    if cert.public_key() != key.key_data() {
        let other = PublicKey::new(cert.public_key().clone(), "").fingerprint(HashAlg::Sha256);
        return Err(Error::Key(format!(
            "the certificate is for another key ({other})"
        )));
    }
    Ok(CertInfo {
        certificate: line.to_owned(),
        key_id: cert.key_id().to_owned(),
        principals: cert.valid_principals().to_vec(),
        valid_after: cert.valid_after(),
        valid_before: cert.valid_before(),
        ca: PublicKey::new(cert.signature_key().clone(), "")
            .fingerprint(HashAlg::Sha256)
            .to_string(),
    })
}

/// A key ready for the vault: OpenSSH's format as given, or a PuTTY key converted to OpenSSH's,
/// unencrypted (the vault encrypts it at rest, as it does generated keys). `info.encrypted` says
/// whether the returned PEM still needs the passphrase.
pub fn for_vault(
    private_key: &str,
    passphrase: Option<&str>,
) -> Result<(Zeroizing<String>, KeyInfo)> {
    if !is_ppk(private_key) {
        let info = inspect(private_key, passphrase)?;
        return Ok((Zeroizing::new(format!("{}\n", private_key.trim())), info));
    }
    let key = decode(private_key, passphrase)?;
    let pem = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| Error::Key(e.to_string()))?;
    let info = info(&key, false)?;
    Ok((pem, info))
}

/// A PuTTY key file (`PuTTY-User-Key-File-2` or `-3`).
pub fn is_ppk(text: &str) -> bool {
    text.trim_start().starts_with("PuTTY-User-Key-File-")
}

/// The public half of a PuTTY key (an `authorized_keys` line), readable without its passphrase.
pub fn ppk_public_key(text: &str) -> Option<String> {
    let mut lines = text.lines().map(str::trim);
    let algorithm = lines
        .next()?
        .strip_prefix("PuTTY-User-Key-File-")?
        .split_once(':')?
        .1
        .trim()
        .to_owned();
    let count: usize = lines
        .by_ref()
        .find_map(|l| l.strip_prefix("Public-Lines:"))?
        .trim()
        .parse()
        .ok()?;
    let blob: String = lines.take(count).collect();
    let key = russh::keys::PublicKey::from_openssh(&format!("{algorithm} {blob}")).ok()?;
    key.to_openssh().ok()
}

fn ppk_encrypted(text: &str) -> bool {
    text.lines()
        .find_map(|l| l.trim().strip_prefix("Encryption:"))
        .is_some_and(|e| e.trim() != "none")
}

pub(crate) fn decode(private_key: &str, passphrase: Option<&str>) -> Result<PrivateKey> {
    // russh reads PuTTY keys too, but says only "encrypted" for one with no passphrase.
    if passphrase.is_none() && is_ppk(private_key) && ppk_encrypted(private_key) {
        return Err(Error::KeyNeedsPassphrase);
    }
    russh::keys::decode_secret_key(private_key.trim(), passphrase).map_err(|e| match e {
        russh::keys::Error::KeyIsEncrypted => Error::KeyNeedsPassphrase,
        other if passphrase.is_some() => Error::Key(format!("{other} (wrong passphrase?)")),
        other => Error::Key(other.to_string()),
    })
}

/// `SHA256:…` of an OpenSSH public key line (`type base64 [comment]`).
pub fn public_fingerprint(public_key: &str) -> Option<String> {
    russh::keys::PublicKey::from_openssh(public_key.trim())
        .ok()
        .map(|k| k.fingerprint(HashAlg::Sha256).to_string())
}

fn info(key: &PrivateKey, encrypted: bool) -> Result<KeyInfo> {
    let public = key.public_key();
    Ok(KeyInfo {
        algorithm: public.algorithm().to_string(),
        fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
        public_key: public.to_openssh().map_err(|e| Error::Key(e.to_string()))?,
        encrypted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_fingerprint_matches_the_private_key() {
        let (_, info) = generate_ed25519("me@laptop").unwrap();
        assert_eq!(
            public_fingerprint(&info.public_key),
            Some(info.fingerprint.clone())
        );
        let without_comment: Vec<&str> = info.public_key.split(' ').take(2).collect();
        assert_eq!(
            public_fingerprint(&without_comment.join(" ")),
            Some(info.fingerprint)
        );
        assert_eq!(public_fingerprint("ssh-ed25519 notbase64"), None);
    }

    #[test]
    fn generated_key_roundtrips() {
        let (pem, info) = generate_ed25519("me@laptop").unwrap();
        assert!(pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")); // gitleaks:allow
        assert_eq!(info.algorithm, "ssh-ed25519");
        assert!(
            info.public_key.starts_with("ssh-ed25519 ") && info.public_key.ends_with(" me@laptop")
        );
        assert_eq!(inspect(&pem, None).unwrap(), info);
    }

    #[test]
    fn two_generated_keys_differ() {
        assert_ne!(
            generate_ed25519("").unwrap().1.fingerprint,
            generate_ed25519("").unwrap().1.fingerprint
        );
    }

    /// `ssh-keygen -t ed25519 -N hunter22 -C fixture` (throwaway, never used anywhere).
    const ENCRYPTED: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBjOKUZlm
sZtjd/eiG6xCBvAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIO1NMI5Rr29No9OA
wNEteW/usTvc9N+Eg4qFFyd6nlCSAAAAkPK74vNcaUteskWwvjsUoJCfPVbm4rukIt+mn3
P7QZcmZBS2p7GVdsVm5nSTdbfAWwvtuYENKzr8O0kiIGaLedFb5FPKDVwkVg55ncPtd7Id
lVCTfqCq4QOh95+NIm8AR6VO4PxmNcf3KLcdd2MM6JoMpoCE6wk2X+ZAKzoJJCycrQ0AmY
ziMdWzgrltVmkydA==
-----END OPENSSH PRIVATE KEY-----
";

    #[test]
    fn encrypted_key_needs_the_right_passphrase() {
        assert!(matches!(
            inspect(ENCRYPTED, None),
            Err(Error::KeyNeedsPassphrase)
        ));
        assert!(matches!(
            inspect(ENCRYPTED, Some("wrong")),
            Err(Error::Key(_))
        ));
        let info = inspect(ENCRYPTED, Some("hunter22")).unwrap();
        assert!(info.encrypted);
        assert_eq!(
            info.fingerprint,
            "SHA256:PkKA84G2fD8LhVMFhyaa7dUkFI0qdnpQyXj55aE///g"
        );
    }

    const PPK: &str = include_str!("../tests/data/id_ed25519.ppk");
    const PPK_ENCRYPTED: &str = include_str!("../tests/data/id_ed25519_enc.ppk");
    const PPK2_ENCRYPTED: &str = include_str!("../tests/data/id_rsa_3072_enc.ppk2");

    #[test]
    fn putty_keys_become_openssh_keys() {
        let (pem, info) = for_vault(PPK, None).unwrap();
        assert!(pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(!info.encrypted);
        assert_eq!(inspect(&pem, None).unwrap().fingerprint, info.fingerprint);
        assert_eq!(
            public_fingerprint(&ppk_public_key(PPK).unwrap()),
            Some(info.fingerprint.clone())
        );

        // Encrypted (version 3, Argon2): the public half without the passphrase, the key with it.
        assert!(matches!(
            inspect(PPK_ENCRYPTED, None),
            Err(Error::KeyNeedsPassphrase)
        ));
        assert!(matches!(
            for_vault(PPK_ENCRYPTED, Some("wrong")),
            Err(Error::Key(_))
        ));
        let (pem, info) = for_vault(PPK_ENCRYPTED, Some("123")).unwrap();
        assert!(!info.encrypted, "stored unencrypted");
        assert_eq!(inspect(&pem, None).unwrap().fingerprint, info.fingerprint);
        assert_eq!(
            public_fingerprint(&ppk_public_key(PPK_ENCRYPTED).unwrap()),
            Some(info.fingerprint)
        );

        // Version 2, RSA.
        let (_, info) = for_vault(PPK2_ENCRYPTED, Some("123")).unwrap();
        assert_eq!(info.algorithm, "ssh-rsa");
        assert_eq!(
            public_fingerprint(&ppk_public_key(PPK2_ENCRYPTED).unwrap()),
            Some(info.fingerprint)
        );
    }

    #[test]
    fn openssh_keys_stay_as_they_are() {
        let (pem, info) = for_vault(ENCRYPTED, Some("hunter22")).unwrap();
        assert_eq!(pem.as_str(), ENCRYPTED);
        assert!(info.encrypted);
    }

    const USER: &str = include_str!("../tests/data/user.pub");
    const USER_CERT: &str = include_str!("../tests/data/user-cert.pub");
    const OTHER: &str = include_str!("../tests/data/other.pub");
    const HOST_CERT: &str = include_str!("../tests/data/host-cert.pub");
    const CA: &str = include_str!("../tests/data/user-ca.pub");

    #[test]
    fn user_certificates_are_read() {
        let info = certificate(&format!("\n# from step\n{USER_CERT}"), USER).unwrap();
        assert_eq!(info.key_id, "alice@example");
        assert_eq!(info.principals, ["deploy", "ops"]);
        assert_eq!((info.valid_after, info.valid_before), (0, u64::MAX));
        assert_eq!(Some(info.ca), public_fingerprint(CA));
        assert_eq!(info.certificate, USER_CERT.trim());
    }

    #[test]
    fn certificates_for_another_key_or_a_host_are_refused() {
        let other = certificate(USER_CERT, OTHER).unwrap_err().to_string();
        assert!(other.contains("another key"), "{other}");
        let host = certificate(HOST_CERT, OTHER).unwrap_err().to_string();
        assert!(host.contains("host certificate"), "{host}");
        assert!(
            certificate(USER, USER).is_err(),
            "a public key is no certificate"
        );
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(matches!(inspect("not a key", None), Err(Error::Key(_))));
    }
}
