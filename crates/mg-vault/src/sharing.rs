//! Sharing vaults between accounts of an organization.
//!
//! * **Fingerprint**: what people compare out of band before trusting an account's keys.
//! * **Certificates**: an owner or admin signs an account's public keys into the organization.
//!   They bind keys to an account and grant nothing; access stays on the server.
//! * **Grant signatures**: whoever seals a vault key to a member signs the sealed key, so a server
//!   can't hand a member a vault key of its own making (and then read what they write).
//!
//! Every signed message is `morphgate/v1/<kind> ‖ fields`, strings as `u16 len ‖ UTF-8`.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{AccountKeys, Error, PublicKeys, Result};

const FINGERPRINT_DOMAIN: &[u8] = b"morphgate/v1/fingerprint";
const GRANT_DOMAIN: &[u8] = b"morphgate/v1/vault-key-grant";
const MEMBER_KEY_DOMAIN: &[u8] = b"morphgate/v1/member-key";
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Bytes of SHA-256 kept for a fingerprint: 160 bits, 32 base32 symbols.
pub const FINGERPRINT_LEN: usize = 20;

/// What a certificate vouches for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertKind {
    /// An admin or owner confirmed this account as a member (its encryption and signing keys).
    Member,
    /// An owner made this account an admin (its signing key may certify members).
    Admin,
    /// The outgoing owner handed the organization to this account.
    Owner,
}

impl CertKind {
    fn domain(self) -> &'static [u8] {
        match self {
            CertKind::Member => b"morphgate/v1/member-cert",
            CertKind::Admin => b"morphgate/v1/admin-cert",
            CertKind::Owner => b"morphgate/v1/owner-cert",
        }
    }
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&u16::try_from(s.len()).unwrap_or(u16::MAX).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// The raw fingerprint of an account's keys.
pub fn fingerprint_bytes(account_id: &str, keys: &PublicKeys) -> [u8; FINGERPRINT_LEN] {
    let mut msg = Vec::with_capacity(FINGERPRINT_DOMAIN.len() + 2 + account_id.len() + 64);
    msg.extend_from_slice(FINGERPRINT_DOMAIN);
    put_str(&mut msg, account_id);
    msg.extend_from_slice(&keys.enc);
    msg.extend_from_slice(&keys.sign);
    let digest = Sha256::digest(&msg);
    digest[..FINGERPRINT_LEN].try_into().expect("fixed length")
}

/// `XXXX-XXXX-…` (8 groups of 4 Crockford base32 symbols), as people compare it.
pub fn fingerprint(account_id: &str, keys: &PublicKeys) -> String {
    let raw = fingerprint_bytes(account_id, keys);
    let mut out = String::with_capacity(39);
    let (mut acc, mut bits, mut n) = (0u32, 0u32, 0usize);
    for byte in raw {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            if n > 0 && n % 4 == 0 {
                out.push('-');
            }
            out.push(char::from(ALPHABET[((acc >> bits) & 31) as usize]));
            n += 1;
        }
    }
    out
}

/// The message a certificate signs.
pub fn cert_message(kind: CertKind, org_id: &str, account_id: &str, keys: &PublicKeys) -> Vec<u8> {
    let mut msg = Vec::with_capacity(32 + org_id.len() + account_id.len() + 64);
    msg.extend_from_slice(kind.domain());
    put_str(&mut msg, org_id);
    put_str(&mut msg, account_id);
    if kind != CertKind::Admin {
        msg.extend_from_slice(&keys.enc);
    }
    msg.extend_from_slice(&keys.sign);
    msg
}

/// Signs a certificate for `account_id`'s `keys` with the signer's account key.
pub fn certify(
    signer: &AccountKeys,
    kind: CertKind,
    org_id: &str,
    account_id: &str,
    keys: &PublicKeys,
) -> [u8; 64] {
    signer.sign(&cert_message(kind, org_id, account_id, keys))
}

/// Checks a certificate against the signer's Ed25519 public key.
pub fn verify_cert(
    signer_sign_pub: &[u8; 32],
    kind: CertKind,
    org_id: &str,
    account_id: &str,
    keys: &PublicKeys,
    sig: &[u8],
) -> Result<()> {
    verify(
        signer_sign_pub,
        &cert_message(kind, org_id, account_id, keys),
        sig,
    )
}

/// The message a grant signature signs: one sealed vault key, for one member, in one vault.
pub fn grant_message(
    vault_id: &str,
    key_id: &[u8; 16],
    recipient_id: &str,
    wrapped_vault_key: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(GRANT_DOMAIN.len() + 4 + vault_id.len() + 16 + 64);
    msg.extend_from_slice(GRANT_DOMAIN);
    put_str(&mut msg, vault_id);
    msg.extend_from_slice(key_id);
    put_str(&mut msg, recipient_id);
    msg.extend_from_slice(&Sha256::digest(wrapped_vault_key));
    msg
}

/// Signs a sealed vault key the signer is handing to `recipient_id`.
pub fn sign_grant(
    signer: &AccountKeys,
    vault_id: &str,
    key_id: &[u8; 16],
    recipient_id: &str,
    wrapped_vault_key: &[u8],
) -> [u8; 64] {
    signer.sign(&grant_message(
        vault_id,
        key_id,
        recipient_id,
        wrapped_vault_key,
    ))
}

pub fn verify_grant(
    signer_sign_pub: &[u8; 32],
    vault_id: &str,
    key_id: &[u8; 16],
    recipient_id: &str,
    wrapped_vault_key: &[u8],
    sig: &[u8],
) -> Result<()> {
    verify(
        signer_sign_pub,
        &grant_message(vault_id, key_id, recipient_id, wrapped_vault_key),
        sig,
    )
}

/// A member's SSH public key published to an organization's directory vault. `public_key` is the
/// OpenSSH `type base64` form, without a comment.
pub fn member_key_message(org_id: &str, account_id: &str, public_key: &str) -> Vec<u8> {
    let mut msg = Vec::with_capacity(MEMBER_KEY_DOMAIN.len() + 6 + org_id.len() + 96);
    msg.extend_from_slice(MEMBER_KEY_DOMAIN);
    put_str(&mut msg, org_id);
    put_str(&mut msg, account_id);
    put_str(&mut msg, public_key);
    msg
}

/// Signs a public key the member publishes (only the member's own key makes this valid).
pub fn sign_member_key(
    member: &AccountKeys,
    org_id: &str,
    account_id: &str,
    public_key: &str,
) -> [u8; 64] {
    member.sign(&member_key_message(org_id, account_id, public_key))
}

pub fn verify_member_key(
    member_sign_pub: &[u8; 32],
    org_id: &str,
    account_id: &str,
    public_key: &str,
    sig: &[u8],
) -> Result<()> {
    verify(
        member_sign_pub,
        &member_key_message(org_id, account_id, public_key),
        sig,
    )
}

fn verify(signer_sign_pub: &[u8; 32], msg: &[u8], sig: &[u8]) -> Result<()> {
    let key = VerifyingKey::from_bytes(signer_sign_pub).map_err(|_| Error::Signature)?;
    let sig: [u8; 64] = sig.try_into().map_err(|_| Error::Signature)?;
    key.verify_strict(msg, &Signature::from_bytes(&sig))
        .map_err(|_| Error::Signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORG: &str = "01JORG00000000000000000000";
    const ACCOUNT: &str = "01JACCOUNT0000000000000000";

    fn fixed(enc: u8, sign: u8) -> AccountKeys {
        AccountKeys::from_secrets(&[enc; 32], &[sign; 32])
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Pins the wire formats: other implementations must produce these exact values.
    #[test]
    fn vectors() {
        let alice = fixed(1, 2);
        let bob = fixed(3, 4);
        let bob_pub = bob.public();
        assert_eq!(fingerprint(ACCOUNT, &bob_pub), FINGERPRINT_VECTOR);
        assert_eq!(
            hex(&certify(&alice, CertKind::Member, ORG, ACCOUNT, &bob_pub)),
            MEMBER_CERT_VECTOR
        );
        assert_eq!(
            hex(&sign_grant(&alice, ORG, &[7; 16], ACCOUNT, b"sealed")),
            GRANT_VECTOR
        );
        assert_eq!(
            hex(&sign_member_key(&alice, ORG, ACCOUNT, SSH_KEY)),
            MEMBER_KEY_VECTOR
        );
    }

    const SSH_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOV7rBdWTkUnX8JssaOJ30xGH0VcTQeQdLyitXAAZJnd";

    #[test]
    fn member_keys_bind_org_account_and_key() {
        let bob = fixed(3, 4);
        let sig = sign_member_key(&bob, ORG, ACCOUNT, SSH_KEY);
        let pk = bob.public().sign;
        verify_member_key(&pk, ORG, ACCOUNT, SSH_KEY, &sig).unwrap();
        let bad = |r: Result<()>| assert_eq!(r, Err(Error::Signature));
        bad(verify_member_key(
            &pk,
            "01JOTHERORG000000000000000",
            ACCOUNT,
            SSH_KEY,
            &sig,
        ));
        bad(verify_member_key(
            &pk,
            ORG,
            "01JOTHER000000000000000000",
            SSH_KEY,
            &sig,
        ));
        bad(verify_member_key(
            &pk,
            ORG,
            ACCOUNT,
            &SSH_KEY.replace("ZJnd", "ZJne"),
            &sig,
        ));
        // Signed by someone else (an admin publishing "for" Bob): not Bob's.
        let forged = sign_member_key(&fixed(1, 2), ORG, ACCOUNT, SSH_KEY);
        bad(verify_member_key(&pk, ORG, ACCOUNT, SSH_KEY, &forged));
    }

    // Computed independently (Python `cryptography`), not by this crate.
    const FINGERPRINT_VECTOR: &str = "AENQ-X0TQ-WSTC-VJM8-KH6P-HKF2-8B7J-EQS5";
    const MEMBER_CERT_VECTOR: &str = "c2587760f532690ea8d43860855121ff517b547cbb8feaf15532e6bb9a0faf9f554e90c018c00e4b5e53390d2fa0663699b835eb278fc052efdb7e883f77b40e";
    const MEMBER_KEY_VECTOR: &str = "451454a81a6bec679ae9c3f1d52dc5e38e48867bbaa9de768115ccfb193a9b5917566383821f65cd6f25d879e4462662ecad23b75fcc4c50bda261d43bd73409";
    const GRANT_VECTOR: &str = "7b863d3e2ad0c305bc0eb99c9557d401b75c7b3713906daace280bc58d99a5d430fe745504372c1465341c7cddf383f86ea1fdfe744c31a1881c5d56e9e70701";

    #[test]
    fn fingerprint_shape_and_binding() {
        let keys = fixed(3, 4).public();
        let fp = fingerprint(ACCOUNT, &keys);
        assert_eq!(fp.len(), 39);
        assert_eq!(fp.split('-').count(), 8);
        assert!(fp.split('-').all(|g| g.len() == 4));
        // Bound to the account id and to both keys.
        assert_ne!(fp, fingerprint("01JOTHER000000000000000000", &keys));
        assert_ne!(fp, fingerprint(ACCOUNT, &fixed(3, 5).public()));
        assert_ne!(fp, fingerprint(ACCOUNT, &fixed(9, 4).public()));
    }

    #[test]
    fn certificates_bind_kind_org_account_and_keys() {
        let owner = fixed(1, 2);
        let bob = fixed(3, 4).public();
        let sig = certify(&owner, CertKind::Member, ORG, ACCOUNT, &bob);
        let signer = owner.public().sign;
        verify_cert(&signer, CertKind::Member, ORG, ACCOUNT, &bob, &sig).unwrap();

        let bad = |r: Result<()>| assert_eq!(r, Err(Error::Signature));
        bad(verify_cert(
            &signer,
            CertKind::Admin,
            ORG,
            ACCOUNT,
            &bob,
            &sig,
        ));
        bad(verify_cert(
            &signer,
            CertKind::Owner,
            ORG,
            ACCOUNT,
            &bob,
            &sig,
        ));
        bad(verify_cert(
            &signer,
            CertKind::Member,
            "01JOTHERORG000000000000000",
            ACCOUNT,
            &bob,
            &sig,
        ));
        bad(verify_cert(
            &signer,
            CertKind::Member,
            ORG,
            "01JX",
            &bob,
            &sig,
        ));
        bad(verify_cert(
            &signer,
            CertKind::Member,
            ORG,
            ACCOUNT,
            &fixed(3, 5).public(),
            &sig,
        ));
        bad(verify_cert(
            &bob.sign,
            CertKind::Member,
            ORG,
            ACCOUNT,
            &bob,
            &sig,
        ));
        bad(verify_cert(
            &signer,
            CertKind::Member,
            ORG,
            ACCOUNT,
            &bob,
            &sig[..63],
        ));

        // An admin certificate covers only the signing key.
        let admin = certify(&owner, CertKind::Admin, ORG, ACCOUNT, &bob);
        let other_enc = PublicKeys {
            enc: [9; 32],
            sign: bob.sign,
        };
        verify_cert(&signer, CertKind::Admin, ORG, ACCOUNT, &other_enc, &admin).unwrap();
    }

    #[test]
    fn grants_bind_vault_key_recipient_and_sealed_bytes() {
        let admin = fixed(1, 2);
        let signer = admin.public().sign;
        let sig = sign_grant(&admin, ORG, &[7; 16], ACCOUNT, b"sealed");
        verify_grant(&signer, ORG, &[7; 16], ACCOUNT, b"sealed", &sig).unwrap();
        for r in [
            verify_grant(&signer, "01JV2", &[7; 16], ACCOUNT, b"sealed", &sig),
            verify_grant(&signer, ORG, &[8; 16], ACCOUNT, b"sealed", &sig),
            verify_grant(&signer, ORG, &[7; 16], "01JMALLORY", b"sealed", &sig),
            verify_grant(&signer, ORG, &[7; 16], ACCOUNT, b"sealeD", &sig),
        ] {
            assert_eq!(r, Err(Error::Signature));
        }
    }
}
