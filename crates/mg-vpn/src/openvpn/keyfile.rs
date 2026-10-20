//! Client keys that need a passphrase: PKCS#8 `ENCRYPTED PRIVATE KEY`s, OpenSSL's older
//! `Proc-Type: 4,ENCRYPTED` PEM keys, and PKCS#12 bundles (`pkcs12`), which bring the client
//! certificate and usually the CA along.
//!
//! Decryption is CPU work (key derivation); callers run it off the async runtime.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockCipherDecrypt, BlockModeDecrypt, KeyInit, KeyIvInit};
use md5::{Digest, Md5};
use p12_keystore::Pkcs12Archive;
use p12_keystore::error::Error as P12Error;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use zeroize::Zeroizing;

use super::tls::tlv;

/// Why a key couldn't be opened.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyError {
    /// The passphrase is wrong (or the file is damaged in a way that looks the same).
    WrongPassphrase,
    /// Not something MorphGate can read; the message says why and what to do.
    Unusable(String),
}

/// The certificate and key a PKCS#12 bundle holds.
pub struct Bundle {
    /// The client certificate first, then intermediates from the bundle.
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    /// The bundle's other certificates (CA and intermediates): trusted when the profile has no
    /// `<ca>`, as OpenVPN does.
    pub authorities: Vec<CertificateDer<'static>>,
}

/// One PEM block.
struct Pem {
    label: String,
    headers: Vec<(String, String)>,
    der: Zeroizing<Vec<u8>>,
}

/// The first `… PRIVATE KEY` block of `text`, with its RFC 1421 headers.
fn private_key_pem(text: &str) -> Option<Pem> {
    let mut lines = text.lines().map(str::trim);
    let label = lines.find_map(|l| {
        l.strip_prefix("-----BEGIN ")
            .and_then(|l| l.strip_suffix("-----"))
            .filter(|l| l.ends_with("PRIVATE KEY"))
    })?;
    let end = format!("-----END {label}-----");
    let mut headers = Vec::new();
    let mut body = String::new();
    for line in lines.by_ref() {
        if line == end {
            let der = Zeroizing::new(STANDARD.decode(body.as_bytes()).ok()?);
            return Some(Pem {
                label: label.to_owned(),
                headers,
                der,
            });
        }
        match line.split_once(": ") {
            Some((k, v)) if body.is_empty() && !k.contains(' ') => {
                headers.push((k.to_owned(), v.to_owned()))
            }
            _ => body.push_str(line),
        }
    }
    None
}

fn header<'a>(pem: &'a Pem, name: &str) -> Option<&'a str> {
    pem.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Whether a `<key>` needs a passphrase.
pub fn is_encrypted(pem: &str) -> bool {
    pem.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") || pem.contains("Proc-Type: 4,ENCRYPTED")
}

const RE_ENCRYPT: &str = "re-encrypt it with `openssl pkcs8 -topk8 -v2 aes-256-cbc -in key.pem \
                          -out key-new.pem`";

/// Import-time check of an encrypted `<key>`: readable, and protected in a way MorphGate can
/// undo once it has the passphrase.
pub fn check_encrypted(pem: &str) -> Result<(), String> {
    let p = private_key_pem(pem).ok_or("the client key is not a readable PEM private key")?;
    if p.label == "ENCRYPTED PRIVATE KEY" {
        // Parsing knows the algorithms: an unknown cipher or key derivation fails here.
        let info = pkcs8::EncryptedPrivateKeyInfoRef::try_from(p.der.as_slice()).map_err(|e| {
            format!(
                "the client key's encryption can't be read or isn't supported ({e}); {RE_ENCRYPT}"
            )
        })?;
        return match info.encryption_algorithm {
            pkcs8::pkcs5::EncryptionScheme::Pbes2(_) => Ok(()),
            _ => Err(format!(
                "the client key is encrypted with an outdated scheme (PKCS#5 v1.5 / PKCS#12 \
                 PBE); {RE_ENCRYPT}"
            )),
        };
    }
    legacy_cipher(&p).map(|_| ())
}

/// A PKCS#8 decryption failure: a wrong passphrase, unless the algorithm is the problem.
fn pkcs8_error(e: pkcs8::Error) -> KeyError {
    use pkcs8::pkcs5::Error as P5;
    match e {
        pkcs8::Error::EncryptedPrivateKey(
            P5::UnsupportedAlgorithm { .. } | P5::AlgorithmParametersInvalid { .. },
        ) => KeyError::Unusable(format!(
            "the client key's encryption isn't supported ({e}); {RE_ENCRYPT}"
        )),
        _ => KeyError::WrongPassphrase,
    }
}

/// Decrypts an encrypted `<key>`.
pub fn decrypt(pem: &str, passphrase: &str) -> Result<PrivateKeyDer<'static>, KeyError> {
    let unusable = |m: String| KeyError::Unusable(m);
    check_encrypted(pem).map_err(unusable)?;
    let p = private_key_pem(pem).ok_or_else(|| unusable("unreadable client key".into()))?;
    let key = if p.label == "ENCRYPTED PRIVATE KEY" {
        let info = pkcs8::EncryptedPrivateKeyInfoRef::try_from(p.der.as_slice())
            .map_err(|e| unusable(e.to_string()))?;
        let doc = info.decrypt(passphrase.as_bytes()).map_err(pkcs8_error)?;
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(doc.as_bytes().to_vec()))
    } else {
        let (cipher, iv) = legacy_cipher(&p).map_err(unusable)?;
        let der = legacy_decrypt(cipher, &iv, &p.der, passphrase.as_bytes())
            .ok_or(KeyError::WrongPassphrase)?;
        match p.label.as_str() {
            "RSA PRIVATE KEY" => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der.to_vec())),
            "EC PRIVATE KEY" => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der.to_vec())),
            "PRIVATE KEY" => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.to_vec())),
            other => {
                return Err(unusable(format!(
                    "the client key is a \"{other}\", which isn't supported"
                )));
            }
        }
    };
    usable(key)
}

/// A decrypted key that doesn't load means the passphrase only happened to unpad cleanly.
fn usable(key: PrivateKeyDer<'static>) -> Result<PrivateKeyDer<'static>, KeyError> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    match provider.key_provider.load_private_key(key.clone_key()) {
        Ok(_) => Ok(key),
        Err(_) => Err(KeyError::WrongPassphrase),
    }
}

// ------------------------------------------------------------------------------- legacy PEM

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LegacyCipher {
    Aes128,
    Aes192,
    Aes256,
    DesEde3,
}

impl LegacyCipher {
    fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes192 | Self::DesEde3 => 24,
            Self::Aes256 => 32,
        }
    }

    fn iv_len(self) -> usize {
        match self {
            Self::DesEde3 => 8,
            _ => 16,
        }
    }
}

/// `DEK-Info: AES-256-CBC,<hex iv>` of a `Proc-Type: 4,ENCRYPTED` key.
fn legacy_cipher(p: &Pem) -> Result<(LegacyCipher, Vec<u8>), String> {
    if !header(p, "Proc-Type").is_some_and(|v| v.replace(' ', "") == "4,ENCRYPTED") {
        return Err("the client key is not encrypted".into());
    }
    let dek = header(p, "DEK-Info").ok_or("the encrypted client key has no DEK-Info")?;
    let (name, iv_hex) = dek
        .split_once(',')
        .ok_or("the encrypted client key's DEK-Info is malformed")?;
    let cipher = match name.trim().to_ascii_uppercase().as_str() {
        "AES-128-CBC" => LegacyCipher::Aes128,
        "AES-192-CBC" => LegacyCipher::Aes192,
        "AES-256-CBC" => LegacyCipher::Aes256,
        "DES-EDE3-CBC" => LegacyCipher::DesEde3,
        other => {
            return Err(format!(
                "the client key is encrypted with {other}, which isn't supported; {RE_ENCRYPT}"
            ));
        }
    };
    let iv: Option<Vec<u8>> = (0..iv_hex.trim().len())
        .step_by(2)
        .map(|i| {
            iv_hex
                .trim()
                .get(i..i + 2)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        })
        .collect();
    match iv {
        Some(iv) if iv.len() == cipher.iv_len() => Ok((cipher, iv)),
        _ => Err("the encrypted client key's DEK-Info has a malformed IV".into()),
    }
}

/// OpenSSL's `EVP_BytesToKey` with MD5 and one round, salted with the IV's first 8 bytes:
/// how traditional PEM keys turn a passphrase into a key.
fn bytes_to_key(passphrase: &[u8], salt: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(len + 16));
    let mut prev: Option<[u8; 16]> = None;
    while out.len() < len {
        let mut h = Md5::new();
        if let Some(p) = &prev {
            h.update(p);
        }
        h.update(passphrase);
        h.update(salt);
        let block: [u8; 16] = h.finalize().into();
        out.extend_from_slice(&block);
        prev = Some(block);
    }
    out.truncate(len);
    out
}

fn cbc_decrypt<C>(key: &[u8], iv: &[u8], data: &[u8]) -> Option<Zeroizing<Vec<u8>>>
where
    C: BlockCipherDecrypt + KeyInit,
    cbc::Decryptor<C>: KeyIvInit + BlockModeDecrypt,
{
    let mut buf = Zeroizing::new(data.to_vec());
    let n = cbc::Decryptor::<C>::new_from_slices(key, iv)
        .ok()?
        .decrypt_padded::<Pkcs7>(&mut buf)
        .ok()?
        .len();
    buf.truncate(n);
    Some(buf)
}

fn legacy_decrypt(
    cipher: LegacyCipher,
    iv: &[u8],
    data: &[u8],
    passphrase: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let key = bytes_to_key(passphrase, &iv[..8], cipher.key_len());
    match cipher {
        LegacyCipher::Aes128 => cbc_decrypt::<aes::Aes128>(&key, iv, data),
        LegacyCipher::Aes192 => cbc_decrypt::<aes::Aes192>(&key, iv, data),
        LegacyCipher::Aes256 => cbc_decrypt::<aes::Aes256>(&key, iv, data),
        LegacyCipher::DesEde3 => cbc_decrypt::<des::TdesEde3>(&key, iv, data),
    }
}

// ------------------------------------------------------------------------------- PKCS#12

/// Import-time check of a `<pkcs12>` bundle: its outer structure, a version 3 PFX protected by
/// a password. Nothing is derived from a password here (that is deliberately slow, and profiles
/// are parsed often); algorithms MorphGate can't open are reported when connecting.
pub fn check_pkcs12(der: &[u8]) -> Result<(), String> {
    /// ContentInfo of type `data` (1.2.840.113549.1.7.1): password integrity.
    const DATA: [u8; 11] = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
    ];
    let bad = || "the <pkcs12> block is not a complete PKCS#12 bundle".to_owned();
    let Some((0x30, pfx, [])) = tlv(der) else {
        return Err(bad());
    };
    let Some((0x02, [3], rest)) = tlv(pfx) else {
        return Err(bad());
    };
    match tlv(rest) {
        Some((0x30, auth_safe, _)) if auth_safe.starts_with(&DATA) => Ok(()),
        Some((0x30, _, _)) => Err(
            "the PKCS#12 bundle is signed with a key instead of a password, which isn't \
             supported"
                .into(),
        ),
        _ => Err(bad()),
    }
}

/// Opens a PKCS#12 bundle with its password.
pub fn open_pkcs12(der: &[u8], password: &str) -> Result<Bundle, KeyError> {
    let archive = Pkcs12Archive::from_pkcs12(der, password).map_err(|e| match e {
        P12Error::MacError(_) | P12Error::UnpadError | P12Error::Pkcs5Error(_) => {
            KeyError::WrongPassphrase
        }
        P12Error::UnsupportedEncryptionScheme | P12Error::UnsupportedMacAlgorithm => {
            KeyError::Unusable(
                "the PKCS#12 bundle is protected with an algorithm MorphGate doesn't support; \
                 convert it with `openssl pkcs12 -in bundle.p12 -nodes` and use <ca>, <cert> \
                 and <key>"
                    .into(),
            )
        }
        e => KeyError::Unusable(format!("the PKCS#12 bundle can't be read: {e}")),
    })?;
    let key = archive
        .keys
        .first()
        .ok_or_else(|| KeyError::Unusable("the PKCS#12 bundle has no private key".into()))?;
    // The client certificate is the one with the key's local key id; failing that, the only
    // certificate, or the first one that isn't self-signed.
    let key_id = key.local_key_id.as_ref().map(|k| k.as_ref().to_vec());
    let leaf = archive
        .certs
        .iter()
        .position(|c| key_id.is_some() && c.local_key_id == key_id)
        .or_else(|| (archive.certs.len() == 1).then_some(0))
        .or_else(|| {
            archive
                .certs
                .iter()
                .position(|c| c.cert.subject() != c.cert.issuer())
        })
        .ok_or_else(|| {
            KeyError::Unusable("the PKCS#12 bundle has no certificate for its key".into())
        })?;
    let der_of = |i: usize| CertificateDer::from(archive.certs[i].cert.as_der().to_vec());
    let others: Vec<usize> = (0..archive.certs.len()).filter(|i| *i != leaf).collect();
    let mut chain = vec![der_of(leaf)];
    // Intermediates go along so the server can build the chain; roots it has already.
    chain.extend(
        others
            .iter()
            .filter(|i| archive.certs[**i].cert.subject() != archive.certs[**i].cert.issuer())
            .map(|i| der_of(*i)),
    );
    let key = usable(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        key.key.as_der().to_vec(),
    )))
    .map_err(|_| KeyError::Unusable("the PKCS#12 bundle's private key isn't supported".into()))?;
    Ok(Bundle {
        chain,
        key,
        authorities: others.into_iter().map(der_of).collect(),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    //! Fixtures in `testdata/`, made with the OpenSSL 3.5 command line:
    //!
    //! ```sh
    //! openssl ecparam -name prime256v1 -genkey -noout -out ca.key
    //! openssl req -x509 -new -key ca.key -subj "/CN=MorphGate fixture CA" -days 36500 -out ca.crt \
    //!   -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
    //! openssl ecparam -name prime256v1 -genkey -noout -out client.ec.key
    //! openssl pkcs8 -topk8 -nocrypt -in client.ec.key -out client.key
    //! openssl req -new -key client.key -subj /CN=client -out client.csr
    //! openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -days 36500 -extfile ext.cnf \
    //!   -out client.crt            # ext.cnf: clientAuth, digitalSignature, keyAgreement
    //! P='pass:s3cret pass'
    //! openssl pkcs8 -topk8 -in client.key -v2 aes-256-cbc -v2prf hmacWithSHA256 -passout "$P" \
    //!   -out client.pkcs8-aes256.pem
    //! openssl pkcs8 -topk8 -in client.key -v2 des3 -v2prf hmacWithSHA1 -passout "$P" \
    //!   -out client.pkcs8-des3-sha1.pem
    //! openssl pkcs8 -topk8 -in client.key -v1 PBE-SHA1-3DES -passout "$P" -out client.pkcs8-pbes1.pem
    //! openssl ec -in client.ec.key -aes128 -passout "$P" -out client.legacy-aes128.pem
    //! openssl ec -in client.ec.key -des3 -passout "$P" -out client.legacy-des3.pem
    //! openssl genrsa -traditional -aes256 -passout "$P" -out rsa.legacy-aes256.pem 2048
    //! openssl pkcs12 -export -inkey client.key -in client.crt -certfile ca.crt -name client \
    //!   -passout "$P" -out client.p12                       # AES-256, SHA-256 MAC
    //! openssl pkcs12 -export -legacy -inkey client.key -in client.crt -certfile ca.crt \
    //!   -name client -passout "$P" -out client-legacy.p12   # RC2-40 + 3DES, SHA-1 MAC
    //! openssl pkcs12 -export -inkey client.key -in client.crt -certfile ca.crt -passout pass: \
    //!   -out client-nopass.p12
    //! ```

    use super::*;

    pub(crate) const PASSPHRASE: &str = "s3cret pass";
    pub(crate) const CA: &str = include_str!("testdata/ca.crt");
    pub(crate) const CLIENT_CERT: &str = include_str!("testdata/client.crt");
    pub(crate) const PKCS8_AES256: &str = include_str!("testdata/client.pkcs8-aes256.pem");
    const PKCS8_DES3_SHA1: &str = include_str!("testdata/client.pkcs8-des3-sha1.pem");
    const PKCS8_PBES1: &str = include_str!("testdata/client.pkcs8-pbes1.pem");
    pub(crate) const LEGACY_AES128: &str = include_str!("testdata/client.legacy-aes128.pem");
    const LEGACY_DES3: &str = include_str!("testdata/client.legacy-des3.pem");
    const RSA_LEGACY_AES256: &str = include_str!("testdata/rsa.legacy-aes256.pem");
    pub(crate) const P12: &[u8] = include_bytes!("testdata/client.p12");
    const P12_LEGACY: &[u8] = include_bytes!("testdata/client-legacy.p12");
    pub(crate) const P12_NO_PASSWORD: &[u8] = include_bytes!("testdata/client-nopass.p12");

    fn first_cert(pem: &str) -> Vec<u8> {
        use rustls::pki_types::pem::PemObject;
        CertificateDer::pem_slice_iter(pem.as_bytes())
            .next()
            .unwrap()
            .unwrap()
            .to_vec()
    }

    #[test]
    fn encrypted_pem_keys_open_with_the_passphrase() {
        for (name, pem, kind) in [
            ("PKCS#8 AES-256", PKCS8_AES256, "pkcs8"),
            ("PKCS#8 3DES/SHA-1", PKCS8_DES3_SHA1, "pkcs8"),
            ("legacy AES-128", LEGACY_AES128, "sec1"),
            ("legacy 3DES", LEGACY_DES3, "sec1"),
            ("legacy RSA AES-256", RSA_LEGACY_AES256, "pkcs1"),
        ] {
            assert!(is_encrypted(pem), "{name}");
            assert_eq!(check_encrypted(pem), Ok(()), "{name}");
            let key = decrypt(pem, PASSPHRASE).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            let got = match key {
                PrivateKeyDer::Pkcs8(_) => "pkcs8",
                PrivateKeyDer::Sec1(_) => "sec1",
                PrivateKeyDer::Pkcs1(_) => "pkcs1",
                _ => "other",
            };
            assert_eq!(got, kind, "{name}");
            assert_eq!(
                decrypt(pem, "wrong").unwrap_err(),
                KeyError::WrongPassphrase,
                "{name}"
            );
            assert_eq!(decrypt(pem, "").unwrap_err(), KeyError::WrongPassphrase);
        }
        assert!(!is_encrypted(CLIENT_CERT));
    }

    #[test]
    fn outdated_or_broken_encryption_is_explained() {
        // PKCS#12-style PBE in a PKCS#8 file: not supported, with the command that fixes it.
        assert!(
            check_encrypted(PKCS8_PBES1)
                .unwrap_err()
                .contains("openssl pkcs8 -topk8")
        );
        assert!(matches!(
            decrypt(PKCS8_PBES1, PASSPHRASE),
            Err(KeyError::Unusable(m)) if m.contains("openssl pkcs8 -topk8")
        ));
        let des = LEGACY_AES128.replace("AES-128-CBC", "DES-CBC");
        assert!(check_encrypted(&des).unwrap_err().contains("DES-CBC"));
        let no_iv = LEGACY_AES128.replace("AES-128-CBC,", "AES-128-CBC,ZZ");
        assert!(check_encrypted(&no_iv).unwrap_err().contains("IV"));
        assert!(check_encrypted("not a key").is_err());
    }

    #[test]
    fn bytes_to_key_chains_md5_blocks() {
        // The legacy fixtures above check it against OpenSSL; spelled out: D1 = MD5(pass ||
        // salt), D2 = MD5(D1 || pass || salt), key = D1 || D2, cut to length.
        let salt = [1, 2, 3, 4, 5, 6, 7, 8];
        let k = bytes_to_key(b"secret", &salt, 24);
        let d1: [u8; 16] = Md5::new()
            .chain_update(b"secret")
            .chain_update(salt)
            .finalize()
            .into();
        let d2: [u8; 16] = Md5::new()
            .chain_update(d1)
            .chain_update(b"secret")
            .chain_update(salt)
            .finalize()
            .into();
        assert_eq!(k[..16], d1);
        assert_eq!(k[16..], d2[..8]);
    }

    #[test]
    fn pkcs12_bundles_bring_certificate_key_and_ca() {
        let client = first_cert(CLIENT_CERT);
        let ca = first_cert(CA);
        for (name, der, password) in [
            ("AES-256", P12, PASSPHRASE),
            ("legacy RC2/3DES", P12_LEGACY, PASSPHRASE),
            ("no password", P12_NO_PASSWORD, ""),
        ] {
            assert_eq!(check_pkcs12(der), Ok(()), "{name}");
            let b = open_pkcs12(der, password).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!(
                b.chain.len(),
                1,
                "{name}: the self-signed CA isn't sent along"
            );
            assert_eq!(b.chain[0].as_ref(), client, "{name}");
            assert_eq!(b.authorities.len(), 1, "{name}");
            assert_eq!(b.authorities[0].as_ref(), ca, "{name}");
            assert!(matches!(b.key, PrivateKeyDer::Pkcs8(_)));
        }
        assert!(matches!(
            open_pkcs12(P12, "wrong"),
            Err(KeyError::WrongPassphrase)
        ));
        assert!(matches!(
            open_pkcs12(P12, ""),
            Err(KeyError::WrongPassphrase)
        ));
        assert!(check_pkcs12(b"\x30\x03\x02\x01\x01").is_err());
        assert!(check_pkcs12(&P12[..P12.len() / 2]).is_err());
    }
}
