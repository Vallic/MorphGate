//! The control channel's TLS client (rustls), set up the way OpenVPN does it: the server is
//! trusted through the profile's CA (no hostname check, no SNI), optionally narrowed by
//! `verify-x509-name`, or pinned by `peer-fingerprint`.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};

use super::config::{Config, NameType};
use super::keyfile;
use crate::VpnError;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn certs(pem: &str, what: &str) -> Result<Vec<CertificateDer<'static>>, VpnError> {
    let certs: Vec<_> = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|e| VpnError::Config(format!("{what}: {e}")))?;
    if certs.is_empty() {
        return Err(VpnError::Config(format!("{what}: no certificate found")));
    }
    Ok(certs)
}

fn private_key(pem: &str) -> Result<PrivateKeyDer<'static>, VpnError> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes())
        .map_err(|e| VpnError::Config(format!("client key: {e}")))
}

/// Who the client is: its certificate chain and key, ready to use (decrypted if they were
/// protected).
pub struct Identity {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    /// CA certificates that came with a PKCS#12 bundle; trusted when the profile has no `<ca>`.
    pub authorities: Vec<CertificateDer<'static>>,
}

/// The profile's `<cert>` with a key that is ready (decrypted, if it was encrypted).
pub fn identity_with_key(cfg: &Config, key: PrivateKeyDer<'static>) -> Result<Identity, VpnError> {
    let cert = cfg
        .cert
        .as_deref()
        .ok_or_else(|| VpnError::Config("the profile has a client key but no <cert>".into()))?;
    Ok(Identity {
        chain: certs(cert, "client certificate")?,
        key,
        authorities: vec![],
    })
}

/// The client identity of a profile whose key needs no passphrase (`None`: no client
/// certificate at all).
pub fn plain_identity(cfg: &Config) -> Result<Option<Identity>, VpnError> {
    match &cfg.key {
        Some(key) if !cfg.needs_passphrase() => identity_with_key(cfg, private_key(key)?).map(Some),
        _ => Ok(None),
    }
}

/// Validates the profile's certificates without connecting (import-time errors). Protected
/// keys are checked as far as possible without their passphrase.
pub fn check(cfg: &Config) -> Result<(), VpnError> {
    if !cfg.needs_passphrase() {
        return client_config(cfg, plain_identity(cfg)?.as_ref()).map(|_| ());
    }
    if !cfg.ca.trim().is_empty() {
        roots(cfg, None)?;
    }
    if let Some(cert) = &cfg.cert {
        certs(cert, "client certificate")?;
    }
    match (&cfg.pkcs12, &cfg.key) {
        (Some(bundle), _) => keyfile::check_pkcs12(bundle),
        (None, Some(key)) => keyfile::check_encrypted(key),
        (None, None) => Ok(()),
    }
    .map_err(VpnError::Config)
}

/// The profile's `<ca>`, or else the CA certificates of its PKCS#12 bundle.
fn roots(cfg: &Config, identity: Option<&Identity>) -> Result<RootCertStore, VpnError> {
    let mut roots = RootCertStore::empty();
    if !cfg.ca.trim().is_empty() {
        for c in certs(&cfg.ca, "CA certificate")? {
            roots
                .add(c)
                .map_err(|e| VpnError::Config(format!("CA certificate: {e}")))?;
        }
    } else if let Some(id) = identity {
        for c in &id.authorities {
            roots.add(c.clone()).map_err(|e| {
                VpnError::Config(format!("CA certificate in the PKCS#12 bundle: {e}"))
            })?;
        }
    }
    if roots.is_empty() && cfg.peer_fingerprints.is_empty() {
        return Err(VpnError::Config(
            "the profile has no CA certificate (<ca>), and its PKCS#12 bundle has none either"
                .into(),
        ));
    }
    Ok(roots)
}

/// The TLS client for the control channel. `identity` is the client certificate and key, if the
/// profile has them (see [`plain_identity`], or the passphrase dance in [`super::start`]).
pub fn client_config(
    cfg: &Config,
    identity: Option<&Identity>,
) -> Result<Arc<ClientConfig>, VpnError> {
    let provider = provider();
    let roots = roots(cfg, identity)?;
    let verifier = Arc::new(Verifier {
        roots: Arc::new(roots),
        algs: provider.signature_verification_algorithms,
        name: cfg.verify_x509_name.clone(),
        fingerprints: cfg.peer_fingerprints.clone(),
    });
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| VpnError::Config(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut config = match identity {
        Some(id) => builder
            .with_client_auth_cert(id.chain.clone(), id.key.clone_key())
            .map_err(|e| VpnError::Config(format!("client certificate: {e}")))?,
        None => builder.with_no_client_auth(),
    };
    config.enable_sni = false;
    // OpenVPN servers don't resume sessions, and every key state wants fresh TLS keys.
    config.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(config))
}

/// Any name will do: OpenVPN neither sends SNI nor checks the certificate's host name.
pub fn server_name() -> ServerName<'static> {
    ServerName::try_from("openvpn").expect("valid name")
}

#[derive(Debug)]
struct Verifier {
    roots: Arc<RootCertStore>,
    algs: WebPkiSupportedAlgorithms,
    name: Option<(String, NameType)>,
    fingerprints: Vec<[u8; 32]>,
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if !self.fingerprints.is_empty() {
            let fp = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, end_entity);
            if self.fingerprints.iter().any(|f| f == fp.as_ref()) {
                return Ok(ServerCertVerified::assertion());
            }
            if self.roots.is_empty() {
                return Err(Error::General(
                    "the server certificate doesn't match the profile's peer-fingerprint".into(),
                ));
            }
        }
        let cert = rustls::server::ParsedCertificate::try_from(end_entity)?;
        // Chain to the profile's CA and serverAuth usage (when the certificate lists usages),
        // but no host name: OpenVPN identifies servers by CA and certificate name instead.
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.roots,
            intermediates,
            now,
            self.algs.all,
        )?;
        if let Some((want, kind)) = &self.name {
            let fields = subject(end_entity).ok_or_else(|| {
                Error::General("cannot read the server certificate's subject".into())
            })?;
            let cn = fields
                .iter()
                .rev()
                .find(|(k, _)| k == "CN")
                .map(|(_, v)| v.as_str())
                .unwrap_or("");
            let ok = match kind {
                NameType::Name => cn == want,
                NameType::NamePrefix => cn.starts_with(want.as_str()),
                NameType::Subject => {
                    let full: Vec<String> =
                        fields.iter().map(|(k, v)| format!("{k}={v}")).collect();
                    full.join(", ") == *want || full.join(",") == *want
                }
            };
            if !ok {
                return Err(Error::General(format!(
                    "the server certificate is for \"{cn}\", but the profile expects \"{want}\" \
                     (verify-x509-name)"
                )));
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Minimal DER reader: (tag, content, rest).
pub(super) fn tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = data.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |a, b| (a << 8) | usize::from(*b));
        (len, &rest[n..])
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

fn oid_name(oid: &[u8]) -> Option<&'static str> {
    Some(match oid {
        [0x55, 0x04, 0x03] => "CN",
        [0x55, 0x04, 0x06] => "C",
        [0x55, 0x04, 0x07] => "L",
        [0x55, 0x04, 0x08] => "ST",
        [0x55, 0x04, 0x0a] => "O",
        [0x55, 0x04, 0x0b] => "OU",
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01] => "emailAddress",
        _ => return None,
    })
}

/// The subject's attributes in certificate order, e.g. `[("C","US"), ("CN","vpn")]`.
pub fn subject(der: &[u8]) -> Option<Vec<(String, String)>> {
    let (0x30, cert, _) = tlv(der)? else {
        return None;
    };
    let (0x30, tbs, _) = tlv(cert)? else {
        return None;
    };
    let mut rest = tbs;
    let (tag, _, r) = tlv(rest)?;
    if tag == 0xa0 {
        rest = r; // explicit version
    }
    // serial, signature algorithm, issuer, validity, then subject
    for _ in 0..4 {
        rest = tlv(rest)?.2;
    }
    let (0x30, mut name, _) = tlv(rest)? else {
        return None;
    };
    let mut out = Vec::new();
    while !name.is_empty() {
        let (_, set, r) = tlv(name)?;
        name = r;
        let mut set = set;
        while !set.is_empty() {
            let (_, atv, r) = tlv(set)?;
            set = r;
            let (_, oid, value) = tlv(atv)?;
            let (_, value, _) = tlv(value)?;
            if let Some(k) = oid_name(oid) {
                out.push((k.to_owned(), String::from_utf8_lossy(value).into_owned()));
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_subject() {
        let mut params = rcgen::CertificateParams::new(vec!["vpn.example".into()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CountryName, "HR");
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Acme d.o.o.");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "server");
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let fields = subject(cert.der()).unwrap();
        assert_eq!(
            fields,
            vec![
                ("C".into(), "HR".into()),
                ("O".into(), "Acme d.o.o.".into()),
                ("CN".into(), "server".into())
            ]
        );
    }
}
