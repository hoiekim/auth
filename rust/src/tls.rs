//! TLS for what the server connects to: Postgres, the SMTP server, and over
//! HTTPS the alert webhook, event URLs and the breached-password range API.
//! Trust is the bundled public roots, the host's own store (where
//! `SSL_CERT_FILE` points, if set), and the PEM file `NODE_EXTRA_CA_CERTS`
//! names, as the Bun server's runtime reads it: where a deployment adds a
//! private CA for either server.
//!
//! A certificate is checked by rustls, and then, where rustls refuses one,
//! accepted in the two cases the TLS library under the Bun server (OpenSSL's
//! rules) accepts it: a trusted self-signed root sent as the server's own
//! certificate, even one marked as a CA, which is how Postgres's
//! documentation has a self-signed certificate made and pinned; and a host
//! name in the subject's common name when the certificate names no DNS
//! names. A CA-issued certificate marked as a CA is still refused.

use std::sync::{Arc, OnceLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme};

use crate::pgurl::{SslMode, TlsFiles};
use crate::x509;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn roots() -> Arc<RootCertStore> {
    static ROOTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    ROOTS
        .get_or_init(|| {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            for cert in rustls_native_certs::load_native_certs().certs {
                let _ = roots.add(cert);
            }
            if let Some(path) = std::env::var_os("NODE_EXTRA_CA_CERTS").filter(|p| !p.is_empty()) {
                for cert in std::fs::read(path).iter().flat_map(|pem| CertificateDer::pem_slice_iter(pem)).flatten() {
                    let _ = roots.add(cert);
                }
            }
            Arc::new(roots)
        })
        .clone()
}

pub fn client_config() -> ClientConfig {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    let shared = CONFIG.get_or_init(|| {
        let verifier = Checked::new(roots(), true).expect("a verifier for the roots");
        Arc::new(
            ClientConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .expect("the default TLS versions")
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth(),
        )
    });
    (**shared).clone()
}

/// TLS to Postgres at one of DATABASE_URL's levels (rust/src/pgurl.rs), as
/// the Bun server's client makes it: `prefer` and `require` encrypt without
/// checking the certificate, `verify-ca` checks its chain but not its name,
/// and `verify-full` both. A file `sslrootcert` names is then the only root
/// trusted. A client certificate is offered when it and its key are both
/// named. The files are read for each connection, so one that can't be read
/// fails the connection, not the start.
pub fn postgres_config(mode: SslMode, files: &TlsFiles) -> Result<ClientConfig, BoxError> {
    let provider = provider();
    let verifier: Arc<dyn ServerCertVerifier> = if mode >= SslMode::VerifyCa {
        let roots = match &files.ca_file {
            Some(path) => {
                let mut roots = RootCertStore::empty();
                for cert in CertificateDer::pem_slice_iter(&std::fs::read(path)?) {
                    roots.add(cert?)?;
                }
                Arc::new(roots)
            }
            None => roots(),
        };
        Checked::new(roots, mode == SslMode::VerifyFull)?
    } else {
        Arc::new(Unchecked(provider.clone()))
    };
    let builder = ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions()?.dangerous().with_custom_certificate_verifier(verifier);
    Ok(match (&files.cert_file, &files.key_file) {
        (Some(cert), Some(key)) => {
            let chain = CertificateDer::pem_slice_iter(&std::fs::read(cert)?).collect::<Result<Vec<_>, _>>()?;
            builder.with_client_auth_cert(chain, PrivateKeyDer::from_pem_slice(&std::fs::read(key)?)?)?
        }
        _ => builder.with_no_client_auth(),
    })
}

/// Any certificate, with the handshake still signed by its key.
#[derive(Debug)]
struct Unchecked(Arc<CryptoProvider>);

impl ServerCertVerifier for Unchecked {
    fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// rustls's checks, then OpenSSL's two acceptances; the name only when
/// `name` is set (`verify-ca` checks the chain alone). rustls checks the
/// name last, so a name error comes only from a chain that passed.
#[derive(Debug)]
struct Checked {
    webpki: Arc<WebPkiServerVerifier>,
    roots: Arc<RootCertStore>,
    name: bool,
}

impl Checked {
    fn new(roots: Arc<RootCertStore>, name: bool) -> Result<Arc<Self>, BoxError> {
        let webpki = WebPkiServerVerifier::builder_with_provider(roots.clone(), provider()).build()?;
        Ok(Arc::new(Checked { webpki, roots, name }))
    }

    /// The common name stands in for DNS names the certificate lacks; never
    /// for an IP address.
    fn common_name_matches(cert: &x509::Cert, server: &ServerName<'_>) -> bool {
        match server {
            ServerName::DnsName(host) => !cert.has_dns_names && cert.common_names.iter().any(|cn| x509::name_matches(cn, host.as_ref())),
            _ => false,
        }
    }

    /// A self-signed certificate that is itself one of the roots.
    fn pinned(&self, end_entity: &CertificateDer<'_>, server: &ServerName<'_>, now: UnixTime) -> Result<(), TlsError> {
        let refused = || TlsError::InvalidCertificate(CertificateError::UnknownIssuer);
        let cert = x509::parse(end_entity).ok_or_else(refused)?;
        let trusted = cert.issuer == cert.subject && self.roots.roots.iter().any(|root| root.subject.as_ref() == cert.subject && root.subject_public_key_info.as_ref() == cert.spki);
        if !trusted {
            return Err(refused());
        }
        let now = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
        if now < cert.not_before {
            return Err(TlsError::InvalidCertificate(CertificateError::NotValidYet));
        }
        if now > cert.not_after {
            return Err(TlsError::InvalidCertificate(CertificateError::Expired));
        }
        if self.name && rustls::client::verify_server_name(&ParsedCertificate::try_from(end_entity)?, server).is_err() && !Self::common_name_matches(&cert, server) {
            return Err(TlsError::InvalidCertificate(CertificateError::NotValidForName));
        }
        Ok(())
    }
}

impl ServerCertVerifier for Checked {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], server: &ServerName<'_>, ocsp: &[u8], now: UnixTime) -> Result<ServerCertVerified, TlsError> {
        match self.webpki.verify_server_cert(end_entity, intermediates, server, ocsp, now) {
            Err(TlsError::InvalidCertificate(CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }))
                if !self.name || x509::parse(end_entity).is_some_and(|cert| Self::common_name_matches(&cert, server)) =>
            {
                Ok(ServerCertVerified::assertion())
            }
            Err(refused) => self.pinned(end_entity, server, now).map(|()| ServerCertVerified::assertion()).map_err(|_| refused),
            verified => verified,
        }
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, TlsError> {
        self.webpki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, TlsError> {
        self.webpki.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}
