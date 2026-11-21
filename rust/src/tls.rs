//! TLS for what the server connects to: Postgres, the SMTP server, and over
//! HTTPS the alert webhook, event URLs and the breached-password range API.
//! Trust is the bundled public roots plus the host's own store, where a
//! deployment adds a private CA.

use std::sync::{Arc, OnceLock};

use rustls::{ClientConfig, RootCertStore};

fn roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    roots
}

pub fn client_config() -> ClientConfig {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    let shared = CONFIG.get_or_init(|| {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        Arc::new(ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions().expect("the default TLS versions").with_root_certificates(roots()).with_no_client_auth())
    });
    (**shared).clone()
}
