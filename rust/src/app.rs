//! Everything a handler needs, built once at start: configuration, the pool,
//! keys, the mail queue and the alert webhook. A request works on an `App`
//! of its own, whose services stay the same from its start to its end.

use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use deadpool_postgres::Pool;
use serde_json::json;
use tokio::sync::Semaphore;

use crate::config::Config;
use crate::crypto::Encrypter;
use crate::db::{Pinger, Tx, Q};
use crate::error::Result;
use crate::keys::KeyStore;
use crate::mail::{MailMessage, Mailer};
use crate::passwords::{is_breached, Hasher};
use crate::registry::ServiceRegistry;
use crate::services::Services;

pub struct Shared {
    pub config: Config,
    pub pool: Pool,
    pub crypt: Encrypter,
    pub keys: KeyStore,
    pub registry: ServiceRegistry,
    pub hasher: Hasher,
    pub http: reqwest::Client,
    pub mailer: Mailer,
    pub pinger: Pinger,
    /// Not healthy until the schema and a signing key are in place.
    pub ready: AtomicBool,
    mail_slots: Arc<Semaphore>,
    mails_in_flight: Arc<AtomicUsize>,
    alerts_in_flight: Arc<AtomicUsize>,
    log_to_stderr: bool,
}

/// The app as one request, or one pass of a job, sees it.
#[derive(Clone)]
pub struct App {
    shared: Arc<Shared>,
    /// The services as this request loaded them; at start, the file's only.
    pub services: Arc<Services>,
}

impl Deref for App {
    type Target = Shared;

    fn deref(&self) -> &Shared {
        &self.shared
    }
}

const MAX_QUEUED_EMAILS: usize = 200;

pub fn http_client() -> reqwest::Client {
    reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).use_preconfigured_tls(crate::tls::client_config()).build().expect("an HTTP client")
}

pub fn log_line(to_stderr: bool, line: &str) {
    if to_stderr {
        eprintln!("{line}");
    } else {
        println!("{line}");
    }
}

impl App {
    /// `log_to_stderr`: the CLI keeps its standard output for what it prints.
    pub fn new(config: Config, pool: Pool, mailer: Mailer, log_to_stderr: bool) -> App {
        let services = config.services.clone();
        let file = services.all().iter().filter(|s| s.source == crate::services::Source::File).map(|s| (**s).clone()).collect();
        let crypt = Encrypter::new(config.encryption_key.clone(), config.decryption_keys.clone());
        let shared = Shared {
            crypt,
            keys: KeyStore::new(),
            registry: ServiceRegistry::new(file, log_to_stderr),
            hasher: Hasher::new(),
            http: http_client(),
            mailer,
            pinger: Pinger::new(pool.clone(), Duration::from_millis(2000)),
            ready: AtomicBool::new(false),
            mail_slots: Arc::new(Semaphore::new(2)),
            mails_in_flight: Arc::new(AtomicUsize::new(0)),
            alerts_in_flight: Arc::new(AtomicUsize::new(0)),
            log_to_stderr,
            pool,
            config,
        };
        App { shared: Arc::new(shared), services }
    }

    /// A copy of the app with the services as they are now (registry.rs).
    pub async fn prepare(&self) -> Result<App> {
        Ok(App { shared: self.shared.clone(), services: self.shared.registry.current(&self.shared.pool).await? })
    }

    pub fn db(&self) -> Q<'_> {
        Q::Pool(&self.shared.pool)
    }

    pub async fn begin(&self) -> Result<Tx> {
        Tx::begin(&self.shared.pool).await
    }

    pub fn log(&self, line: &str) {
        log_line(self.shared.log_to_stderr, line);
    }

    /// Queues an email; sending happens after the caller's response, so an
    /// answer never waits on, or reveals, whether a message went out.
    pub fn mail(&self, msg: MailMessage) {
        let shared = self.shared.clone();
        if shared.mails_in_flight.load(Ordering::SeqCst) >= MAX_QUEUED_EMAILS {
            self.log("email dropped: the send queue is full");
            return;
        }
        shared.mails_in_flight.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(async move {
            let slot = shared.mail_slots.clone().acquire_owned().await;
            // The mail module's own errors name an SMTP code and command and nothing else.
            if let Err(e) = shared.mailer.send(&msg).await {
                log_line(shared.log_to_stderr, &format!("email failed: {}", e.0));
            }
            drop(slot);
            shared.mails_in_flight.fetch_sub(1, Ordering::SeqCst);
        });
    }

    /// Settles once every queued email has been sent or has failed.
    pub async fn drain_mail(&self) {
        while self.shared.mails_in_flight.load(Ordering::SeqCst) > 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Posts to the deployment's alert webhook, when it has one, after the
    /// caller's response.
    pub fn alert(&self, text: String) {
        let Some(url) = self.shared.config.alert_webhook_url.clone() else { return };
        let shared = self.shared.clone();
        shared.alerts_in_flight.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(async move {
            post_alert(&shared.http, &url, &text, |line| log_line(shared.log_to_stderr, line)).await;
            shared.alerts_in_flight.fetch_sub(1, Ordering::SeqCst);
        });
    }

    /// Settles once every alert posted has been answered or has failed.
    pub async fn drain_alerts(&self) {
        while self.shared.alerts_in_flight.load(Ordering::SeqCst) > 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub async fn breached(&self, password: &str) -> bool {
        is_breached(&self.shared.http, &self.shared.config.breached_passwords_url, password).await
    }
}

/// Posts `{"text": …}`, the shape chat webhooks take. The URL is never logged:
/// it can carry a token.
pub async fn post_alert(client: &reqwest::Client, url: &str, text: &str, log: impl Fn(&str)) {
    let request = client.post(url).header("Content-Type", "application/json").body(json!({ "text": text }).to_string()).timeout(Duration::from_millis(5000));
    match request.send().await {
        Ok(res) if res.status().is_success() => {}
        Ok(res) => log(&format!("alert webhook answered {}", res.status().as_u16())),
        Err(e) => log(&format!("alert webhook failed: {}", if e.is_timeout() { "TimeoutError" } else { "Error" })),
    }
}
