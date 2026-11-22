//! Postgres: a pool of five connections (docs/DESIGN.md §10), transactions
//! whose outside effects wait for the commit, and the health check's ping.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use deadpool_postgres::{Hook, HookError, Manager, ManagerConfig, Object, Pool, RecyclingMethod};
use tokio::sync::watch;
use tokio_postgres::config::ChannelBinding;
use tokio_postgres::tls::MakeTlsConnect;
use tokio_postgres::types::ToSql;
use tokio_postgres::Row;
use tokio_postgres_rustls::MakeRustlsConnect;

use crate::error::{Error, Result};
use crate::pgurl::{self, SslMode, TlsFiles};
use crate::tls::BoxError;

pub type Param<'a> = &'a (dyn ToSql + Sync);

/// A pool on DATABASE_URL, read as the Bun server's client reads it
/// (rust/src/pgurl.rs). It opens no connection until one is asked for.
pub fn connect(url: &str) -> std::result::Result<Pool, Error> {
    let s = pgurl::parse(url, &|name| std::env::var(name).ok()).map_err(|_| Error::Other("ConfigError"))?;
    let mut config = tokio_postgres::Config::new();
    config.user(&s.username).password(s.password.as_bytes()).dbname(&s.database).port(s.port);
    match &s.path {
        // tokio-postgres reaches a socket as `<directory>/.s.PGSQL.<port>`,
        // so a socket named otherwise can't be reached.
        Some(path) => match path.rsplit_once("/.s.PGSQL.").map(|(dir, port)| (dir, port.parse::<u16>())) {
            Some((dir, Ok(port))) => {
                config.host_path(if dir.is_empty() { "/" } else { dir }).port(port);
            }
            _ => {
                config.host_path(path);
            }
        },
        None => {
            config.host(s.hostname.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(&s.hostname));
        }
    }
    // The startup parameters: two by their own names, `database` overriding
    // the path's as it does after Bun's own, and the rest in `options`.
    let (mut options, mut rest) = (String::new(), Vec::new());
    for (name, value) in &s.startup {
        match name.as_str() {
            "application_name" => {
                config.application_name(value);
            }
            "options" => options.clone_from(value),
            "database" => {
                config.dbname(value);
            }
            _ => rest.push((name.as_str(), value.as_str())),
        }
    }
    let options = pgurl::options_with(&options, &rest);
    if !options.is_empty() {
        config.options(&options);
    }
    // Bun gives up on a connection after 30 seconds unless told otherwise;
    // 0 waits for ever.
    match s.connect_timeout {
        None => {
            config.connect_timeout(Duration::from_secs(30));
        }
        Some(timeout) if !timeout.is_zero() => {
            config.connect_timeout(timeout);
        }
        Some(_) => {}
    }
    config.channel_binding(match s.channel_binding.as_str() {
        "require" => ChannelBinding::Require,
        "prefer" => ChannelBinding::Prefer,
        _ => ChannelBinding::Disable,
    });
    config.ssl_mode(match s.ssl_mode {
        SslMode::Disable => tokio_postgres::config::SslMode::Disable,
        SslMode::Prefer => tokio_postgres::config::SslMode::Prefer,
        _ => tokio_postgres::config::SslMode::Require,
    });
    let recycle = ManagerConfig { recycling_method: RecyclingMethod::Fast };
    let manager = match s.ssl_mode {
        SslMode::Disable => Manager::from_config(config, tokio_postgres::NoTls, recycle),
        mode => Manager::from_config(config, PostgresTls { mode, files: s.tls.clone() }, recycle),
    };
    let mut pool = Pool::builder(manager).max_size(5);
    // A connection idle, or open, for longer than the URL allows is closed
    // when next taken, and another opened in its place.
    let (idle, lifetime) = (s.idle_timeout.filter(|d| !d.is_zero()), s.max_lifetime.filter(|d| !d.is_zero()));
    if idle.is_some() || lifetime.is_some() {
        pool =
            pool.pre_recycle(Hook::sync_fn(
                move |_, metrics| {
                    if lifetime.is_some_and(|l| metrics.age() >= l) || idle.is_some_and(|i| metrics.last_used() >= i) {
                        Err(HookError::message("expired"))
                    } else {
                        Ok(())
                    }
                },
            ));
    }
    pool.build().map_err(|_| Error::Other("PoolError"))
}

/// TLS made for each connection from the URL's level and files.
#[derive(Clone)]
struct PostgresTls {
    mode: SslMode,
    files: TlsFiles,
}

impl<S> MakeTlsConnect<S> for PostgresTls
where
    MakeRustlsConnect: MakeTlsConnect<S>,
    <MakeRustlsConnect as MakeTlsConnect<S>>::Error: Into<BoxError>,
{
    type Stream = <MakeRustlsConnect as MakeTlsConnect<S>>::Stream;
    type TlsConnect = <MakeRustlsConnect as MakeTlsConnect<S>>::TlsConnect;
    type Error = BoxError;

    fn make_tls_connect(&mut self, hostname: &str) -> std::result::Result<Self::TlsConnect, BoxError> {
        let config = crate::tls::postgres_config(self.mode, &self.files)?;
        MakeRustlsConnect::new(config).make_tls_connect(hostname).map_err(Into::into)
    }
}

/// Where a statement runs: on any pooled connection, or inside a transaction.
/// Functions that can be called from either take one of these.
#[derive(Clone, Copy)]
pub enum Q<'a> {
    Pool(&'a Pool),
    Tx(&'a Tx),
}

impl<'a> Q<'a> {
    pub async fn query(self, sql: &str, params: &[Param<'_>]) -> Result<Vec<Row>> {
        match self {
            Q::Pool(pool) => {
                let conn = pool.get().await?;
                let statement = conn.prepare_cached(sql).await?;
                Ok(conn.query(&statement, params).await?)
            }
            Q::Tx(tx) => {
                let conn = tx.conn();
                let statement = conn.prepare_cached(sql).await?;
                Ok(conn.query(&statement, params).await?)
            }
        }
    }

    /// The first row, if there is one.
    pub async fn first(self, sql: &str, params: &[Param<'_>]) -> Result<Option<Row>> {
        Ok(self.query(sql, params).await?.into_iter().next())
    }

    /// The one row a statement always returns.
    pub async fn one(self, sql: &str, params: &[Param<'_>]) -> Result<Row> {
        self.first(sql, params).await?.ok_or(Error::Other("NoRowError"))
    }

    pub async fn execute(self, sql: &str, params: &[Param<'_>]) -> Result<u64> {
        match self {
            Q::Pool(pool) => {
                let conn = pool.get().await?;
                let statement = conn.prepare_cached(sql).await?;
                Ok(conn.execute(&statement, params).await?)
            }
            Q::Tx(tx) => {
                let conn = tx.conn();
                let statement = conn.prepare_cached(sql).await?;
                Ok(conn.execute(&statement, params).await?)
            }
        }
    }
}

type Effect = Box<dyn FnOnce() + Send>;

/// A transaction whose side effects outside Postgres (emails, alerts) run
/// only once it has committed, so nothing announces a change that rolled
/// back. Dropped without `commit` or `finish`, it rolls back.
pub struct Tx {
    conn: Option<Object>,
    effects: Mutex<Vec<Effect>>,
}

impl Tx {
    pub async fn begin(pool: &Pool) -> Result<Tx> {
        let conn = pool.get().await?;
        conn.batch_execute("BEGIN").await?;
        Ok(Tx { conn: Some(conn), effects: Mutex::new(Vec::new()) })
    }

    fn conn(&self) -> &Object {
        self.conn.as_ref().expect("the transaction is open")
    }

    pub fn q(&self) -> Q<'_> {
        Q::Tx(self)
    }

    /// Runs `effect` once the transaction has committed.
    pub fn after(&self, effect: impl FnOnce() + Send + 'static) {
        self.effects.lock().unwrap().push(Box::new(effect));
    }

    pub async fn commit(mut self) -> Result<()> {
        let conn = self.conn.take().expect("the transaction is open");
        if let Err(e) = conn.batch_execute("COMMIT").await {
            let _ = conn.batch_execute("ROLLBACK").await;
            return Err(e.into());
        }
        drop(conn);
        for effect in std::mem::take(&mut *self.effects.lock().unwrap()) {
            effect();
        }
        Ok(())
    }

    pub async fn rollback(mut self) {
        if let Some(conn) = self.conn.take() {
            let _ = conn.batch_execute("ROLLBACK").await;
        }
    }

    /// Commits when the work succeeded and rolls back when it failed, as
    /// `sql.begin(callback)` does with what its callback returns or throws.
    pub async fn finish<T>(self, outcome: Result<T>) -> Result<T> {
        match outcome {
            Ok(value) => {
                self.commit().await?;
                Ok(value)
            }
            Err(e) => {
                self.rollback().await;
                Err(e)
            }
        }
    }
}

impl Drop for Tx {
    fn drop(&mut self) {
        // A request that failed or was cancelled part-way: the connection goes
        // back to the pool only once its transaction is gone.
        if let Some(conn) = self.conn.take() {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    let _ = conn.batch_execute("ROLLBACK").await;
                });
            }
        }
    }
}

// Below the pool's 5, so stalled pings never take every connection.
const MAX_PINGS: usize = 2;

/// Answers within a bounded time, with at most MAX_PINGS queries in the pool.
///
/// A caller that stops waiting can't cancel its query, which keeps its place
/// in the pool until the database answers. So callers that arrive while a
/// query runs share it, and share one answer that settles when the query does
/// or when the timeout passes, whichever comes first. After a timeout the
/// next caller sends a fresh query, which another connection can answer when
/// only one is stuck; once MAX_PINGS are stuck, callers get the last
/// timed-out answer at once.
pub struct Pinger {
    pool: Pool,
    timeout: Duration,
    queries: Arc<AtomicUsize>,
    answer: Mutex<watch::Receiver<Option<bool>>>,
}

impl Pinger {
    pub fn new(pool: Pool, timeout: Duration) -> Pinger {
        let (_, settled) = watch::channel(Some(true));
        Pinger { pool, timeout, queries: Arc::new(AtomicUsize::new(0)), answer: Mutex::new(settled) }
    }

    pub async fn ping(&self) -> bool {
        let mut answer = {
            let mut current = self.answer.lock().unwrap();
            let answering = current.borrow().is_none();
            if !answering && self.queries.load(Ordering::SeqCst) < MAX_PINGS {
                let (tx, rx) = watch::channel(None);
                let tx = Arc::new(tx);
                self.queries.fetch_add(1, Ordering::SeqCst);
                let (pool, queries, done) = (self.pool.clone(), self.queries.clone(), tx.clone());
                tokio::spawn(async move {
                    let ok = async { Q::Pool(&pool).query("SELECT 1", &[]).await.is_ok() }.await;
                    queries.fetch_sub(1, Ordering::SeqCst);
                    done.send_if_modified(|v| v.is_none().then(|| *v = Some(ok)).is_some());
                });
                let timeout = self.timeout;
                tokio::spawn(async move {
                    tokio::time::sleep(timeout).await;
                    tx.send_if_modified(|v| v.is_none().then(|| *v = Some(false)).is_some());
                });
                *current = rx;
            }
            current.clone()
        };
        let settled = answer.wait_for(|v| v.is_some()).await.map(|v| *v);
        matches!(settled, Ok(Some(true)))
    }
}
