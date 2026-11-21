//! Postgres: a pool of five connections (docs/DESIGN.md §10), transactions
//! whose outside effects wait for the commit, and the health check's ping.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use deadpool_postgres::{Manager, ManagerConfig, Object, Pool, RecyclingMethod};
use tokio::sync::watch;
use tokio_postgres::types::ToSql;
use tokio_postgres::Row;

use crate::error::{Error, Result};

pub type Param<'a> = &'a (dyn ToSql + Sync);

/// Whether the connection string can be used at all: reported with the other
/// configuration problems instead of failing the start after them.
pub fn parses_as_database_url(url: &str) -> bool {
    url.parse::<tokio_postgres::Config>().is_ok()
}

pub fn connect(url: &str) -> std::result::Result<Pool, Error> {
    let config: tokio_postgres::Config = url.parse().map_err(|_| Error::Other("ConfigError"))?;
    let recycle = ManagerConfig { recycling_method: RecyclingMethod::Fast };
    let manager = match config.get_ssl_mode() {
        tokio_postgres::config::SslMode::Disable | tokio_postgres::config::SslMode::Prefer => Manager::from_config(config, tokio_postgres::NoTls, recycle),
        _ => Manager::from_config(config, tokio_postgres_rustls::MakeRustlsConnect::new(crate::tls::client_config()), recycle),
    };
    Pool::builder(manager).max_size(5).build().map_err(|_| Error::Other("PoolError"))
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
