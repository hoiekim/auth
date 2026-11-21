//! Plain SQL migrations, applied at start under an advisory lock so two copies
//! starting together apply each one once (docs/DESIGN.md §8). Each is
//! expand-only: the copy still running the previous image keeps working. The
//! files are ../src/migrations, the one copy both servers apply.

use deadpool_postgres::Pool;

use crate::error::Result;

include!(concat!(env!("OUT_DIR"), "/migrations.rs"));

pub async fn migrate(pool: &Pool, log: impl Fn(&str)) -> Result<()> {
    let conn = pool.get().await?;
    conn.batch_execute("SELECT pg_advisory_lock(hashtext('auth.migrate'))").await?;
    let applied = async {
        conn.batch_execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
               version    text PRIMARY KEY,
               applied_at timestamptz NOT NULL DEFAULT now()
             )",
        )
        .await?;
        let mut done: Vec<String> = Vec::new();
        for r in &conn.query("SELECT version FROM schema_migrations", &[]).await? {
            done.push(r.try_get("version")?);
        }
        for (version, text) in MIGRATIONS {
            if done.iter().any(|d| d == version) {
                continue;
            }
            conn.batch_execute("BEGIN").await?;
            let one: Result<()> = async {
                conn.batch_execute(text).await?;
                conn.execute("INSERT INTO schema_migrations (version) VALUES ($1)", &[version]).await?;
                Ok(())
            }
            .await;
            if let Err(e) = one {
                let _ = conn.batch_execute("ROLLBACK").await;
                return Err(e);
            }
            conn.batch_execute("COMMIT").await?;
            log(&format!("migration {version} applied"));
        }
        Ok(())
    }
    .await;
    let _ = conn.batch_execute("SELECT pg_advisory_unlock(hashtext('auth.migrate'))").await;
    applied
}
