//! Background work. Every copy runs it; Postgres decides who does what, so
//! nothing depends on which copy is up (docs/DESIGN.md §8).

use std::time::Duration;

use deadpool_postgres::Pool;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

use crate::app::App;
use crate::db::Tx;
use crate::error::Result;
use crate::events::deliver_due;
use crate::keys::rotate_keys;

/// Drops what has expired (§8 Housekeeping), in one copy at a time.
pub async fn housekeep(pool: &Pool, audit_retention_days: i32) -> Result<bool> {
    let tx = Tx::begin(pool).await?;
    let work = async {
        let q = tx.q();
        if !q.one("SELECT pg_try_advisory_xact_lock(hashtext('auth.housekeeping')) AS got", &[]).await?.try_get::<_, bool>("got")? {
            return Ok(false);
        }
        q.execute("DELETE FROM auth_codes WHERE expires_at < now() - interval '1 hour'", &[]).await?;
        q.execute("DELETE FROM one_time_tokens WHERE expires_at < now() - interval '1 day'", &[]).await?;
        q.execute("DELETE FROM sessions WHERE expires_at < now() OR ends_at < now()", &[]).await?;
        q.execute("DELETE FROM refresh_tokens WHERE expires_at < now() OR revoked_at < now() - interval '1 day'", &[]).await?;
        q.execute("DELETE FROM invites WHERE accepted_at IS NULL AND expires_at < now() - interval '30 days'", &[]).await?;
        q.execute("DELETE FROM throttle WHERE window_start < now() - interval '1 day'", &[]).await?;
        q.execute("DELETE FROM outbox WHERE delivered_at < now() - interval '7 days' OR failed_at < now() - interval '7 days'", &[]).await?;
        q.execute("DELETE FROM audit WHERE at < now() - make_interval(days => $1)", &[&audit_retention_days]).await?;
        Ok(true)
    }
    .await;
    tx.finish(work).await
}

const OUTBOX_EVERY: Duration = Duration::from_millis(1000);
const HOURLY: Duration = Duration::from_secs(60 * 60);

pub struct Jobs {
    stop: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl Jobs {
    /// Lets the pass in flight finish, and starts no other.
    pub async fn stop(self) {
        let _ = self.stop.send(true);
        for task in self.tasks {
            let _ = task.await;
        }
    }
}

pub fn start_jobs(app: &App) -> Jobs {
    let (stop, stopped) = watch::channel(false);

    let (outbox_app, mut outbox_stop) = (app.clone(), stopped.clone());
    let outbox = tokio::spawn(async move {
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + OUTBOX_EVERY, OUTBOX_EVERY);
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = outbox_stop.changed() => return,
            }
            if let Err(e) = deliver_due(&outbox_app, 20).await {
                outbox_app.log(&format!("outbox delivery failed: {}", e.name()));
            }
        }
    });

    let (hourly_app, mut hourly_stop) = (app.clone(), stopped);
    let hourly = tokio::spawn(async move {
        let mut tick = tokio::time::interval(HOURLY);
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = hourly_stop.changed() => return,
            }
            let pass: Result<()> = async {
                rotate_keys(&hourly_app.pool, &hourly_app.crypt).await?;
                housekeep(&hourly_app.pool, hourly_app.config.audit_retention_days).await?;
                Ok(())
            }
            .await;
            if let Err(e) = pass {
                hourly_app.log(&format!("housekeeping failed: {}", e.name()));
            }
        }
    });

    Jobs { stop, tasks: vec![outbox, hourly] }
}
