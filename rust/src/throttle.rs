//! Rate limits (docs/DESIGN.md §9.4), counted in the shared `throttle` table so
//! every copy sees the same numbers and a restart doesn't reset them.

use crate::db::Q;
use crate::error::Result;

pub struct Verdict {
    pub allowed: bool,
    pub retry_after: i64,
}

/// A fixed window: `limit` hits per `window_seconds`, counted per key.
pub async fn hit(q: Q<'_>, key: &str, limit: i32, window_seconds: i64) -> Result<Verdict> {
    let window = window_seconds as f64;
    let row = q
        .one(
            "INSERT INTO throttle AS t (key, window_start, hits) VALUES ($1, now(), 1)
             ON CONFLICT (key) DO UPDATE SET
               window_start = CASE WHEN t.window_start <= now() - make_interval(secs => $2) THEN now() ELSE t.window_start END,
               hits = CASE WHEN t.window_start <= now() - make_interval(secs => $2) THEN 1 ELSE t.hits + 1 END
             RETURNING hits,
               GREATEST(1, ceil(extract(epoch FROM window_start + make_interval(secs => $2) - now())))::int AS retry_after",
            &[&key, &window],
        )
        .await?;
    let hits: i32 = row.try_get("hits")?;
    Ok(Verdict { allowed: hits <= limit, retry_after: i64::from(row.try_get::<_, i32>("retry_after")?) })
}

/// Sign-in failures per account: five, then one attempt a minute, doubling up
/// to fifteen minutes. There is no lockout, so nobody can lock another person
/// out; a success or a reset clears it.
pub async fn failure_wait(q: Q<'_>, key: &str) -> Result<Verdict> {
    let row = q
        .first(
            "SELECT GREATEST(0, ceil(extract(epoch FROM
                      window_start + make_interval(secs => LEAST(60 * power(2, hits - 5), 900)) - now())))::int AS wait
             FROM throttle WHERE key = $1 AND hits >= 5",
            &[&key],
        )
        .await?;
    let wait = match row {
        Some(r) => i64::from(r.try_get::<_, i32>("wait")?),
        None => 0,
    };
    Ok(Verdict { allowed: wait == 0, retry_after: wait })
}

pub async fn record_failure(q: Q<'_>, key: &str) -> Result<()> {
    q.execute(
        "INSERT INTO throttle AS t (key, window_start, hits) VALUES ($1, now(), 1)
         ON CONFLICT (key) DO UPDATE SET window_start = now(), hits = t.hits + 1",
        &[&key],
    )
    .await?;
    Ok(())
}

pub async fn clear(q: Q<'_>, key: &str) -> Result<()> {
    q.execute("DELETE FROM throttle WHERE key = $1", &[&key]).await?;
    Ok(())
}

/// True the first time a key is seen: a WebAuthn challenge used once.
/// Housekeeping drops the row after a day, longer than anything it guards lives.
pub async fn once(q: Q<'_>, key: &str) -> Result<bool> {
    let rows = q.query("INSERT INTO throttle (key, window_start, hits) VALUES ($1, now(), 1) ON CONFLICT (key) DO NOTHING RETURNING key", &[&key]).await?;
    Ok(rows.len() == 1)
}

/// The hits counted under a key in its current window, without adding one:
/// for limits that count failures only.
pub async fn peek(q: Q<'_>, key: &str, limit: i32, window_seconds: i64) -> Result<Verdict> {
    let window = window_seconds as f64;
    let row = q
        .first(
            "SELECT hits, GREATEST(1, ceil(extract(epoch FROM window_start + make_interval(secs => $2) - now())))::int AS retry_after
             FROM throttle WHERE key = $1 AND window_start > now() - make_interval(secs => $2)",
            &[&key, &window],
        )
        .await?;
    Ok(match row {
        Some(r) => Verdict { allowed: r.try_get::<_, i32>("hits")? < limit, retry_after: i64::from(r.try_get::<_, i32>("retry_after")?) },
        None => Verdict { allowed: true, retry_after: 0 },
    })
}
