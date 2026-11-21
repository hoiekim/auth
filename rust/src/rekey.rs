//! Re-encryption after the encryption key changes (docs/DESIGN.md §9.3): every
//! TOTP secret and private signing key, each under its row id as additional
//! data, moves to the current key. Each row is rewritten in a transaction of
//! its own under a row lock, so the server can keep running alongside.

use std::collections::BTreeMap;

use deadpool_postgres::Pool;

use crate::crypto::Encrypter;
use crate::db::{Q, Tx};
use crate::error::Result;

struct Column {
    label: &'static str,
    ids: &'static str,
    read: &'static str,
    write: &'static str,
}

const COLUMNS: [Column; 2] = [
    Column {
        label: "TOTP secrets",
        ids: "SELECT user_id AS id FROM totp ORDER BY user_id",
        read: "SELECT secret_enc AS sealed FROM totp WHERE user_id = $1 FOR UPDATE",
        write: "UPDATE totp SET secret_enc = $2 WHERE user_id = $1",
    },
    Column {
        label: "signing keys",
        ids: "SELECT kid AS id FROM signing_keys ORDER BY kid",
        read: "SELECT private_key_enc AS sealed FROM signing_keys WHERE kid = $1 FOR UPDATE",
        write: "UPDATE signing_keys SET private_key_enc = $2 WHERE kid = $1",
    },
];

async fn ids(q: Q<'_>, column: &Column) -> Result<Vec<String>> {
    q.query(column.ids, &[]).await?.iter().map(|r| Ok(r.try_get("id")?)).collect()
}

async fn read(q: Q<'_>, column: &Column, id: &str) -> Result<Option<Vec<u8>>> {
    match q.first(column.read, &[&id]).await? {
        Some(r) => Ok(Some(r.try_get("sealed")?)),
        None => Ok(None),
    }
}

pub struct ColumnStatus {
    pub label: &'static str,
    /// Rows per key version.
    pub by_version: BTreeMap<u32, usize>,
    /// Rows with no version at all.
    pub unversioned: usize,
    /// Rows whose version has no configured key.
    pub unreadable: usize,
}

pub async fn encryption_status(pool: &Pool, crypt: &Encrypter) -> Result<Vec<ColumnStatus>> {
    let q = Q::Pool(pool);
    let mut out = Vec::new();
    for column in &COLUMNS {
        let mut status = ColumnStatus { label: column.label, by_version: BTreeMap::new(), unversioned: 0, unreadable: 0 };
        for id in ids(q, column).await? {
            let Some(sealed) = read(q, column, &id).await? else { continue };
            match Encrypter::version_of(&sealed) {
                Some(version) => {
                    *status.by_version.entry(version).or_default() += 1;
                    if !crypt.versions().contains(&version) {
                        status.unreadable += 1;
                    }
                }
                None => {
                    status.unversioned += 1;
                    status.unreadable += 1;
                }
            }
        }
        out.push(status);
    }
    Ok(out)
}

pub struct ColumnResult {
    pub label: &'static str,
    pub rewritten: usize,
    pub current: usize,
    /// Rows no configured key could read, left as they were.
    pub failed: Vec<String>,
}

enum Outcome {
    Gone,
    Current,
    Failed,
    Rewritten,
}

pub async fn reencrypt(pool: &Pool, crypt: &Encrypter) -> Result<Vec<ColumnResult>> {
    let mut out = Vec::new();
    for column in &COLUMNS {
        let mut result = ColumnResult { label: column.label, rewritten: 0, current: 0, failed: Vec::new() };
        for id in ids(Q::Pool(pool), column).await? {
            let tx = Tx::begin(pool).await?;
            let work = async {
                let Some(sealed) = read(tx.q(), column, &id).await? else { return Ok(Outcome::Gone) };
                if Encrypter::version_of(&sealed) == Some(crypt.version()) {
                    return Ok(Outcome::Current);
                }
                let Ok(plaintext) = crypt.decrypt(&sealed, &id) else { return Ok(Outcome::Failed) };
                tx.q().execute(column.write, &[&id, &crypt.encrypt(&plaintext, &id)]).await?;
                Ok(Outcome::Rewritten)
            }
            .await;
            match tx.finish(work).await? {
                Outcome::Rewritten => result.rewritten += 1,
                Outcome::Current => result.current += 1,
                Outcome::Failed => result.failed.push(id),
                Outcome::Gone => {}
            }
        }
        out.push(result);
    }
    Ok(out)
}
