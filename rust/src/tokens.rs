//! One-time tokens (docs/DESIGN.md §7.3): reset 30 minutes, email
//! verification 24 hours, activation 14 days like an invitation. Single use,
//! stored as SHA-256.

use crate::crypto::{random_token, sha256};
use crate::db::Q;
use crate::error::Result;
use crate::throttle::{hit, Verdict};
use crate::util::utf16_len;

#[derive(Clone, Copy, PartialEq)]
pub enum Purpose {
    Reset,
    VerifyEmail,
    Activate,
}

impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Purpose::Reset => "reset",
            Purpose::VerifyEmail => "verify_email",
            Purpose::Activate => "activate",
        }
    }

    fn lifetime_seconds(self) -> f64 {
        match self {
            Purpose::Reset => 30.0 * 60.0,
            Purpose::VerifyEmail => 24.0 * 60.0 * 60.0,
            Purpose::Activate => 14.0 * 24.0 * 60.0 * 60.0,
        }
    }
}

pub async fn issue_token(q: Q<'_>, purpose: Purpose, user_id: &str, email: Option<&str>) -> Result<String> {
    let token = random_token();
    q.execute(
        "INSERT INTO one_time_tokens (token_hash, purpose, user_id, email, expires_at) VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))",
        &[&sha256(token.as_bytes()), &purpose.as_str(), &user_id, &email, &purpose.lifetime_seconds()],
    )
    .await?;
    Ok(token)
}

pub struct TokenRow {
    pub user_id: String,
    pub email: Option<String>,
}

/// The hash a presented token is looked up by; an over-long one matches nothing.
pub fn token_hash(token: Option<&str>) -> Vec<u8> {
    sha256(token.filter(|t| !t.is_empty() && utf16_len(t) <= 128).unwrap_or("").as_bytes())
}

fn row(r: Option<tokio_postgres::Row>) -> Result<Option<TokenRow>> {
    Ok(match r {
        Some(r) => Some(TokenRow { user_id: r.try_get("user_id")?, email: r.try_get("email")? }),
        None => None,
    })
}

/// A live token without using it up: to show the form it leads to.
pub async fn peek_token(q: Q<'_>, purpose: Purpose, token: Option<&str>) -> Result<Option<TokenRow>> {
    row(q
        .first(
            "SELECT user_id, email FROM one_time_tokens WHERE token_hash = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > now()",
            &[&token_hash(token), &purpose.as_str()],
        )
        .await?)
}

/// Uses a token up, once, however many requests race for it.
pub async fn consume_token(q: Q<'_>, purpose: Purpose, token: Option<&str>) -> Result<Option<TokenRow>> {
    row(q
        .first(
            "UPDATE one_time_tokens SET used_at = now()
             WHERE token_hash = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > now()
             RETURNING user_id, email",
            &[&token_hash(token), &purpose.as_str()],
        )
        .await?)
}

/// Reset, invite and sign-up emails: 3 an hour per address, 10 an hour per
/// sender (§9.4), counted whether or not the address has an account.
pub async fn email_allowed(q: Q<'_>, address: &str, sender: &str) -> Result<Verdict> {
    let per_address = hit(q, &format!("mail:to:{}", address.to_lowercase()), 3, 3600).await?;
    let per_sender = hit(q, &format!("mail:from:{sender}"), 10, 3600).await?;
    Ok(if per_address.allowed { per_sender } else { per_address })
}
