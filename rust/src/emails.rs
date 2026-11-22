//! The emails auth sends (docs/DESIGN.md §9.1, U13). A link carries a one-time
//! token; nothing else in a message is secret.

use crate::mail::MailMessage;

fn message(to: &str, subject: String, lines: &[&str]) -> MailMessage {
    MailMessage { to: to.to_string(), subject, text: lines.join("\n") }
}

pub fn activation_email(issuer: &str, to: &str, username: &str, token: &str) -> MailMessage {
    message(
        to,
        "Activate your account".into(),
        &[
            &format!("An account with the username \"{username}\" was created for you."),
            "",
            "Set your password with this link. It works once and expires in 14 days:",
            &format!("{issuer}/activate?token={token}"),
            "",
            "If you didn't expect this, ignore this message.",
        ],
    )
}

pub fn invite_email(issuer: &str, to: &str, service: &str, token: &str) -> MailMessage {
    message(
        to,
        format!("You're invited to {service}"),
        &[
            &format!("You've been invited to use {service}."),
            "",
            "Accept with this link, creating an account or using the one you have. It works once and expires in 14 days:",
            &format!("{issuer}/invite?token={token}"),
            "",
            "If you didn't expect this, ignore this message.",
        ],
    )
}

pub fn reset_email(issuer: &str, to: &str, token: &str) -> MailMessage {
    message(
        to,
        "Reset your password".into(),
        &[
            "Someone asked to reset the password of the account that uses this address.",
            "",
            "Choose a new password with this link. It works once and expires in 30 minutes:",
            &format!("{issuer}/reset/confirm?token={token}"),
            "",
            "If it wasn't you, ignore this message: your password stays as it is.",
        ],
    )
}

pub fn verify_email(issuer: &str, to: &str, token: &str) -> MailMessage {
    message(
        to,
        "Confirm your email address".into(),
        &[
            "Confirm that this address is yours with this link. It works once and expires in 24 hours:",
            &format!("{issuer}/verify-email?token={token}"),
            "",
            "If you didn't ask for this, ignore this message.",
        ],
    )
}

/// For a sign-up or address change to an address another account already
/// uses: the requester sees the same answer either way, and the owner learns
/// someone tried.
pub fn address_in_use_email(to: &str) -> MailMessage {
    message(
        to,
        "Your address was used for another account".into(),
        &["Someone tried to use this address for an account, but it already belongs to yours.", "Nothing changed. If it was you, sign in to the account you have."],
    )
}

/// `change` is one of the security changes of U13, as the subject words it:
/// "password changed", "a passkey was added", …
pub fn security_notice(to: &str, username: &str, change: &str, detail: Option<&str>) -> MailMessage {
    let first = format!("On the account \"{username}\": {change}.");
    let mut lines: Vec<&str> = vec![&first];
    if let Some(d) = detail.filter(|d| !d.is_empty()) {
        lines.push("");
        lines.push(d);
    }
    lines.push("");
    lines.push("If this wasn't you, reset your password and contact an administrator.");
    message(to, format!("Security notice: {change}"), &lines)
}
