import type { MailMessage } from "./mail";

// The emails auth sends (docs/DESIGN.md §9.1, U13). A link carries a one-time
// token; nothing else in a message is secret.

export function activationEmail(issuer: string, to: string, username: string, token: string): MailMessage {
  return {
    to,
    subject: "Activate your account",
    text: [
      `An account with the username "${username}" was created for you.`,
      "",
      "Set your password with this link. It works once and expires in 14 days:",
      `${issuer}/activate?token=${token}`,
      "",
      "If you didn't expect this, ignore this message.",
    ].join("\n"),
  };
}

export function inviteEmail(issuer: string, to: string, service: string, token: string): MailMessage {
  return {
    to,
    subject: `You're invited to ${service}`,
    text: [
      `You've been invited to use ${service}.`,
      "",
      "Accept with this link, creating an account or using the one you have. It works once and expires in 14 days:",
      `${issuer}/invite?token=${token}`,
      "",
      "If you didn't expect this, ignore this message.",
    ].join("\n"),
  };
}

export function resetEmail(issuer: string, to: string, token: string): MailMessage {
  return {
    to,
    subject: "Reset your password",
    text: [
      "Someone asked to reset the password of the account that uses this address.",
      "",
      "Choose a new password with this link. It works once and expires in 30 minutes:",
      `${issuer}/reset/confirm?token=${token}`,
      "",
      "If it wasn't you, ignore this message: your password stays as it is.",
    ].join("\n"),
  };
}

export function verifyEmail(issuer: string, to: string, token: string): MailMessage {
  return {
    to,
    subject: "Confirm your email address",
    text: [
      "Confirm that this address is yours with this link. It works once and expires in 24 hours:",
      `${issuer}/verify-email?token=${token}`,
      "",
      "If you didn't ask for this, ignore this message.",
    ].join("\n"),
  };
}

// For a sign-up or address change to an address another account already
// uses: the requester sees the same answer either way, and the owner learns
// someone tried.
export function addressInUseEmail(to: string): MailMessage {
  return {
    to,
    subject: "Your address was used for another account",
    text: [
      "Someone tried to use this address for an account, but it already belongs to yours.",
      "Nothing changed. If it was you, sign in to the account you have.",
    ].join("\n"),
  };
}

export type SecurityChange =
  | "password changed"
  | "password reset"
  | "two-factor authentication added"
  | "two-factor authentication removed"
  | "recovery codes regenerated"
  | "a recovery code was used"
  | "a passkey was added"
  | "a passkey was removed"
  | "an app password was created"
  | "an API key was created"
  | "a sign-in from a new device"
  | "two-factor authentication was cleared by an administrator"
  | "your email address is changing";

export function securityNotice(to: string, username: string, change: SecurityChange, detail?: string): MailMessage {
  return {
    to,
    subject: `Security notice: ${change}`,
    text: [
      `On the account "${username}": ${change}.`,
      ...(detail ? ["", detail] : []),
      "",
      "If this wasn't you, reset your password and contact an administrator.",
    ].join("\n"),
  };
}
