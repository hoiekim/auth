# auth

An identity and access service you can deploy anywhere, in front of whatever
apps you run: one account per person, one sign-in for every app they may use,
and one place to grant, change or remove that access. Apps speak a small subset
of OpenID Connect to it and verify its tokens locally, so serving a request
never waits on auth.

It covers what different kinds of app need:

- **Web apps**: sign-in by redirect, a role per app, and revocation that
  reaches open websockets and SSE streams.
- **Servers for password-only protocols** (IMAP, SMTP, CalDAV, WebDAV):
  scoped app passwords they check with auth.
- **APIs**: scoped API keys.
- **Native apps**: a public client with PKCE, and platform sign-in.
- **Apps with resources and members of their own** (workspaces, spaces,
  groups): the app keeps those and every role on them, while auth decides who
  may use the app at all, finds and invites people for it, and tells it when
  someone leaves.

auth is a product, not a deployment. Nothing in this repository names or
assumes a particular deployment or app. Each deployment's services, hostnames
and secrets are its own configuration (`docs/DESIGN.md` §2).

The design documents are the contract. Read them before changing behavior:

- [`docs/DESIGN.md`](docs/DESIGN.md): the principle, use cases, the access
  model, every endpoint, token and event, the schema, security, and how each
  kind of app integrates.
- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md): the image, releases, and what a
  deployment needs.

## Status

Phases 1 to 3 of [`docs/DESIGN.md`](docs/DESIGN.md) §13 are built:

- **Sign-in:** passwords (argon2id, breached-password check), TOTP, recovery
  codes and passkeys; SSO sessions, devices and sign-out.
- **OpenID Connect:** the authorization code flow with PKCE, refresh
  (rotated for public clients), revocation, introspection of app passwords
  and API keys, userinfo, logout, discovery and JWKS, with Ed25519 keys that
  rotate every 90 days.
- **Access:** the services file, one role per user per service, invitations,
  bot users, and the management API with its scoped calls for apps that
  manage their own members.
- **Events** to apps through a Postgres outbox; the audit log; alerts; rate
  limits shared across copies; hourly housekeeping.
- **Pages** for sign-in, sign-up, invitations, activation, reset, the account
  and administration; the break-glass CLI; and
  [`client/auth-client.ts`](client/auth-client.ts) for apps on Bun or Node.

Phase 4, platform sign-in through token exchange (§12.3), is designed but
not built, as §3 decides for v1.

## Configuration

Configuration comes from the environment only. The server refuses to start
when a value is missing or malformed, and lists every problem.
[`.env.example`](.env.example) has the same list, and
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) §3 what each means for a
deployment.

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `PORT` | no | `3000` | HTTP listen port |
| `DATABASE_URL` | yes | — | Postgres connection string for the auth database |
| `ISSUER_URL` | yes | — | auth's own origin, the tokens' `iss` |
| `SERVICES_FILE` | yes | — | Path to the services file (`docs/DESIGN.md` §6) |
| `AUTH_ENCRYPTION_KEY` | yes | — | 32 bytes, base64; encrypts signing keys and TOTP secrets |
| `API_KEY_PREFIX` | when a service has `api_key_scopes` | — | Prefix of API keys, for secret scanners |
| `TRUSTED_PROXIES` | no | none | IPs or CIDR ranges whose `X-Real-IP` is trusted |
| `SMTP_URL` | yes | — | `smtps://` or `smtp://` (STARTTLS) server for auth's emails |
| `EMAIL_FROM` | yes | — | The emails' sender |
| `AUDIT_RETENTION_DAYS` | no | `365` | Days of audit log kept |
| `ALLOW_ACCOUNT_DELETION` | no | `false` | Whether people may delete their own accounts |
| `ALERT_WEBHOOK_URL` | no | — | Webhook that receives alerts as `{"text": …}` |
| `TEST_DATABASE_URL` | tests only | — | A Postgres the database tests use; each test file makes and drops a schema of its own, and they skip without it |

## Development

Requires Bun 1.4.4, the version `packageManager` in `package.json` pins, and
Postgres 16.

```sh
bun install
cp .env.example .env    # then set DATABASE_URL, AUTH_ENCRYPTION_KEY, SERVICES_FILE
bun run dev             # restarts on change
bun run typecheck
TEST_DATABASE_URL=postgres://auth:auth@localhost:5432/auth bun test
```

`SMTP_URL` may point at a local mail catcher on a loopback port without TLS.
The first admin comes from the CLI, which prints an activation link:

```sh
bun cli.ts user create --username alice --email alice@example.com --access auth:admin --print-link
bun cli.ts client secret wiki    # a confidential client's secret, printed once
bun cli.ts help
```

## Contributing

1. **Start from an issue.** Each one cites the `docs/DESIGN.md` section it
   implements.
2. **Change the design first.** A change to the access model, an endpoint, a
   token or claim, an event, or the schema goes to `docs/DESIGN.md` in its
   own PR before any code depends on it.
3. **Open a PR against `main`.** Start the description with a
   `## Design alignment` section naming the sections it implements, then a
   summary. CI (typecheck; tests against Postgres; the image built, started
   and stopped) must be green.
4. **Migrations are expand-only.** Never edit or drop an applied migration;
   add a new one. During a deploy the previous image runs against the new
   schema.
5. **No secret in a log, an error or a response.** Passwords, codes, tokens,
   keys, cookies, `Authorization` headers and connection strings
   (`docs/DESIGN.md` §9.3).
6. **A product, not a deployment.** No code, default, test, CI step, doc,
   example or comment names or assumes a particular deployment or app: no real
   hostnames, domains, app names or figures from one setup. Examples use
   reserved names (`example.com`, `.test`, `.internal`, `wiki`, `alice`). Anything a
   deployment needs to differ is configuration. A feature is described by the
   kind of app that needs it, never by one app. The same holds for the apps
   that integrate with auth: they reach it through standard, configurable
   interfaces, never through knowledge of a particular deployment
   (`docs/DESIGN.md` §2).

Code review by agents follows [`AGENTS.md`](AGENTS.md).

## Security

Report vulnerabilities privately: see [`SECURITY.md`](SECURITY.md).

## License

[Apache License 2.0](LICENSE).
