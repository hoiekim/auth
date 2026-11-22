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
- **Access:** services registered on the admin page or declared in a
  services file, one role per user per service, invitations,
  bot users, and the management API with its scoped calls for apps that
  manage their own members.
- **Events** to apps through a Postgres outbox; the audit log; alerts; rate
  limits shared across copies; hourly housekeeping.
- **Pages** for sign-in, sign-up, invitations, activation, reset, the account
  and administration; the break-glass CLI; and
  [`client/auth-client.ts`](client/auth-client.ts) for apps on Bun or Node.

Phase 4, platform sign-in through token exchange (§12.3), is designed but
not built, as §3 decides for v1.

## Two servers

The service is written twice, side by side (`docs/DESIGN.md` §16):

- [`src/`](src): TypeScript on Bun, with no runtime dependencies. Its image
  is [`Dockerfile`](Dockerfile); its break-glass CLI is `bun cli.ts`.
- [`rust/`](rust): Rust. Its image is [`rust/Dockerfile`](rust/Dockerfile);
  its break-glass CLI is `auth cli`.

Both implement the same design, read the same configuration, and use the same
database: the migrations in `src/migrations` and the pages' assets in
`src/assets` are the one copy each applies and serves. What one writes the
other reads, so a deployment can move from one to the other, and back, with an
ordinary rolling deploy.

[`conformance/`](conformance) holds them to the same behaviour: tests that
start a server as a process and reach it only over HTTP, SMTP, the CLI and
Postgres, so the same files run against either
(`AUTH_BACKEND=bun`, the default, or `rust`), and
[`conformance/mixed.test.ts`](conformance/mixed.test.ts) runs a copy of each
on one database.

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
| `SERVICES_FILE` | no | none | Path to a services file, whose services are read-only on the admin page (`docs/DESIGN.md` §6.2) |
| `AUTH_ENCRYPTION_KEY` | yes | — | 32 bytes, base64, optionally as `v<N>:<base64>`; encrypts signing keys and TOTP secrets |
| `AUTH_DECRYPTION_KEYS` | during a key rotation | — | Other keys, `v<N>:<base64>`, comma-separated, that only decrypt |
| `API_KEY_PREFIX` | when a service has `api_key_scopes` | — | Prefix of API keys, for secret scanners |
| `TRUSTED_PROXIES` | no | none | IPs or CIDR ranges whose `X-Real-IP` is trusted |
| `SMTP_URL` | yes | — | `smtps://` or `smtp://` (STARTTLS) server for auth's emails |
| `EMAIL_FROM` | yes | — | The emails' sender |
| `AUDIT_RETENTION_DAYS` | no | `365` | Days of audit log kept |
| `ALLOW_ACCOUNT_DELETION` | no | `false` | Whether people may delete their own accounts |
| `ALERT_WEBHOOK_URL` | no | — | Webhook that receives alerts as `{"text": …}` |
| `BREACHED_PASSWORDS_URL` | no | `https://api.pwnedpasswords.com/range` | The range API the breached-password check asks, for a deployment that mirrors it |
| `TEST_DATABASE_URL` | tests only | — | A Postgres the database tests use; each test file makes and drops a schema of its own, and they skip without it |
| `AUTH_BACKEND` | tests only | `bun` | Which server `conformance/` starts: `bun` or `rust` |

## Development

Requires Bun 1.4.4, the version `packageManager` in `package.json` pins, and
Postgres 16; the Rust server also needs rustup.

```sh
bun install
cp .env.example .env    # then set DATABASE_URL and AUTH_ENCRYPTION_KEY
bun run dev             # restarts on change
bun run typecheck
TEST_DATABASE_URL=postgres://auth:auth@localhost:5432/auth bun test
```

The Rust server needs the toolchain `rust/rust-toolchain.toml` pins, which
rustup installs by itself:

```sh
set -a; . ./.env; set +a            # it reads no .env file of its own
cd rust
cargo run --release                 # the server, configured by the same environment
cargo run --release -- cli help     # its break-glass CLI
cargo fmt --check && cargo clippy --release -- -D warnings && cargo test --release
cd ..
TEST_DATABASE_URL=postgres://auth:auth@localhost:5432/auth bun run test:rust   # builds it, then runs conformance/ against it
bun rust/tests/database_urls.ts --check   # Bun still reads each DATABASE_URL case as recorded
```

`bun test` runs `conformance/` against the Bun server, with the unit tests.
Once the Rust server is built, `conformance/mixed.test.ts` also starts a copy
of it beside the server under test.

`SMTP_URL` may point at a local mail catcher on a loopback port without TLS.
The first admin comes from the CLI, which prints an activation link:

```sh
bun cli.ts user create --username alice --email alice@example.com --access auth:admin --print-link
bun cli.ts client secret wiki    # a confidential client's secret, printed once (the admin page makes a registered client's)
bun cli.ts import users users.jsonl --dry-run
bun cli.ts help
```

## Contributing

1. **An issue is optional.** A PR can stand on its own. An issue, when there
   is one, cites the `docs/DESIGN.md` section it implements.
2. **The design changes with the code, never after it.** A change to the
   access model, an endpoint, a token or claim, an event, or the schema
   updates `docs/DESIGN.md` in the same PR as the code, or in a PR merged
   before it.
3. **Open a PR against `main`.** Start the description with a
   `## Design alignment` section naming the sections it implements or
   changes, then a summary. CI (typecheck; tests against Postgres; for the
   Rust server, format, lint, unit tests and the conformance suite; each
   image built, started and stopped) must be green.
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

7. **One behaviour, two servers.** A change to what the service does is made
   in `src/` and in `rust/` in the same PR, with a test in `conformance/`
   that both pass: status, error text, headers, what is written to the
   database, events, emails and CLI output. A format either server stores or
   hands out (a hash, a ciphertext, a sealed cookie, a token) changes in both
   at once, or not at all: the other must read it during a deploy.

Code review by agents follows [`AGENTS.md`](AGENTS.md).

## Security

Report vulnerabilities privately: see [`SECURITY.md`](SECURITY.md).

## License

[Apache License 2.0](LICENSE).
