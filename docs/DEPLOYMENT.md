# Deployment

How the image is built and released, and what any deployment of it needs.
`docs/DESIGN.md` §11 sets the requirements this follows. Everything that
differs between deployments (the issuer URL, its services, secrets,
limits) is the deployment's own configuration (`docs/DESIGN.md` §2).

## 1. The image

`Dockerfile` builds it in two stages:

- **Builder**, on `oven/bun:1.4.4`: installs from `bun.lock`, runs
  `bun run typecheck` and `bun test`, then deletes the test files and
  their helpers in `src/testing`. The
  database tests skip here, with no `TEST_DATABASE_URL`; CI runs them, and CD
  publishes only commits whose CI passed.
- **Runtime**, on `oven/bun:1.4.4-slim`: installs production dependencies
  only and copies `src` and the break-glass `cli.ts`, all owned by root, and runs as `bun`, which can read
  the code but not change it. The server runs under `bun --no-install`, so
  an import that isn't in `node_modules` fails instead of fetching a package
  at run time.

**It runs from source** (`bun src/index.ts`), with no bundle step. Bun's
bundler replaces `process.env.NODE_ENV` with a constant at build time, so a
bundled server decides anything that reads it when the image is built, not
when it runs. The service reads no `NODE_ENV` at all, and sets
`development: false` on `Bun.serve` itself, since Bun would otherwise derive
that from `NODE_ENV`.

**The Rust server's image.** `rust/Dockerfile` builds the other
implementation of the service (`docs/DESIGN.md` §16), from the repository
root: `docker build -f rust/Dockerfile .`. Its builder, on
`rust:1.97.0-slim-bookworm` (the version `rust/rust-toolchain.toml` pins),
runs the unit tests and compiles one binary from `Cargo.lock`'s exact
dependencies, with the migrations and assets of `src/` built in; its runtime,
on `debian:bookworm-slim`, holds that binary alone, owned by root and run as
`nobody`. `auth` is the server, `auth cli <command>` the break-glass CLI, and
`auth healthcheck` what its `HEALTHCHECK` runs. Everything else in this
document holds for both images: the environment, health, stopping, the
database and the network. CD publishes the Bun image only; a deployment that
wants the Rust one builds it.

**Health.** `HEALTHCHECK` runs `GET /healthz` every 30 seconds. It answers
200 when the database answers within two seconds, and 503 otherwise. At
start the server applies pending migrations under an advisory lock and
makes sure a signing key exists; until then `/healthz` answers 503 and every
other request 503 with `Retry-After`, so a copy starting before Postgres
waits for it rather than exiting.

**Stopping.** On SIGTERM the server stops accepting connections, finishes
the requests in flight, closes its database pool and exits 0. The `CMD` is
in exec form, so `bun` is PID 1 and receives the signal. CI's `image` job
checks this on every PR: it starts the image with a services file, waits for
its own `HEALTHCHECK` to report healthy, runs the CLI inside it, and stops
it. The `rust-image` job does the same for the Rust server's image.

## 2. Releases

1. A PR merges to `main`.
2. CI runs on the push. Once it passes, CD builds `main`'s tip, pushes it to
   Docker Hub as `<namespace>/auth:latest` and `<namespace>/auth:sha-<short sha>`
   (the namespace is the account the CD secrets below name), and records the
   image digest in the run's summary.
3. When the repository has a `DEPLOY_URL` secret, CD then POSTs
   `{"sha", "digest", "repo"}` to it, `digest` being the image it just
   pushed, with `Authorization: Bearer <DEPLOY_SECRET>`, and waits for the
   answer. A refused or cut connection, 409, 502 and 504 are retried a
   minute apart, up to 10 tries; any other answer than 2xx fails the run.
   Only the status is printed, never the URL or the response. Without
   `DEPLOY_URL`, CD stops after publishing.

**The deploy hook.** What CD expects of the endpoint behind `DEPLOY_URL`:

- It deploys `<namespace>/auth@<digest>`, the image this run built. A hook
  that pulls `latest` instead runs whatever the tag holds when it pulls, so
  anyone who can push to the namespace can put an image there; for that
  deployment, the Docker Hub credential is as sensitive as the right to
  merge here.
- It answers when the deploy has ended: 2xx only if it succeeded, any
  other status if it failed.
- It answers 409 while another deploy is in flight.
- It finishes or gives up within 660 seconds, when CD stops waiting and
  fails the run without retrying.
- A repeated POST with the same digest is safe to deploy again: CD retries
  after a refused or cut connection, 502 and 504, any of which can follow a
  POST the hook already acted on.

A deployment chooses how releases reach it (`docs/DESIGN.md` §11):

- **Following releases**, with a hook behind `DEPLOY_URL` that deploys
  the posted digest and replaces its copies: every release that passes CI
  goes live minutes after its merge, so a merge here is a deploy, and this
  repository's review rules (§4) are what stand between a change and it.
- **Pinned by digest**: the deployment pulls the image it chooses and
  upgrades by moving the pin in its own configuration, where it reviews the
  change. A push to this repository can't reach it on its own.

**Rolling back.** Following releases, revert the change here, which
releases and deploys the code before it, or pin the previous digest until a
fix lands. Pinned, move the pin back. Migrations are expand-only, so the
previous image runs against the newer schema either way. An image from
before services could be registered on the admin page reads only the
services file: before rolling back to one, declare the registered services
in the file, or their apps stop signing people in.

CD's repository secrets: `DOCKER_HUB_USERNAME`, and `DOCKER_HUB_ACCESS_TOKEN`,
a Docker Hub access token that can push to the `auth` repository; and, to
deploy, `DEPLOY_URL` and `DEPLOY_SECRET`, the deployment's hook and its
bearer token.

## 3. What the runtime needs

### Environment

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `PORT` | no | `3000` (the image sets it) | HTTP listen port |
| `DATABASE_URL` | yes | — | Postgres connection string for the auth database: TLS and other parameters below |
| `ISSUER_URL` | yes | — | The issuer: the https origin browsers and apps reach auth at, with no path. It is every token's `iss` and the passkeys' RP ID, so changing it signs everyone out and invalidates every passkey. |
| `SERVICES_FILE` | no | none | Path to a services file inside the container (below) |
| `AUTH_ENCRYPTION_KEY` | yes | — | 32 random bytes, base64 (`openssl rand -base64 32`), optionally written `v<N>:<base64>` to give it a version (a bare key is version 1). Encrypts signing keys and TOTP secrets at rest. Keep a copy offline: a restored backup is useless without it. |
| `AUTH_DECRYPTION_KEYS` | during a key rotation | — | Other keys, `v<N>:<base64>`, comma-separated, that decrypt but never encrypt (below) |
| `API_KEY_PREFIX` | when a service declares `api_key_scopes` | — | The first part of every API key (`[a-z][a-z0-9]{1,15}`), so the deployment can register the pattern with a secret scanner |
| `TRUSTED_PROXIES` | no | none | The proxy's addresses, as IPs or CIDR ranges, comma-separated. Only these may set `X-Real-IP`. Behind a proxy, leaving it out puts every client in one rate-limit bucket. |
| `SMTP_URL` | yes | — | `smtps://user:password@host[:465]`, or `smtp://…[:587]` with STARTTLS required. Plain SMTP only to a loopback host. |
| `EMAIL_FROM` | yes | — | The sender of auth's emails: `auth@example.com` or `Example Auth <auth@example.com>` |
| `AUDIT_RETENTION_DAYS` | no | `365` | Days of audit log kept; lower it under a shorter retention rule |
| `ALLOW_ACCOUNT_DELETION` | no | `false` | `true` lets people delete their own accounts (U14), for example where a store requires it |
| `ALERT_WEBHOOK_URL` | no | — | An http(s) URL that receives `{"text": "…"}` on every change an `auth:admin` makes through the administration endpoints (`docs/DESIGN.md` §7.5), which the admin page calls; every change to who administers auth; every change the break-glass CLI makes to users, access, secrets, encryption or imported data; a held copy of a service taking effect; a reused refresh token; and every event given up (after 24 hours, or at its next attempt once its service has no `events_url`) |
| `BREACHED_PASSWORDS_URL` | no | `https://api.pwnedpasswords.com/range` | The range API the breached-password check asks (`docs/DESIGN.md` §9.1), as `<URL>/<five hex characters of the SHA-1>`: an http(s) URL without credentials, a query or a fragment. A deployment sets it to its own mirror of the public API. |

Secrets (`DATABASE_URL`, `AUTH_ENCRYPTION_KEY` and `AUTH_DECRYPTION_KEYS`, the password in `SMTP_URL`,
a token in `ALERT_WEBHOOK_URL`) come from the deployment's secret store into
the environment, never from the image or the database.

### Connecting to Postgres

`DATABASE_URL` is `postgres://user:password@host:port/database`, with
anything in it percent-encoded, and these query parameters:

- **`sslmode`**, for TLS to Postgres: `disable`, the default, never asks
  for it; `prefer` (or `allow`) takes it when the server offers it;
  `require` insists on it. None of these three checks the server's
  certificate. `verify-ca` checks that it chains to a trusted root, and
  `verify-full` that it also names the host. Anything else refuses the
  start.
- **`sslrootcert=<file>`** makes that PEM file the only root trusted, and
  means `verify-full` unless `sslmode` says `verify-ca`; it can be the
  server's own self-signed certificate, made as Postgres's documentation
  shows (`openssl req -x509 …`). `sslrootcert=system` checks against the
  usual roots instead: the public ones, the host's store, `SSL_CERT_FILE`,
  and the PEM file `NODE_EXTRA_CA_CERTS` names, which is where a private CA
  goes. A certificate with no DNS names may name the host in its common
  name. A file that can't be read fails each connection, not the start.
- **`sslcert=<file>&sslkey=<file>`** shows a client certificate, and asks
  for TLS.
- **`application_name`**, and any other parameter that isn't the client's
  own (`statement_timeout=5000`, `search_path=…`), goes to Postgres as a
  setting for every connection.
- `connect_timeout` (seconds, default 30, `0` for none), `idle_timeout` and
  `max_lifetime` (seconds) for the pool's connections; `channel_binding`
  (`disable`, the default, `prefer` or `require`); and `host`, `port`,
  `user`, `password` and `dbname`, which win over the URL's own.
  libpq's keywords for its own connection (`keepalives`,
  `target_session_attrs` and the like) are read past.

What the URL leaves out comes from `PGHOST`, `PGPORT`, `PGUSER`,
`PGPASSWORD`, `PGSSLMODE`, `PGAPPNAME`, `PGOPTIONS`, `PGCONNECT_TIMEOUT` and
`PGCHANNELBINDING`; `PGDATABASE`, though, wins over the URL's database. A
host that is a directory (`?host=/var/run/postgresql`) is a Unix socket,
where there is no TLS. Over any network the deployment doesn't control,
use `verify-full`.

### Services

An `auth:admin` registers each app as a service on the admin page's
Services tab (`docs/DESIGN.md` §6.2), with no shell on the host and no
restart. The tab then makes each confidential client's secret and shows it
once, with the other settings the app needs: the issuer, the client id, the
redirect URI and the audience. Every change reaches every copy at its next
request, needs a sign-in in the last 15 minutes with a second factor, and is
audited and alerted.

A deployment that keeps its services in configuration it reviews elsewhere
can declare some or all of them in a services file instead: a JSON file kept
with its own configuration and mounted read-only, for example at
`/etc/auth/services.json`, named by `SERVICES_FILE`. `docs/DESIGN.md` §6
defines its fields; the server checks it at start and refuses to start on
any problem, listing all of them. Its services are read-only on the admin
page and change with a restart, and their clients' secrets come from the
CLI, so they are out of an admin's reach.

To move a service from the file to the admin page with no outage, use
**Copy to the admin page** on its card: the copy is held while the file
still declares the service. Then remove it from the file and restart; the
copy takes over, and access, credentials and client secrets carry over. To
pin one the other way, add it to the file and restart, then delete the held
copy.

### First admin and client secrets

Run the CLI inside a running container (`docker exec <container> bun cli.ts
…`). Every change it makes to users, access, secrets, encryption or imported
data is audited as `host-cli` and alerted. Every command but `help` applies
pending migrations first, which is neither audited nor alerted.

```sh
bun cli.ts user create --username alice --email alice@example.com --access auth:admin
```

It emails an activation link (add `--print-link` to print it instead when
email isn't working yet). The admin then sets a password, signs in and
enrolls a second factor, which `auth:admin` always requires, and registers
services from there.

A registered service's confidential client gets its secret on the admin
page; a services file client gets its secret from
`bun cli.ts client secret wiki`, which prints it once (the CLI makes either
kind). To rotate one, make a new one, move the app to it, then retire the
old one: **Retire older** on the admin page, or
`bun cli.ts client retire-old-secrets wiki`.

### Rotating the encryption key

Every ciphertext carries its key's version (`docs/DESIGN.md` §9.3). A
rotation is four deploys, so the two copies of a rolling deploy can always
read what the other writes. With the current key at version 1 and a new key
made with `openssl rand -base64 32`:

1. Add `AUTH_DECRYPTION_KEYS=v2:<new key>` and deploy. Nothing is written
   under the new key yet, but every copy can read it.
2. Set `AUTH_ENCRYPTION_KEY=v2:<new key>` and
   `AUTH_DECRYPTION_KEYS=v1:<old key>`, and deploy. New secrets are written
   under version 2.
3. Run `bun cli.ts encryption reencrypt` in a running container. It rewrites
   every TOTP secret and private signing key under version 2, and lists any
   value no configured key reads (it exits 1 then, and leaves the value as it
   was). `bun cli.ts encryption status` should then show only `v2`.
4. Remove `AUTH_DECRYPTION_KEYS` and deploy. Keep the old key offline for as
   long as you keep backups taken before step 3: restoring one needs it.

Signed-in users stay signed in throughout: CSRF tokens and the short-lived
values handed to browsers are accepted under every configured key.

### Moving existing users and API keys

An app's users, with their password hashes, and its API keys can be
imported instead of re-created (`docs/DESIGN.md` §12.5, §13). Both commands
read JSON Lines, one object per line, from a file in the container or from
standard input (`-`), so a file on the operator's machine can be piped in:

```sh
docker exec -i <container> bun cli.ts import users - --dry-run < users.jsonl
docker exec -i <container> bun cli.ts import users - < users.jsonl
docker exec -i <container> bun cli.ts import api-keys --service tasks - < keys.jsonl
```

- **Users:** `{"username", "email", "name"?, "email_verified"?, "password_hash"?, "access"?: {"<service>": "<role>"}}`.
  `password_hash` is an argon2 or bcrypt PHC string, which the first sign-in
  rehashes to today's parameters. Until then it is verified at its own cost,
  so only argon2 (`argon2id`, `argon2i` or `argon2d`) with at most
  `m=19456`, `t=3` and `p=4`, and bcrypt with a cost of at most 12, are
  taken (PHP's and some frameworks' argon2 defaults use more memory or
  parallelism); a bcrypt hash is checked against the password's first 72 bytes,
  as standard bcrypt does. Hashes made some other way (a pre-hash, a
  truncation, another algorithm, or over those costs) can't be imported:
  leave `password_hash` out, and the user gets an activation link by email,
  or printed with `--print-links`.
- **API keys:** `{"owner", "sha256", "scopes", "name"?, "expires_at"?, "revoked_at"?, "created_at"?, "last_used_at"?}`.
  `owner` is the user's `sub` or username, and must already hold a role on
  the service; `sha256` is the SHA-256 of the full key, in hex or base64.
  The keys keep their own format and keep working without reissue. An owner
  holds at most 100 live keys, imported and created together.

Each import checks every line first and writes all rows or none, listing
problems by line number without echoing a hash or an address. It takes at
most 10,000 lines and 8 MB; split a larger one into several files. Each row
is audited as `host-cli`, and the import is alerted.

### Database

Postgres 16, with a database and a role that only auth uses. As a superuser:

```sql
CREATE ROLE auth LOGIN PASSWORD '<generated>';
CREATE DATABASE auth OWNER auth;
REVOKE CONNECT ON DATABASE auth FROM PUBLIC;
```

Then allow the role only from the network auth connects from, above any
broader rule in `pg_hba.conf`, and reload with `SELECT pg_reload_conf();`:

```
host  auth  auth  <auth's subnet>  scram-sha-256
host  auth  auth  all              reject
```

No app's role can connect to the `auth` database.

### Network

- A hostname of the deployment's choosing, whose URL is the issuer, behind a
  TLS-terminating proxy. The proxy sets `X-Real-IP` from the connecting
  address.
- No ports published on the host.
- Apps make their back-channel calls over a private network where the
  deployment has one, or over HTTPS otherwise; browsers reach auth through the
  proxy.
- Outbound, auth reaches the SMTP server, the alert webhook, each service's
  `events_url`, and `https://api.pwnedpasswords.com`, or the mirror
  `BREACHED_PASSWORDS_URL` names, for the
  breached-password check (`docs/DESIGN.md` §9.1). That check allows the
  password when the API can't be reached, so blocking it turns the check
  off without an error.
- Emails go out from a queue in memory, two at a time and at most 200
  waiting. One that fails is logged and not retried, and a stopping copy
  waits at most 5 seconds for the queue: during an SMTP outage, activation,
  reset and invitation links are lost and must be sent again.

### Resources

Designed for 64 MB of memory and half a CPU. A deployment that expects
bursts of sign-ins should measure its peak during one and size the limit to
it (`docs/DESIGN.md` §10).

### Two copies

A rolling deploy can start the new copy beside the old one and stop the old
one once the new one is healthy, so both serve at once for a while. The
service keeps nothing in memory that another copy needs (`docs/DESIGN.md`
§8).

## 4. Settings of this repository

- **A branch ruleset on `main`:** changes only by pull request, code-owner
  review required (`.github/CODEOWNERS`), the `check` and `image` CI jobs
  required, no force pushes.
- **Private vulnerability reporting on** (`SECURITY.md`).
- **The CD secrets** from §2.
