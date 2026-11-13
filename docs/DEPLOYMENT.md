# Deployment

How the image is built and released, and what any deployment of it needs.
`docs/DESIGN.md` §11 sets the requirements this follows. Everything that
differs between deployments (the issuer URL, the services file, secrets,
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
  the code but not change it. `bun --no-install` makes an import that isn't
  in `node_modules` fail instead of fetching a package at run time.

**It runs from source** (`bun src/index.ts`), with no bundle step. Bun's
bundler replaces `process.env.NODE_ENV` with a constant at build time, so a
bundled server decides anything that reads it when the image is built, not
when it runs. The service reads no `NODE_ENV` at all, and sets
`development: false` on `Bun.serve` itself, since Bun would otherwise derive
that from `NODE_ENV`.

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
it.

## 2. Releases

1. A PR merges to `main`.
2. CI runs on the push. Once it passes, CD builds `main`'s tip, pushes it to
   Docker Hub as `<namespace>/auth:latest` and `<namespace>/auth:sha-<short sha>`
   (the namespace is the account the CD secrets below name), and records the
   image digest in the run's summary.

CD deploys nothing. A deployment pulls the image it chooses, **pinned by
digest**, and upgrades by moving the pin in its own configuration, where it
reviews the change. A push to this repository therefore can't reach any
deployment on its own (`docs/DESIGN.md` §11).

**Rolling back** is moving the pin back to the previous digest. Migrations
are expand-only, so the previous image runs against the newer schema.

CD needs two repository secrets: `DOCKER_HUB_USERNAME`, and
`DOCKER_HUB_ACCESS_TOKEN`, a Docker Hub access token that can push to the
`auth` repository.

## 3. What the runtime needs

### Environment

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `PORT` | no | `3000` (the image sets it) | HTTP listen port |
| `DATABASE_URL` | yes | — | Postgres connection string for the auth database |
| `ISSUER_URL` | yes | — | The issuer: the https origin browsers and apps reach auth at, with no path. It is every token's `iss` and the passkeys' RP ID, so changing it signs everyone out and invalidates every passkey. |
| `SERVICES_FILE` | yes | — | Path to the services file inside the container (below) |
| `AUTH_ENCRYPTION_KEY` | yes | — | 32 random bytes, base64 (`openssl rand -base64 32`). Encrypts signing keys and TOTP secrets at rest. Keep a copy offline: a restored backup is useless without it. |
| `API_KEY_PREFIX` | when a service declares `api_key_scopes` | — | The first part of every API key (`[a-z][a-z0-9]{1,15}`), so the deployment can register the pattern with a secret scanner |
| `TRUSTED_PROXIES` | no | none | The proxy's addresses, as IPs or CIDR ranges, comma-separated. Only these may set `X-Real-IP`. Behind a proxy, leaving it out puts every client in one rate-limit bucket. |
| `SMTP_URL` | yes | — | `smtps://user:password@host[:465]`, or `smtp://…[:587]` with STARTTLS required. Plain SMTP only to a loopback host. |
| `EMAIL_FROM` | yes | — | The sender of auth's emails: `auth@example.com` or `Example Auth <auth@example.com>` |
| `AUDIT_RETENTION_DAYS` | no | `365` | Days of audit log kept; lower it under a shorter retention rule |
| `ALLOW_ACCOUNT_DELETION` | no | `false` | `true` lets people delete their own accounts (U14), for example where a store requires it |
| `ALERT_WEBHOOK_URL` | no | — | An http(s) URL that receives `{"text": "…"}` on every change to who administers auth, every break-glass use, admin resets and disables, a reused refresh token, and events given up after 24 hours |

Secrets (`DATABASE_URL`, `AUTH_ENCRYPTION_KEY`, the password in `SMTP_URL`,
a token in `ALERT_WEBHOOK_URL`) come from the deployment's secret store into
the environment, never from the image or the database.

### The services file

A JSON file the deployment keeps with its own configuration and mounts
read-only, for example at `/etc/auth/services.json`. `docs/DESIGN.md` §6
defines its fields; the server checks it at start and refuses to start on
any problem, listing all of them. Changing it takes a restart.

### First admin and client secrets

Run the CLI inside a running container (`docker exec <container> bun cli.ts
…`); every use is audited as `host-cli` and alerted.

```sh
bun cli.ts user create --username alice --email alice@example.com --access auth:admin
bun cli.ts client secret wiki
```

The first emails an activation link (add `--print-link` to print it instead
when email isn't working yet). The admin then sets a password, signs in and
enrolls a second factor, which `auth:admin` always requires. The second
prints a confidential client's secret once, for the app's environment. To
rotate one, run it again, move the app to the new secret, then run
`bun cli.ts client retire-old-secrets wiki`.

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

### Resources

Designed for 128 MB of memory and half a CPU. A deployment that expects
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
- **The two CD secrets** from §2.
