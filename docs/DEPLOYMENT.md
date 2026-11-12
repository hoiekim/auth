# Deployment

How the image is built and released, and what any deployment of it needs.
`docs/DESIGN.md` §11 sets the requirements this follows. Everything that
differs between deployments (the issuer URL, the services file, secrets,
limits) is the deployment's own configuration (`docs/DESIGN.md` §2).

## 1. The image

`Dockerfile` builds it in two stages:

- **Builder**, on `oven/bun:1.4.4`: installs from `bun.lock`, runs
  `bun run typecheck` and `bun test`, then deletes the test files. The
  database tests skip here, with no `TEST_DATABASE_URL`; CI runs them, and CD
  publishes only commits whose CI passed.
- **Runtime**, on `oven/bun:1.4.4-slim`: installs production dependencies
  only and copies `src`, all owned by root, and runs as `bun`, which can read
  the code but not change it. `bun --no-install` makes an import that isn't
  in `node_modules` fail instead of fetching a package at run time.

**It runs from source** (`bun src/index.ts`), with no bundle step. Bun's
bundler replaces `process.env.NODE_ENV` with a constant at build time, so a
bundled server decides anything that reads it when the image is built, not
when it runs. The service reads no `NODE_ENV` at all, and sets
`development: false` on `Bun.serve` itself, since Bun would otherwise derive
that from `NODE_ENV`.

**Health.** `HEALTHCHECK` runs `GET /healthz` every 30 seconds. It answers
200 when the database answers within two seconds, and 503 otherwise.

**Stopping.** On SIGTERM the server stops accepting connections, finishes
the requests in flight, closes its database pool and exits 0. The `CMD` is
in exec form, so `bun` is PID 1 and receives the signal. CI's `image` job
checks this on every PR, and waits for the image's own `HEALTHCHECK` to
report healthy.

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

Later phases add variables as they need them (`docs/DESIGN.md` §11).

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
