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

A scaffold. The service validates its configuration and serves
`GET /healthz`, which answers 200 when the database answers and 503
otherwise. Nothing else in the design is built yet;
[`docs/DESIGN.md`](docs/DESIGN.md) §13 lists the phases.

## Configuration

Configuration comes from the environment only. The server refuses to start
when a value is missing or malformed, and lists every problem.
[`.env.example`](.env.example) has the same list.

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `PORT` | no | `3000` | HTTP listen port |
| `DATABASE_URL` | yes | — | Postgres connection string for the auth database |
| `TEST_DATABASE_URL` | tests only | — | A Postgres the database tests connect to; they skip without it |

## Development

Requires Bun 1.4.4, the version `packageManager` in `package.json` pins, and
Postgres 16.

```sh
bun install
cp .env.example .env    # then point DATABASE_URL at a local database
bun run dev             # restarts on change
bun run typecheck
TEST_DATABASE_URL=postgres://auth:auth@localhost:5432/auth bun test
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
