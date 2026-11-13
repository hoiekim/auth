-- docs/DESIGN.md §8. Migrations are expand-only: never edit or drop one that
-- has been applied; add a new file.

CREATE TABLE users (
  id                text PRIMARY KEY,                 -- usr_…
  username          text NOT NULL UNIQUE CHECK (username ~ '^[a-z][a-z0-9-]{1,30}[a-z0-9]$'),
  name              text NOT NULL DEFAULT '',
  email             text,                             -- recovery and notices
  email_verified_at timestamptz,
  kind              text NOT NULL DEFAULT 'person' CHECK (kind IN ('person', 'bot')),
  owner_id          text REFERENCES users,            -- bots only
  password_hash     text,                             -- PHC string; NULL for bots and passkey-only users
  disabled_at       timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email ON users (lower(email)) WHERE email IS NOT NULL;
CREATE INDEX users_owner ON users (owner_id) WHERE owner_id IS NOT NULL;

CREATE TABLE identities (                             -- platform sign-in (§12.3)
  provider   text NOT NULL,                           -- 'apple', …
  subject    text NOT NULL,                           -- the provider's stable user id
  user_id    text NOT NULL REFERENCES users ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (provider, subject)
);

CREATE TABLE access (
  user_id    text NOT NULL REFERENCES users ON DELETE CASCADE,
  service    text NOT NULL,                           -- checked against the services file (§6)
  role       text NOT NULL,
  granted_by text NOT NULL,                           -- usr_… or cli_<service>
  granted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, service)
);
CREATE INDEX access_service ON access (service, user_id);

CREATE TABLE totp (
  user_id        text PRIMARY KEY REFERENCES users ON DELETE CASCADE,
  secret_enc     bytea NOT NULL,                      -- AES-256-GCM, see §9.3
  last_step      bigint NOT NULL DEFAULT 0,           -- blocks replay of a code
  created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE passkeys (
  id            text PRIMARY KEY,
  user_id       text NOT NULL REFERENCES users ON DELETE CASCADE,
  credential_id bytea NOT NULL UNIQUE,
  public_key    bytea NOT NULL,                       -- COSE
  sign_count    bigint NOT NULL DEFAULT 0,
  name          text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_used_at  timestamptz
);
CREATE INDEX passkeys_user ON passkeys (user_id);

CREATE TABLE recovery_codes (
  user_id   text NOT NULL REFERENCES users ON DELETE CASCADE,
  code_hash bytea NOT NULL,                           -- SHA-256 (§9.1)
  used_at   timestamptz,
  PRIMARY KEY (user_id, code_hash)
);

CREATE TABLE sessions (                               -- SSO sessions at the issuer
  id           text PRIMARY KEY,                      -- ses_…, the token's sid
  user_id      text NOT NULL REFERENCES users ON DELETE CASCADE,
  token_hash   bytea NOT NULL UNIQUE,
  auth_time    timestamptz NOT NULL,                  -- last full sign-in (max_age, 15-min re-auth)
  amr          text[] NOT NULL,
  ip           inet,
  user_agent   text,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,                  -- idle
  ends_at      timestamptz NOT NULL                   -- absolute
);
CREATE INDEX sessions_user ON sessions (user_id);

CREATE TABLE refresh_tokens (
  token_hash  bytea PRIMARY KEY,
  family_id   text NOT NULL,                          -- rotation family (public clients)
  session_id  text REFERENCES sessions ON DELETE CASCADE,  -- confidential clients: dies with the SSO session
  user_id     text NOT NULL REFERENCES users ON DELETE CASCADE,
  client_id   text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  rotated_at  timestamptz,
  revoked_at  timestamptz,
  -- The sign-in's methods, for a public client's family, which outlives the
  -- SSO session; a confidential client's token reads its session's.
  amr         text[] NOT NULL DEFAULT '{}'
);
CREATE INDEX refresh_tokens_session ON refresh_tokens (session_id) WHERE session_id IS NOT NULL;
CREATE INDEX refresh_tokens_family ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_user ON refresh_tokens (user_id);

CREATE TABLE auth_codes (
  code_hash      bytea PRIMARY KEY,
  client_id      text NOT NULL,
  session_id     text NOT NULL REFERENCES sessions ON DELETE CASCADE,
  redirect_uri   text NOT NULL,
  code_challenge text NOT NULL,
  nonce          text,
  expires_at     timestamptz NOT NULL,
  used_at        timestamptz
);

CREATE TABLE credentials (                            -- app passwords and API keys
  id          text PRIMARY KEY,                       -- apw_… / key_…; not secret (§7.3)
  user_id     text NOT NULL REFERENCES users ON DELETE CASCADE,
  kind        text NOT NULL CHECK (kind IN ('app_password', 'api_key')),
  service     text NOT NULL,
  scopes      text[] NOT NULL,
  name        text NOT NULL,
  secret_hash bytea NOT NULL UNIQUE,
  created_at  timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  expires_at  timestamptz,
  revoked_at  timestamptz
);
CREATE INDEX credentials_user ON credentials (user_id);

CREATE TABLE client_secrets (                         -- two may be live during a rotation
  client_id   text NOT NULL,
  secret_hash bytea NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  revoked_at  timestamptz,
  PRIMARY KEY (client_id, secret_hash)
);

CREATE TABLE invites (
  id          text PRIMARY KEY,                       -- inv_…
  email       text NOT NULL,
  service     text NOT NULL,
  role        text NOT NULL,
  token_hash  bytea NOT NULL UNIQUE,
  invited_by  text NOT NULL,
  expires_at  timestamptz NOT NULL,
  accepted_by text REFERENCES users ON DELETE SET NULL,
  accepted_at timestamptz
);
CREATE INDEX invites_service ON invites (service, id);

CREATE TABLE one_time_tokens (                        -- reset, email verification, activation
  token_hash bytea PRIMARY KEY,
  purpose    text NOT NULL CHECK (purpose IN ('reset', 'verify_email', 'activate')),
  user_id    text NOT NULL REFERENCES users ON DELETE CASCADE,
  email      text,
  expires_at timestamptz NOT NULL,
  used_at    timestamptz
);
CREATE INDEX one_time_tokens_user ON one_time_tokens (user_id);

CREATE TABLE signing_keys (
  kid             text PRIMARY KEY,
  public_jwk      jsonb NOT NULL,
  private_key_enc bytea NOT NULL,
  publish_at      timestamptz NOT NULL,              -- in JWKS from here
  sign_from       timestamptz NOT NULL,              -- publish_at + 1 day
  retire_at       timestamptz                        -- dropped from JWKS
);

CREATE TABLE outbox (                                 -- events to apps
  id              bigserial PRIMARY KEY,
  service         text NOT NULL,
  token           text NOT NULL,                      -- the signed SET
  attempts        int NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  delivered_at    timestamptz,
  failed_at       timestamptz
);
CREATE INDEX outbox_pending ON outbox (next_attempt_at) WHERE delivered_at IS NULL AND failed_at IS NULL;

CREATE TABLE audit (
  id        bigserial PRIMARY KEY,
  at        timestamptz NOT NULL DEFAULT now(),
  actor     text,                                     -- usr_…, cli_<service>, 'host-cli', NULL for anonymous
  action    text NOT NULL,                            -- 'login.ok', 'login.fail', 'access.put', 'mfa.cleared', …
  user_id   text,                                     -- the subject; no FK, so the log outlives a deleted user
  ip        inet,
  detail    jsonb NOT NULL DEFAULT '{}'               -- never a secret, a token or a password
);
CREATE INDEX audit_user ON audit (user_id, id);
CREATE INDEX audit_at ON audit (at);

CREATE UNLOGGED TABLE throttle (                      -- shared across every copy
  key          text PRIMARY KEY,                      -- 'ip:1.2.3.4:login', 'user:usr_…:login'
  window_start timestamptz NOT NULL,
  hits         int NOT NULL
);
