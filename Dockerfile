# The production image (docs/DEPLOYMENT.md). The server runs from source:
# there is no bundle step, so nothing in it is decided at build time.
# Configuration comes from the environment only; no .env file is copied in.

# The Bun version pinned by `packageManager` in package.json.
FROM oven/bun:1.4.4 AS builder

WORKDIR /app

COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

COPY tsconfig.json ./
COPY src src

# The database tests skip here (no TEST_DATABASE_URL); CI runs them, and CD
# publishes only commits whose CI passed.
RUN bun run typecheck
RUN bun test
RUN find src -name '*.test.ts' -delete

FROM oven/bun:1.4.4-slim

WORKDIR /app

# Owned by root: the server, running as bun, can read its code but not change it.
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production
COPY --from=builder /app/src src

USER bun

ENV PORT=3000
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
  CMD ["bun", "-e", "const r = await fetch(`http://localhost:${process.env.PORT}/healthz`); process.exit(r.ok ? 0 : 1)"]

# Exec form, so bun is PID 1 and receives the SIGTERM a deploy sends.
# --no-install: an import that isn't in node_modules fails instead of being
# fetched from the registry at run time.
CMD ["bun", "--no-install", "src/index.ts"]
