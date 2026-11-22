# The image of the Rust server (docs/DEPLOYMENT.md §1). Built from the
# repository root, because the migrations and the pages' assets are the ones
# in src/, shared with the Bun server:
#
#   docker build -f rust/Dockerfile -t auth-rust .
#
# Configuration comes from the environment only; nothing is copied in.

# The Rust version rust/rust-toolchain.toml pins.
FROM rust:1.97.0-slim-bookworm AS builder

WORKDIR /app

COPY src/migrations src/migrations
COPY src/assets src/assets
COPY rust rust

# --locked: the dependencies are exactly those of Cargo.lock.
RUN cargo test --release --locked --manifest-path rust/Cargo.toml
RUN cargo build --release --locked --manifest-path rust/Cargo.toml

FROM debian:bookworm-slim

# Owned by root: the server, running as nobody, can read its binary but not
# change it. The one file is the server, the break-glass CLI (docs/DESIGN.md
# §9.6: `auth cli help` in a running container) and the health check.
COPY --from=builder /app/rust/target/release/auth /usr/local/bin/auth

USER 65534:65534

ENV PORT=3000
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
  CMD ["auth", "healthcheck"]

# Exec form, so auth is PID 1 and receives the SIGTERM a deploy sends.
CMD ["auth"]
