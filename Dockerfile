# syntax=docker/dockerfile:1

# Builder: compile the existing guardian-meshd from source. protoc is required
# by build.rs (tonic-prost-build).
FROM rust:1-bookworm AS builder

# Optional build identity. When empty, it is left unset so build.rs can fall
# back to git (absent in the image, so it records "unknown"). Never fake it.
ARG GUARDIAN_MESH_GIT_COMMIT=

RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy only what the daemon build needs. Cargo.lock is optional in this repo
# (it is gitignored), so the wildcard keeps the copy valid when it is absent.
COPY Cargo.toml Cargo.lock* ./
COPY guardian-meshd/Cargo.toml guardian-meshd/
COPY guardian-meshd/build.rs guardian-meshd/
COPY guardian-meshd/proto/ guardian-meshd/proto/
COPY guardian-meshd/src/ guardian-meshd/src/

# build.rs embeds GUARDIAN_MESH_GIT_COMMIT. Only export it when the caller
# supplied a value; exporting an empty value would embed "" instead of letting
# build.rs fall back to git (absent here) and record "unknown".
RUN if [ -n "${GUARDIAN_MESH_GIT_COMMIT}" ]; then \
        GUARDIAN_MESH_GIT_COMMIT="${GUARDIAN_MESH_GIT_COMMIT}" \
        cargo build --release --package guardian-meshd --bin guardian-meshd; \
    else \
        cargo build --release --package guardian-meshd --bin guardian-meshd; \
    fi

# Runtime: minimal Debian base with no build toolchain. Non-root only.
FROM debian:bookworm-slim AS runtime

RUN groupadd --gid 10001 guardian \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin guardian

COPY --from=builder /build/target/release/guardian-meshd /usr/local/bin/guardian-meshd

# WORKDIR /app is LOAD-BEARING: config.rs verify_no_program_dir_write uses
# program_dir "." and refuses to start when the workspace resolves inside it.
# With WORKDIR /, every absolute path would be "inside" the program dir.
WORKDIR /app

# Runtime defaults. The workspace lives outside the program dir and on a
# persistent volume so the signing key and hash-chained audit log survive a
# container restart.
ENV GUARDIAN_MESH_WORKSPACE=/data/workspace \
    GUARDIAN_MESH_OUTPUT=/data/output \
    GUARDIAN_MESH_BIND_ADDR=0.0.0.0 \
    GUARDIAN_MESH_PORT=50051

RUN mkdir -p /data/workspace /data/output \
    && chown -R guardian:guardian /data

# Minimal runtime, non-root by default. /data holds the workspace and is the
# only path the daemon needs to write. NO secret is baked into the image: the
# handshake secret is injected at run time (environment variable or Kubernetes
# Secret), never set here and never built into the image.
VOLUME ["/data"]
EXPOSE 50051

USER guardian

ENTRYPOINT ["/usr/local/bin/guardian-meshd"]
