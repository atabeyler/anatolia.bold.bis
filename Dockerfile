# Single image: the Rust binary serves both the API and the built
# frontend from one process — mirrors the single-service Render deploy
# (render.yaml), so there is no separate frontend container.

FROM node:22-slim AS client-builder
WORKDIR /app/client
COPY client/package.json client/package-lock.json* ./
RUN npm ci
COPY client/ ./
RUN npm run build

# Debian "trixie" (13), not the older "bookworm" (12): the real ONNX
# biometric provider (`--features onnx-provider`, see ARG ONNX_PROVIDER
# below) statically links a prebuilt `libonnxruntime.a` at build time
# that requires glibc >= 2.38 (the ISO C23 additions, e.g.
# `__isoc23_strtoll`) — bookworm ships glibc 2.36, which is exactly what
# made this feature fail to link on Render's (bookworm-based) native Rust
# build image. trixie ships glibc 2.40. This was verified empirically,
# not assumed: building with `--features onnx-provider` against a glibc
# 2.39 host linked cleanly and produced a fully self-contained binary —
# `ldd` shows no `onnxruntime` dependency at all, because the archive is
# statically embedded, not dynamically loaded; there is no runtime
# network dependency for ONNX Runtime itself (the YuNet/SFace *model*
# files are a separate, already-documented runtime download — see
# `server/src/biometric/models.rs`).
FROM rust:1-slim-trixie AS server-builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev g++ \
    && rm -rf /var/lib/apt/lists/*
COPY server/Cargo.toml server/Cargo.lock* ./
COPY server/build.rs ./build.rs
COPY server/src ./src
# Cargo parses every declared target in Cargo.toml — including
# `[[bench]]` — before building anything, even just the binary; without
# this, the build fails at the manifest-parsing stage looking for
# benches/biometric_pipeline.rs.
COPY server/benches ./benches
# Render's Docker build context does not include `.git` (confirmed
# empirically: a `COPY .git` here fails with "not found", unlike a local
# `docker build` from a real checkout), so `build.rs`'s own git fallback
# can never run here — an explicit build arg is the only way to get the
# real commit into this build. Render does not appear to set this
# automatically either, so it stays "unknown" on Render specifically
# until that's confirmed/wired up; a real value can still be supplied
# with `--build-arg GIT_COMMIT_SHA=$(git rev-parse HEAD)` when building
# elsewhere. See `server/build.rs` and `docs/ENVIRONMENT.md`.
ARG GIT_COMMIT_SHA=unknown
ENV GIT_COMMIT_SHA=${GIT_COMMIT_SHA}
# Off by default, matching server/Cargo.toml's default-off `onnx-provider`
# feature — building this image with no extra build args reproduces
# today's known-good mock-only artifact. Pass
# `--build-arg ONNX_PROVIDER=true` to build the real biometric provider
# in; see docs/DEPLOYMENT.md "Enabling the real ONNX biometric provider".
ARG ONNX_PROVIDER=false
RUN if [ "$ONNX_PROVIDER" = "true" ]; then \
        cargo build --release --features onnx-provider; \
    else \
        cargo build --release; \
    fi

FROM debian:trixie-slim AS runtime
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin app

COPY --from=server-builder /app/target/release/anatolia-bis-server /usr/local/bin/anatolia-bis-server
COPY --from=client-builder /app/client/dist ./client/dist

# `WORKDIR`/`COPY` above run as root, so /app and everything under it is
# root-owned; the `app` user (below) has no write access to it otherwise.
# BIOMETRIC_PROVIDER=onnx's default MODEL_CACHE_DIR (./data/models,
# relative to this working directory) needs to be creatable at runtime —
# without this, the non-root `app` user hits a "Permission denied"
# creating it and the server refuses to start (fail-closed, per
# server/src/biometric/onnx_provider.rs).
RUN mkdir -p /app/data/models && chown -R app:app /app

ENV STATIC_DIR=client/dist
USER app
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/anatolia-bis-server"]
