# Single image: the Rust binary serves both the API and the built
# frontend from one process — mirrors the single-service Render deploy
# (render.yaml), so there is no separate frontend container.

FROM node:22-slim AS client-builder
WORKDIR /app/client
COPY client/package.json client/package-lock.json* ./
RUN npm ci
COPY client/ ./
RUN npm run build

FROM rust:1-slim-bookworm AS server-builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
COPY server/Cargo.toml server/Cargo.lock* ./
COPY server/build.rs ./build.rs
COPY server/src ./src
ARG GIT_COMMIT_SHA=unknown
ENV GIT_COMMIT_SHA=${GIT_COMMIT_SHA}
RUN cargo build --release

FROM debian:bookworm-slim AS runtime
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin app

COPY --from=server-builder /app/target/release/anatolia-bis-server /usr/local/bin/anatolia-bis-server
COPY --from=client-builder /app/client/dist ./client/dist

ENV STATIC_DIR=client/dist
USER app
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/anatolia-bis-server"]
