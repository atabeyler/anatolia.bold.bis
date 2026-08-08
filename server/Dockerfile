FROM rust:1-slim-bookworm AS builder
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

COPY --from=builder /app/target/release/anatolia-bis-server /usr/local/bin/anatolia-bis-server

USER app
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/anatolia-bis-server"]
