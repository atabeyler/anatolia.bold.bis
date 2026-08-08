# Architecture

## Overview

Anatolia B.I.S. is a single Rust (Axum) backend serving a React/TypeScript
frontend, designed to extend to desktop (Tauri) and mobile (thin
Android/iOS clients) without architectural rework.

```
anatolia.bold.bis/
├── server/            # Rust backend (Axum)
│   ├── src/
│   │   ├── main.rs      # Entry point: server bootstrap, middleware stack
│   │   ├── lib.rs        # Library surface (used by main.rs and tests)
│   │   ├── config.rs     # Environment-driven configuration
│   │   ├── error.rs      # Shared ApiError type
│   │   ├── middleware.rs # Security headers
│   │   └── routes/       # HTTP route handlers
│   ├── build.rs          # Embeds the commit SHA at compile time
│   └── tests/            # Integration tests
├── client/            # React frontend (Vite + TypeScript)
│   └── src/
│       ├── app/, pages/, components/, hooks/, services/
│       └── i18n/          # Translation resources and configuration
└── docker-compose.yml  # Local stack: PostgreSQL, API, Web
```

## Backend

- **Framework**: Axum, single binary, no separate process per concern.
- **Persistence**: SQLx — PostgreSQL in production, SQLite as a local
  development fallback only (not yet wired up; Phase 1 has no database
  layer).
- **Provider abstractions** (planned, Phase 3+): `BiometricProvider` and
  vector-search/connector traits keep the core application decoupled from
  any specific model, vector database, or external data source. A mock
  biometric provider is implemented first so the full workflow is
  developable and testable without a real model.
- **Observability**: structured (JSON) logs, per-request IDs propagated
  via the `x-request-id` header, `GET /api/health` reporting the exact
  running commit SHA.

## Frontend

- React 18+, TypeScript (strict), Vite, TanStack Query, i18next.
- No user-facing string is ever hardcoded — see `docs/I18N.md`.

## Desktop and mobile (planned)

- **Desktop**: Tauri, wrapping the same web client as a native window.
- **Android / iOS**: thin clients only — camera/file capture, upload, and
  result display. Biometric inference and candidate search always run
  server-side, never on-device. This is a deliberate choice, not a
  temporary limitation:
  - The system only ever searches authorized, centrally governed data
    sources — those cannot meaningfully live on a phone.
  - Every sensitive action must be audited centrally; on-device matching
    would bypass that.
  - It avoids on-device ONNX Runtime cross-compilation for Android and the
    fact that iOS does not allow a persistent bundled server subprocess —
    neither constraint applies when the client is just an HTTPS API
    consumer.

## Deployment

Render, native Rust binary (no Node process at runtime for the API).
`GET /api/health`'s `version` field is the reliable way to confirm a given
deployment is actually live. See `docs/DEPLOYMENT.md`.
