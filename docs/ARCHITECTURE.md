# Architecture

## Overview

Anatolia B.I.S. is a single Rust (Axum) backend serving a React/TypeScript
frontend from the same process and origin — one deployed service, one URL
— designed to extend to desktop (Tauri) and mobile (thin Android/iOS
clients) without architectural rework.

```
anatolia.bold.bis/
├── server/            # Rust backend (Axum)
│   ├── src/
│   │   ├── main.rs       # Entry point: bootstrap, middleware stack,
│   │   │                 #   frontend static-file serving with SPA fallback
│   │   ├── lib.rs        # Library surface (used by main.rs and tests)
│   │   ├── config.rs     # Environment-driven configuration
│   │   ├── db/           # DbBackend (Postgres/SQLite), AppState, split by domain
│   │   ├── auth.rs       # JWT issuing/verification, register/login/refresh
│   │   ├── admin.rs      # Admin-approval workflow, admin bootstrap
│   │   ├── search.rs     # Search-workflow route handlers
│   │   ├── biometric/    # BiometricProvider trait, mock + real (ONNX) implementations
│   │   ├── email.rs      # Resend-backed registration notifications
│   │   ├── roles.rs      # RBAC role identifiers
│   │   ├── error.rs      # Shared ApiError type
│   │   ├── middleware.rs # Security headers
│   │   └── routes/       # HTTP route handlers
│   ├── build.rs          # Embeds the commit SHA at compile time
│   └── tests/            # Integration tests
├── client/            # React frontend (Vite + TypeScript)
│   └── src/
│       ├── features/auth/, pages/, components/, hooks/, services/
│       └── i18n/          # Translation resources and configuration
├── Dockerfile          # Single image: builds client + server, one process
└── docker-compose.yml  # Local stack: PostgreSQL + the single app service
```

## Backend

- **Framework**: Axum, single binary, no separate process per concern.
- **Persistence**: SQLx — PostgreSQL in production (in its own
  `anatolia_bis` schema, so the database can safely be shared with another
  project — see `server/src/db/mod.rs`'s `PG_SCHEMA`), SQLite as a local
  development fallback. `server/src/db/` is split by domain: `db/audit.rs`
  (append-only audit trail), `db/mfa.rs`, `db/org.rs`, `db/biometric.rs`,
  `db/evidence.rs`, `db/identity.rs` (user accounts), and `db/session.rs`
  (refresh-token sessions and approval tokens). Connection setup, schema
  migration, and the search/candidate/verification tables — more
  interdependent with the others than a mechanical split allows — still
  live in `db/mod.rs`; see item 31 in `docs/HARDENING_CHECKLIST.md`.
- **Background jobs**: a retention task (`main.rs::spawn_retention_job`)
  purges expired `sessions`/`approval_tokens` rows on a fixed interval
  (`db::purge_expired_auth_records`); configurable via
  `RETENTION_JOB_INTERVAL_SECS`/`RETENTION_JOB_ENABLED`, same pattern as
  the existing self-ping job.
- **Authentication**: JWT access tokens (15 min, returned in the response
  body) plus an `HttpOnly` refresh cookie (30 days), bcrypt password
  hashing, an admin-approval gate on new registrations, and RBAC
  (`SYSTEM_ADMIN`, `SECURITY_ADMIN`, `OPERATOR`, `REVIEWER`, `AUDITOR`).
  See `API.md` and `docs/SECURITY_ARCHITECTURE.md`.
- **Provider abstractions**: `BiometricProvider` (`server/src/biometric/`)
  keeps the core application decoupled from any specific model.
  `MockBiometricProvider` ranks candidates deterministically from the
  probe image's bytes, so the full search workflow (`server/src/search.rs`)
  is developable and testable without a real model.
  `OnnxBiometricProvider` (YuNet detection + SFace embedding via ONNX
  Runtime) is the real implementation, behind the opt-in
  `onnx-provider` Cargo feature and `BIOMETRIC_PROVIDER=onnx` — see
  `docs/ENVIRONMENT.md` for why it's off by default on Render's native
  build and how to enable it via Docker. Biometric search itself uses a
  brute-force in-memory cosine scan on SQLite, and on PostgreSQL an
  indexed HNSW search (the `pgvector` extension) when available,
  falling back to brute-force otherwise — see
  `docs/SECURITY_ARCHITECTURE.md`. OSINT connector traits
  (`WebSearchProvider`/`NewsProvider`/`AuthorizedSocialProvider`,
  `server/src/osint/`) follow the same pattern: real implementations
  (Brave Search, NewsAPI.org) behind the same interface as their mocks,
  selected per-provider by whether an API key is configured.
- **Observability**: structured (JSON) logs, per-request IDs propagated
  via the `x-request-id` header, `GET /api/health` reporting the exact
  running commit SHA.

## Frontend

- React 19, TypeScript (strict), Vite, TanStack Query, i18next.
- No user-facing string is ever hardcoded — see `docs/I18N.md`.
- Talks to the API via a relative `/api` base URL by default, since in
  every deployed environment it's served from the same origin as the
  backend (see "Single-service serving" below). `VITE_API_BASE_URL` only
  needs to be set for local development, when running the frontend's own
  dev server (`npm run dev`) against a backend on a different port.

## Single-service serving

The backend serves the frontend's build output directly (via `STATIC_DIR`,
see `docs/ENVIRONMENT.md`), with any request that isn't an API route or an
existing static file falling back to `index.html` for client-side routing.
This means:
- One deployed URL, with no "api" or "web" segment in it.
- No CORS configuration needed between the frontend and its own backend in
  production — they're same-origin. `ALLOWED_ORIGINS` stays relevant only
  for local cross-origin dev and future non-browser clients (mobile,
  desktop).

## Desktop and mobile (planned)

- **Desktop**: Tauri, wrapping the same web client as a native window.
- **Android / iOS**: thin clients only — camera/file capture, upload, and
  result display. Biometric inference and candidate search always run
  server-side, never on-device. This is a deliberate choice, not a
  temporary limitation:
  - The system only ever searches authorized, centrally governed data
    sources — those cannot meaningfully live on a phone.
  - It avoids on-device ONNX Runtime cross-compilation for Android and the
    fact that iOS does not allow a persistent bundled server subprocess —
    neither constraint applies when the client is just an HTTPS API
    consumer.

## Deployment

Render, single native Rust web service (no separate frontend resource, no
Node process at runtime). `GET /api/health`'s `version` field is the
reliable way to confirm a given deployment is actually live. See
`docs/DEPLOYMENT.md`.
