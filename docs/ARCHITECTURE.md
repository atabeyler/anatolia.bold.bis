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
│   │   ├── db.rs         # DbBackend (Postgres/SQLite), AppState, users table
│   │   ├── auth.rs       # JWT issuing/verification, register/login/refresh
│   │   ├── admin.rs      # Admin-approval workflow, admin bootstrap
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
  project — see `server/src/db.rs`'s `PG_SCHEMA`), SQLite as a local
  development fallback.
- **Authentication**: JWT access tokens (15 min, returned in the response
  body) plus an `HttpOnly` refresh cookie (30 days), bcrypt password
  hashing, an admin-approval gate on new registrations, and RBAC
  (`SYSTEM_ADMIN`, `SECURITY_ADMIN`, `OPERATOR`, `REVIEWER`, `AUDITOR`).
  See `API.md` and `docs/SECURITY_ARCHITECTURE.md`.
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
  - Every sensitive action must be audited centrally; on-device matching
    would bypass that.
  - It avoids on-device ONNX Runtime cross-compilation for Android and the
    fact that iOS does not allow a persistent bundled server subprocess —
    neither constraint applies when the client is just an HTTPS API
    consumer.

## Deployment

Render, single native Rust web service (no separate frontend resource, no
Node process at runtime). `GET /api/health`'s `version` field is the
reliable way to confirm a given deployment is actually live. See
`docs/DEPLOYMENT.md`.
