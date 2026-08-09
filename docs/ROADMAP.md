# Roadmap

Implemented incrementally. Nothing below Phase 3 is implemented yet.

## Phase 1 — Repository foundation (this phase)

- [x] Repository rules (`AGENTS.md`, `CLAUDE.md`)
- [x] Backend shell (Rust/Axum), `GET /api/health` reporting the live commit SHA
- [x] Frontend shell (React/TypeScript/Vite)
- [x] i18n system, 6 languages (en, tr, de, fr, ar, ru), Arabic RTL
- [x] Docker (backend, frontend, docker-compose with PostgreSQL)
- [x] CI (backend tests/clippy, frontend typecheck/test/build)

## Phase 2 — Authentication foundation

- [x] User model and SQLx-managed schema (PostgreSQL production, SQLite local fallback)
- [x] RBAC roles (SYSTEM_ADMIN, SECURITY_ADMIN, OPERATOR, REVIEWER, AUDITOR); approved registrations default to OPERATOR
- [x] JWT auth (register/login/refresh/logout), bcrypt password hashing, per-key rate limiting
- [x] Admin-approval workflow for new registrations, admin user administration (approve/reject/ban/unban/delete), rate-limited admin bootstrap (`seed-admin`)
- [ ] Session/device management UI, MFA, enterprise SSO

## Phase 3 — Search workflow

- [x] Mock biometric provider (`BiometricProvider` trait)
- [x] Search request creation (case reference + purpose required)
- [x] Candidate results (top-K), candidate detail view, human confirm/reject
- [x] Attach the operator's captured location (see "Operator geolocation"
      below) to searches

## Phase 4 — Production biometric provider

- [ ] Real `BiometricProvider` implementation (ONNX Runtime via `ort`, server-side)
- [ ] Vector database provider abstraction (pgvector/Qdrant/other)
- [ ] Image quality assessment (blur, brightness, face angle, multiple faces)

## Phase 5 — Authorized connectors and administration

- [ ] Authorized data source connectors (declared authorization type, capabilities, rate limits)
- [ ] Secondary verification workflow
- [ ] Administration screens
- [ ] Thin Android/iOS clients (capture/upload + result display; no on-device inference)

## Phase 6 — Hardening

- [ ] Observability, security tests, performance tests
- [ ] Institutional deployment hardening

## Operator geolocation

The sign-in screen requests the browser's real geolocation on load (no
synthetic fallback coordinate on denial — an explicit "unavailable"
message instead) and displays it alongside the running app version. The
captured coordinate is exposed via `useGeolocation`'s
`getLastKnownLocation()`; `POST /api/v1/search/face` sends it along as
optional `latitude`/`longitude` form fields, and the search-results view
displays it when present.
