# Roadmap

Implemented incrementally. Nothing below Phase 3.6 is implemented yet.

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
- [ ] Session/device management UI (server-side session model exists as of Phase 3.5 — no UI to list/revoke individual sessions yet), MFA, enterprise SSO

## Phase 3 — Search workflow

- [x] Mock biometric provider (`BiometricProvider` trait)
- [x] Search request creation (case reference + purpose required)
- [x] Candidate results (top-K), candidate detail view, human confirm/reject
- [x] Attach the operator's captured location (see "Operator geolocation"
      below) to searches

## Phase 3.5 — Authentication hardening

- [x] Centralized, production-fail-fast secret validation (`JWT_SECRET`,
      `JWT_REFRESH_SECRET`, `APPROVAL_TOKEN_SECRET` — see
      `docs/SECURITY_ARCHITECTURE.md`)
- [x] Server-side `sessions` table; refresh-token rotation with
      reuse/theft detection revoking the whole token family
- [x] `POST /api/v1/auth/logout-all`; banning a user revokes its active
      sessions immediately
- [x] Registration approval tokens isolated from login tokens
      (`APPROVAL_TOKEN_SECRET`, `approval_tokens` table, single-use)
- [x] Registration-status polling by unguessable tracking token instead
      of the account's own user code (enumeration fix)
- [x] Login rate limiting layered with per-IP and burst windows (in
      addition to the existing per-account window)
- [x] CORS method list includes `PATCH`; CSP and Permissions-Policy
      headers; HSTS restricted to production
- [ ] MFA, organization/unit-scoped authorization (tracked separately —
      see the milestones below)

## Phase 3.6 — Audit trail

- [x] Append-only `audit_events` table (PostgreSQL/SQLite), never
      `UPDATE`d or `DELETE`d by any code path
- [x] Central `AuditService`/`AuditRecorder` (`server/src/audit.rs`) —
      handlers call one consistent API instead of ad-hoc `INSERT`s
- [x] Events wired into auth (login/refresh/logout/logout-all/token
      reuse/password reset request), registration (created/approved/
      rejected), user administration (created/updated/banned/unbanned/
      deleted), search (created/completed/failed), candidate (confirmed/
      rejected), and admin-seed (used/failed)
- [x] `GET /api/v1/audit`, server-side paginated and filtered
      (date range, actor, action, case reference, resource type, result),
      restricted to `AUDITOR`/`SECURITY_ADMIN`/`SYSTEM_ADMIN`
- [x] Frontend Audit Logs screen (filters, pagination, expandable detail),
      all 6 locales
- [ ] Organization/unit-scoped audit visibility (depends on the
      organization model in a later milestone)

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
