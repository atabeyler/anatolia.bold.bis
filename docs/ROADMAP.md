# Roadmap

Implemented incrementally. Nothing below Phase 2 is implemented yet.

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

- [ ] Mock biometric provider (`BiometricProvider` trait)
- [ ] Search request creation (case reference + purpose required)
- [ ] Candidate results (top-K), candidate detail view
- [ ] Audit logging (append-only)

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
