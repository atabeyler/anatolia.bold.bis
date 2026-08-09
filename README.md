# Anatolia B.I.S.

[![Version](https://img.shields.io/github/package-json/v/atabeyler/anatolia.bold.bis?filename=client%2Fpackage.json)](client/package.json)
[![CI](https://github.com/atabeyler/anatolia.bold.bis/actions/workflows/ci.yml/badge.svg)](https://github.com/atabeyler/anatolia.bold.bis/actions/workflows/ci.yml)
[![License: Proprietary](https://img.shields.io/badge/license-proprietary-red)](LICENSE.txt)

**Bold Askeri Teknoloji ve Savunma Sanayi A.Ş.**

A secure biometric candidate-matching and identity verification platform for
authorized institutional use.

---

## Project Status

**Phases 1–3 (auth foundation, search workflow, authentication hardening)
complete.** The backend has JWT authentication (register/login/refresh/
logout/logout-all) backed by real server-side sessions with refresh-token
rotation and theft detection, bcrypt password hashing, RBAC (SYSTEM_ADMIN,
SECURITY_ADMIN, OPERATOR, REVIEWER, AUDITOR), an admin-approval workflow
for new registrations (with its own isolated, single-use approval token),
enumeration-safe registration-status polling, layered rate limiting, and a
production-only CSP/Permissions-Policy/HSTS header set — see `API.md` and
`docs/SECURITY_ARCHITECTURE.md`. Every security- or case-relevant action
(auth, registration, user administration, search, candidate review,
admin bootstrap) is recorded to an append-only audit trail through one
central `AuditRecorder`, browsable at `GET /api/v1/audit` and in a
dedicated frontend Audit Logs screen (`AUDITOR`/`SECURITY_ADMIN`/
`SYSTEM_ADMIN` only). The end-to-end search workflow (case
reference + purpose → face image → ranked candidates → human review) is
implemented end to end using **`MockBiometricProvider`** — a deterministic,
non-biometric stand-in behind the same `BiometricProvider` trait a real
model will later implement. Production biometric inference (real face
detection/embedding/vector search) is not yet implemented — do not treat
returned "candidates" as based on any real face analysis. Verified:
backend tests (including register → admin-approve → login, refresh
rotation/reuse-detection/logout-all, and audit-trail role/pagination
integration tests) + clippy, frontend typecheck + tests + build all pass.
See `docs/ROADMAP.md` for what's
planned next. This README is expanded as each part of the system is
actually built — it never describes a feature, endpoint, or integration
ahead of the code that implements it.

### Running locally

```bash
# Backend
cd server && cargo run

# Frontend (separate terminal)
cd client && npm install && npm run dev

# Or the full stack
docker compose up --build
```

---

## Purpose

Anatolia B.I.S. does not make automated final identity decisions from a
face alone. The intended workflow is:

1. An authorized operator uploads or captures a face image, bound to a case
   reference and a stated search purpose.
2. The system validates image quality and extracts a face representation
   through a biometric provider abstraction.
3. The system searches only authorized biometric/identity data sources.
4. The system returns ranked candidate matches with similarity scores — not
   a final verdict.
5. A human operator reviews candidates and records the verification outcome.

---

## Architecture

| Layer | Technology | Status |
|---|---|---|
| Backend | Rust, single Axum binary, SQLx (PostgreSQL in production, SQLite for local development) | Authentication, admin, and search workflow implemented |
| Biometric provider | Abstracted interface; mock implementation first, server-side ONNX-based implementation later | Mock implemented |
| Vector search / connectors | Abstracted providers — never hard-coupled to one vector database or one external data source | Planned |
| Frontend | React, TypeScript, Vite, i18next | Auth + search workflow implemented |
| Desktop | Tauri, wrapping the same web client | Planned |
| Android / iOS | Thin clients (capture/upload + result display); biometric inference and search always run server-side | Planned |
| Deployment | Render, single native Rust web service (serves the built frontend itself — no separate static-site resource) | Documented (`docs/DEPLOYMENT.md`); provisioning in progress |

See `CLAUDE.md` for the full architecture rationale.

---

## Core Principles

- **Candidates, not verdicts** — the biometric engine returns ranked, scored
  candidates for human review. A "Confirmed Identity" status is only ever
  set by an explicit human verification action.
- **Least privilege** — role-based access control (SYSTEM_ADMIN,
  SECURITY_ADMIN, OPERATOR, REVIEWER, AUDITOR).

---

## Internationalization

The application is i18n-first from its very first implementation. Supported
languages: English (default), Turkish, German, French, Arabic, Russian.
Arabic renders with full RTL layout. No user-facing string is ever
hardcoded.

---

## Repository Documentation

- `AGENTS.md` — enforced workflow, commit/PR, and code standards for anyone
  (human or automated) contributing to this repository.
- `CLAUDE.md` — project context and architecture guidance.

---

## License

Proprietary — see [LICENSE.txt](LICENSE.txt). All rights reserved; this
source is not licensed for copying, modification, or redistribution without
the Company's prior written consent.

© 2026 Bold Askeri Teknoloji ve Savunma Sanayi A.Ş. · All Rights Reserved
