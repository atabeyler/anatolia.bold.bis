# Anatolia B.I.S.

[![Version](https://img.shields.io/github/package-json/v/atabeyler/anatolia.bold.bis?filename=client%2Fpackage.json)](client/package.json)
[![CI](https://github.com/atabeyler/anatolia.bold.bis/actions/workflows/ci.yml/badge.svg)](https://github.com/atabeyler/anatolia.bold.bis/actions/workflows/ci.yml)
[![License: Proprietary](https://img.shields.io/badge/license-proprietary-red)](LICENSE.txt)

**Bold Askeri Teknoloji ve Savunma Sanayi A.Ş.**

A secure biometric candidate-matching and identity verification platform for
authorized institutional use.

---

## Project Status

**Phases 1–5 substantially complete; Phase 6 (hardening) in progress.**
See `docs/ROADMAP.md` for the authoritative, item-by-item status — this
section is a summary, not the source of truth.

- **Authentication & access control**: JWT auth (register/login/refresh/
  logout/logout-all) backed by real server-side sessions with
  refresh-token rotation and reuse detection, bcrypt password hashing,
  TOTP multi-factor authentication (voluntary for any role, mandatory for
  configured roles), self-service session/device management (list and
  revoke individual sessions), RBAC (`SYSTEM_ADMIN`, `SECURITY_ADMIN`,
  `OPERATOR`, `REVIEWER`, `AUDITOR`), an organization/unit model with
  object-level authorization, an admin-approval workflow for new
  registrations, layered rate limiting, and a production-only
  CSP/Permissions-Policy/HSTS header set — see `API.md` and
  `docs/SECURITY_ARCHITECTURE.md`.
- **Audit trail**: every security- or case-relevant action is recorded to
  an append-only, hash-chained audit trail with an on-demand integrity
  check, browsable at `GET /api/v1/audit` and in a dedicated frontend
  screen.
- **Biometric search**: real, non-mock face detection/embedding (YuNet +
  SFace via ONNX Runtime) is implemented behind the `BiometricProvider`
  trait, selected via `BIOMETRIC_PROVIDER=onnx` and the `onnx-provider`
  Cargo feature — **not the default**, and **not yet exercised as a live
  production deployment** (see `docs/ROADMAP.md` Phase 4 and
  `docs/ENTERPRISE_DEPLOYMENT.md`). `MockBiometricProvider` remains the
  default, deterministic, non-biometric stand-in behind the same trait.
  Vector search runs a correct in-memory scan everywhere, plus a native
  `pgvector`-indexed path on PostgreSQL when the extension is available.
- **OSINT/evidence**: real (non-mock) web-search and news connectors,
  independently enabled per API key, wrapped in a timeout/retry/circuit-breaker;
  conservative entity resolution (possible-duplicate detection) and a
  candidate-centric entity graph (aliases/usernames/organizations/websites),
  both advisory-only. A per-candidate OSINT workspace in the frontend
  drives evidence collection and entity-graph editing.
  A real `AuthorizedSocialProvider` is not implemented — every
  candidate social-platform API requires its own developer agreement not
  available in this environment.
- **Administration**: user management, organization/unit management,
  system diagnostics (readiness, calibrated biometric thresholds, OSINT
  connector status, on-demand audit-integrity check) in a tabbed admin
  panel.
- **Verified**: backend integration tests (auth, sessions, search,
  review, audit, organizations, entity graph, entity resolution,
  calibration, connectors, and a full end-to-end registration → search →
  review → evidence → entity-graph → audit-integrity scenario) + clippy +
  `cargo fmt --check`, frontend typecheck + tests + build + lint, all
  passing in CI (`.github/workflows/ci.yml`).
- **Not yet implemented**: occlusion detection (no reliable heuristic
  without a trained model), a real `AuthorizedSocialProvider`, reverse
  image search, enterprise SSO, thin Android/iOS clients, automated
  backups. See `docs/ROADMAP.md` for the complete list with rationale for
  each gap.

This README is expanded as each part of the system is actually built — it
never describes a feature, endpoint, or integration ahead of the code that
implements it.

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
| Backend | Rust, single Axum binary, SQLx (PostgreSQL in production, SQLite for local development) | Implemented |
| Biometric provider | Abstracted interface; mock implementation (default) and a real ONNX-based implementation (YuNet + SFace) behind the same trait | Both implemented; ONNX is opt-in and not yet live-verified in production |
| Vector search | In-memory brute-force scan (all backends) plus a native `pgvector`-indexed path on PostgreSQL | Implemented |
| Connectors / OSINT | Abstracted providers (web search, news, social) — never hard-coupled to one external data source; real web-search/news providers, mock social | Web search + news implemented (real, opt-in); social remains mock only |
| Frontend | React, TypeScript, Vite, i18next | Implemented |
| Desktop | Tauri, wrapping the same web client | Planned |
| Android / iOS | Thin clients (capture/upload + result display); biometric inference and search always run server-side | Planned |
| Deployment | Render, single native Rust web service (serves the built frontend itself — no separate static-site resource) | Documented and configured (`render.yaml`, `docs/DEPLOYMENT.md`, `docs/ENTERPRISE_DEPLOYMENT.md`) |

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
- `API.md` — the full HTTP API reference; `docs/openapi.json` is its
  machine-readable counterpart, checked in CI to never drift from the
  real routes.
- `docs/ARCHITECTURE.md` — system architecture and component boundaries.
- `docs/SECURITY_ARCHITECTURE.md` — authentication, authorization,
  encryption, audit-trail, and other security-relevant design decisions.
- `docs/THREAT_MODEL.md` — a STRIDE-style pass over the threats
  considered and their current mitigation (or explicit "not yet
  addressed") status.
- `docs/DATA_FLOW.md` — end-to-end data flow for each major workflow
  (registration, login, search, review, audit).
- `docs/DEPLOYMENT.md` — how this deploys (Render, Docker Compose),
  migrations, and backups.
- `docs/ENTERPRISE_DEPLOYMENT.md` — a readiness summary for institutional
  deployment: identity/access, data protection, scaling, observability,
  incident response, and what to do before going live with real data.
- `docs/ENVIRONMENT.md` — every environment variable this application
  reads, what it controls, and whether it's required in production.
- `docs/I18N.md` — the internationalization system and how to add a
  translation key.
- `docs/ROADMAP.md` — the authoritative, phase-by-phase implementation
  status; `docs/HARDENING_CHECKLIST.md` is the detailed session-by-session
  hardening log behind it.

---

## License

Proprietary — see [LICENSE.txt](LICENSE.txt). All rights reserved; this
source is not licensed for copying, modification, or redistribution without
the Company's prior written consent.

© 2026 Bold Askeri Teknoloji ve Savunma Sanayi A.Ş. · All Rights Reserved
