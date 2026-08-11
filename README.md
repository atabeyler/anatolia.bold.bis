# Anatolia B.I.S.

[![Version](https://img.shields.io/github/package-json/v/atabeyler/anatolia.bold.bis?filename=client%2Fpackage.json)](client/package.json)
[![CI](https://github.com/atabeyler/anatolia.bold.bis/actions/workflows/ci.yml/badge.svg)](https://github.com/atabeyler/anatolia.bold.bis/actions/workflows/ci.yml)
[![License: Proprietary](https://img.shields.io/badge/license-proprietary-red)](LICENSE.txt)

**Bold Askeri Teknoloji ve Savunma Sanayi A.Ş.**

A secure biometric candidate-matching and identity verification platform for
authorized institutional use.

---

## Project Status

Authentication and access control are built on JWT auth
(register/login/refresh/logout/logout-all) backed by real server-side
sessions with refresh-token rotation and reuse detection, bcrypt password
hashing, multi-factor authentication (TOTP or an emailed one-time code),
self-service session/device
management, RBAC (`SYSTEM_ADMIN`, `SECURITY_ADMIN`, `OPERATOR`,
`REVIEWER`, `AUDITOR`), an organization/unit model with object-level
authorization, and an admin-approval workflow for new registrations — see
`API.md` and `docs/SECURITY_ARCHITECTURE.md`. Every security- or
case-relevant action is recorded to an append-only, hash-chained audit
trail with an on-demand integrity check.

Biometric search runs behind a `BiometricProvider` trait: a deterministic
mock implementation by default, and a real, non-mock ONNX-based
implementation (YuNet detection + SFace embedding) opt-in via
`BIOMETRIC_PROVIDER=onnx` and the `onnx-provider` Cargo feature. Vector
search runs a correct in-memory scan everywhere, plus a native
`pgvector`-indexed path on PostgreSQL when the extension is available.

OSINT/evidence collection has real (non-mock) web-search and news
connectors, independently enabled per API key; conservative entity
resolution and a candidate-centric entity graph (aliases, usernames,
organizations, websites) surface possible duplicates and related
identifiers, both advisory-only, editable from a per-candidate OSINT
workspace in the frontend. A completed biometric search can automatically
trigger web/news evidence collection against its top-scoring candidates
(`AUTO_OSINT_AFTER_BIOMETRIC_SEARCH`, off by default — see
`docs/ENVIRONMENT.md`); it never runs the social slot or any
reverse-image capability, both of which stay `NOT CONFIGURED` in this
codebase (no real implementation of either exists — see
`docs/ENTERPRISE_DEPLOYMENT.md`) rather than being simulated. Biometric
similarity and OSINT evidence are always reported as separate signals,
never combined into a single identity-confidence score — the final
identity decision stays a human reviewer's, recorded through the existing
confirm/reject/inconclusive review workflow. Administration covers user
management, organization/unit management, and system diagnostics
(readiness, calibrated biometric thresholds, OSINT connector status, an
on-demand audit-integrity check) in a tabbed admin panel.

Not yet implemented: occlusion detection (no reliable heuristic exists
without a trained model), a real `AuthorizedSocialProvider` (every
candidate social-platform API requires its own developer agreement),
reverse image search, enterprise SSO, thin Android/iOS clients, and
automated backups — see `docs/ENTERPRISE_DEPLOYMENT.md` for the fuller
picture.

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

---

## License

Proprietary — see [LICENSE.txt](LICENSE.txt). All rights reserved; this
source is not licensed for copying, modification, or redistribution without
the Company's prior written consent.

© 2026 Bold Askeri Teknoloji ve Savunma Sanayi A.Ş. · All Rights Reserved
