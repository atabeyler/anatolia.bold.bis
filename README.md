# Anatolia B.I.S.

[![License: Proprietary](https://img.shields.io/badge/license-proprietary-red)](LICENSE.txt)

**Bold Askeri Teknoloji ve Savunma Sanayi A.Ş.**

A secure biometric candidate-matching and identity verification platform for
authorized institutional use.

---

## Project Status

**Phase 1 (repository foundation) complete.** The backend shell (Rust/Axum,
`GET /api/health`), the frontend shell (React/TypeScript/Vite), the
six-language i18n system, Docker images, a local docker-compose stack, and
CI are implemented and verified (backend tests + clippy, frontend
typecheck + tests + build all pass). No authentication, database,
biometric provider, or search workflow exists yet — see
`docs/ROADMAP.md` for what's planned next. This README is expanded as each
part of the system is actually built — it never describes a feature,
endpoint, or integration ahead of the code that implements it.

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

Anatolia B.I.S. is not a mass-surveillance scraper. It does not crawl social
platforms and it does not make automated final identity decisions from a
face alone. The intended workflow is:

1. An authorized operator uploads or captures a face image, bound to a case
   reference and a stated search purpose.
2. The system validates image quality and extracts a face representation
   through a biometric provider abstraction.
3. The system searches only authorized biometric/identity data sources.
4. The system returns ranked candidate matches with similarity scores — not
   a final verdict.
5. A human operator reviews candidates and records the verification outcome.
6. Every sensitive action is written to an append-only audit log.

---

## Architecture

| Layer | Technology | Status |
|---|---|---|
| Backend | Rust, single Axum binary, SQLx (PostgreSQL in production, SQLite for local development) | Shell implemented (health endpoint only); SQLx not yet wired up |
| Biometric provider | Abstracted interface; mock implementation first, server-side ONNX-based implementation later | Planned |
| Vector search / connectors | Abstracted providers — never hard-coupled to one vector database or one external data source | Planned |
| Frontend | React, TypeScript, Vite, i18next | Shell implemented |
| Desktop | Tauri, wrapping the same web client | Planned |
| Android / iOS | Thin clients (capture/upload + result display); biometric inference and search always run server-side | Planned |
| Deployment | Render, native Rust binary | Documented (`docs/DEPLOYMENT.md`); not yet provisioned |

See `CLAUDE.md` for the full architecture rationale.

---

## Core Principles

- **Candidates, not verdicts** — the biometric engine returns ranked, scored
  candidates for human review. A "Confirmed Identity" status is only ever
  set by an explicit human verification action.
- **No indiscriminate scraping** — data access goes through authorized
  connector abstractions only.
- **Every sensitive action is audited**, append-only.
- **Least privilege** — role-based access control (SYSTEM_ADMIN,
  SECURITY_ADMIN, OPERATOR, REVIEWER, AUDITOR).
- **Privacy by default** — raw images are not retained beyond a
  configurable, short retention window.

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
