# CLAUDE.md

Project guidance for Claude Code (and any other AI coding assistant) working in this repository.

## Project

Anatolia B.I.S. is a secure, institutional biometric candidate-matching and identity
verification platform for authorized use. It returns ranked candidate matches with
similarity scores for human review — it never issues an automated final identity verdict.

Core product principles (do not weaken these when implementing features):
- Candidates, not verdicts: the biometric engine returns ranked, scored candidates. A
  "Confirmed Identity" status is only ever set by an explicit human verification action.
- Least privilege via RBAC: SYSTEM_ADMIN, SECURITY_ADMIN, OPERATOR, REVIEWER, AUDITOR.

## Architecture

- **Backend**: Rust, single Axum binary (API + WebSocket where needed), SQLx against
  PostgreSQL in production with SQLite as a local-development fallback only. The same
  binary also serves the built frontend (with an SPA fallback) from the same origin —
  one deployed service, one URL; no separate frontend resource, no "api"/"web" in it.
- **Biometric provider**: behind a trait/interface abstraction (`BiometricProvider`),
  implemented first as a mock provider so the full workflow is developable and testable
  without a real model. A production provider (ONNX Runtime via `ort`, running
  server-side) is added later behind the same interface.
- **Vector search / connectors**: also behind provider abstractions — never hard-couple
  the core application to one vector database or one external data source.
- **Frontend**: React + TypeScript + Vite, i18next for translations.
- **Desktop**: Tauri, wrapping the same web client.
- **Android / iOS**: thin clients only (capture/upload + result display). Biometric
  inference and candidate search always run server-side — never on-device. This is a
  deliberate architectural choice, not a temporary limitation: it keeps every search
  auditable and centrally governed, and it avoids the cross-compilation and iOS
  subprocess constraints that on-device inference would run into.
- **Deploy**: Render, a single native Rust web service, `GET /api/health` reports the live
  commit SHA.

## Repository Rules

See `AGENTS.md` for the authoritative, enforced rules on workflow, commit/PR style, and
code standards (English-only source, i18n-first, no AI attribution anywhere in repository
history). Those rules apply in full here — this file adds project context on top of them,
it does not relax them.

## Working in this repository

- Confirm scope with the repository owner before starting large, multi-phase work —
  implement incrementally rather than attempting the full platform in one pass.
- A feature is not complete until its documentation is updated (API.md for API changes,
  docs/ARCHITECTURE.md for architecture changes, all six locales for user-facing text,
  SECURITY.md / docs/SECURITY_ARCHITECTURE.md for security-relevant behavior).
- Never claim a feature is implemented or tested unless it was actually run and verified.
  Label planned-but-unimplemented features explicitly as planned.
- Never commit secrets, real biometric data, real subject photographs, or production
  credentials. Only `.env.example` placeholders belong in the repository.
- Always ask the repository owner for confirmation before running `git push`, to any
  branch, no matter how small the change — commits can be prepared locally first, but
  the push itself always waits for explicit go-ahead.
