# Changelog

Notable changes to Anatolia B.I.S., newest first.

## [Unreleased]

## [0.2.0] - 2026-08-09

- Restricted the search/candidate view endpoints (`GET /api/v1/search`,
  `/search/{id}`, `/search/{id}/candidates`, `/candidates/{id}`) to the
  OPERATOR, REVIEWER, SECURITY_ADMIN, SYSTEM_ADMIN, and AUDITOR roles,
  instead of any authenticated user — matching the read-only AUDITOR role
  already described in `docs/SECURITY_ARCHITECTURE.md`. See `API.md`.
- Fixed the Light appearance setting not applying to the sign-in panel and
  the Menu/Settings overlay, which kept a hardcoded dark background and
  text colors regardless of the selected theme.
- Hid the "New Search" form from roles that aren't allowed to start a
  search, showing a view-only notice instead.
- Added a demo/mock-engine notice to the search form, in all six locales,
  clarifying that match scores are simulated pending a real biometric
  provider.
- Made past-search cards keyboard-accessible.

## [0.1.0] - Initial development

- Implemented Phase 2 authentication: SQLx-backed `users` table
  (PostgreSQL production, SQLite local fallback), JWT access/refresh
  tokens, bcrypt password hashing, RBAC roles (SYSTEM_ADMIN,
  SECURITY_ADMIN, OPERATOR, REVIEWER, AUDITOR), an admin-approval
  workflow for new registrations (with email notifications via Resend,
  silently skipped if unconfigured), a rate-limited/constant-time-compared
  admin bootstrap endpoint, and per-key rate limiting on
  login/registration/admin-seed. See `API.md`.
- Implemented the Phase 1 repository foundation: a Rust/Axum backend shell
  (`GET /api/health` reporting the live commit SHA), a React/TypeScript/Vite
  frontend shell, a six-language i18n system (English, Turkish, German,
  French, Arabic, Russian) with Arabic RTL support and a locale key-tree
  consistency test, Docker images for both services plus a local
  docker-compose stack, and GitHub Actions CI (backend clippy/tests,
  frontend typecheck/tests/build).
- Added `API.md`, `SECURITY.md`, `CONTRIBUTING.md`, and
  `docs/{ARCHITECTURE,I18N,SECURITY_ARCHITECTURE,ROADMAP,DEPLOYMENT,ENVIRONMENT}.md`.
- Added `AGENTS.md` and `CLAUDE.md`, establishing repository engineering
  rules, target architecture, and documentation standards ahead of any
  application code.
- Added `README.md` describing project purpose, architecture, and core
  product principles.
- Added `LICENSE.txt` (proprietary).
