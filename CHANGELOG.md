# Changelog

Notable changes to Anatolia B.I.S., newest first.

## [Unreleased]

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
