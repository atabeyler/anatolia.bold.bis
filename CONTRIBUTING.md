# Contributing

This repository follows the rules in `AGENTS.md` (enforced) and `CLAUDE.md`
(project context) — read both before contributing. Summary:

- All source code, identifiers, comments, logs, tests, and documentation
  are written in English, with no exceptions.
- All user-facing text goes through the i18n system (`client/src/i18n/`);
  no hardcoded user-facing strings, ever, including during prototyping.
  Every locale file must carry the same set of translation keys.
- Commits and pull requests read as normal professional engineering work —
  no AI-assistant attribution, signatures, or tool names anywhere in
  commit messages, PR text, branch names, or code comments.
- Work targets the `main` branch.

## Local development

Backend:

```bash
cd server
cargo test
cargo clippy --all-targets -- -D warnings
cargo run
```

Frontend:

```bash
cd client
npm install
npm run typecheck
npm run test
npm run dev
```

Full stack:

```bash
docker compose up --build
```

## Documentation

A feature is not complete until its documentation is updated:
- API changes → `API.md`
- Architecture changes → `docs/ARCHITECTURE.md`
- User-facing text → all six locales
- Security-relevant behavior → `SECURITY.md` / `docs/SECURITY_ARCHITECTURE.md`
- Repository engineering behavior → `AGENTS.md`

Never describe a feature as implemented unless it was actually run and
verified. Label planned-but-unimplemented work explicitly as planned.
