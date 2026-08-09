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

## Versioning

Every user-visible or behavioral change bumps the application version —
there is one version for the whole app, since it ships as a single
service. Both of the following must be updated together, to the same
value:
- `client/package.json`'s `version` field
- `server/Cargo.toml`'s `version` field

Nothing else needs to change by hand: the sign-in screen reads
`client/package.json`'s version at build time (`__APP_VERSION__`, wired in
`client/vite.config.ts`), and the README's version badge reads the same
field live from GitHub — both stay in sync automatically as long as this
one field is correct.

Bump the patch version (`0.2.0` → `0.2.1`) for fixes, the minor version
(`0.2.0` → `0.3.0`) for new functionality, and record the change under a
new dated heading in `CHANGELOG.md`. This is independent of the
deployment/runtime identifier: `GET /api/health` reports the live commit
SHA, which verifies a specific deploy picked up a specific push and is not
meant to be human-readable.

Never describe a feature as implemented unless it was actually run and
verified. Label planned-but-unimplemented work explicitly as planned.
