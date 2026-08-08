# Deployment

## Target: Render

The backend deploys to Render as a native Rust binary — there is no Node
process at runtime for the API itself (the frontend build only runs during
the Render build step, if the frontend is deployed alongside it).

- **Build**: `cargo build --release` inside `server/`.
- **Start**: the resulting `anatolia-bis-server` binary.
- **Health check**: `GET /api/health`. Its `version` field is the exact
  commit SHA of the running build (embedded at compile time by
  `server/build.rs`) — compare it against a pushed commit to confirm a
  deployment actually went live, rather than assuming from push time
  alone.

A `render.yaml` blueprint will be added once the service is actually
provisioned on Render; until then, deployment configuration lives only in
this document and is not automated.

## Local: Docker Compose

```bash
cp .env.example .env
docker compose up --build
```

Starts three services: `postgres` (PostgreSQL 16), `api` (the Rust
backend), and `web` (the frontend, built and served via nginx). Note: the
Phase 1 backend does not yet read `DATABASE_URL` or connect to Postgres —
that wiring lands in Phase 2.

## Environment variables

See `docs/ENVIRONMENT.md` and `.env.example`.
