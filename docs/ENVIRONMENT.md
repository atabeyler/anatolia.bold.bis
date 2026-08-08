# Environment Variables

See `.env.example` for a copyable template. Never commit a real `.env`
file — only placeholders belong in the repository.

## Backend (`server/`)

| Variable | Description | Required |
|---|---|---|
| `PORT` | Port the server listens on. Defaults to `8080` if unset. | No |
| `ALLOWED_ORIGINS` | Comma-separated list of origins allowed by CORS. If unset, all cross-origin requests are rejected — this is a deliberate fail-closed default, not a bug. | No (but effectively required for any browser client) |
| `RUST_LOG` | Log level filter for structured logging (e.g. `info`, `debug`). Defaults to `info`. | No |
| `DATABASE_URL` | PostgreSQL connection string. **Reserved for Phase 2** — the Phase 1 backend does not read this yet. | No (not yet used) |
| `GIT_COMMIT_SHA` | Build-time only (not a runtime env var). Passed as a Docker build arg when `.git` isn't available in the build context; `server/build.rs` falls back to reading the checkout's own commit directly otherwise. | No |

## Frontend (`client/`)

| Variable | Description | Required |
|---|---|---|
| `VITE_API_BASE_URL` | Base URL the frontend uses for API requests. Defaults to `/api` (same-origin) if unset. | No |
