# Environment Variables

See `.env.example` for a copyable template. Never commit a real `.env`
file — only placeholders belong in the repository.

## Backend (`server/`)

Critical — the cloud/Postgres deploy refuses to start (or immediately
rejects requests) without these; a plain local dev run tolerates most of
them missing by falling back to SQLite and locally-generated defaults:

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string. May point at a database instance shared with another project — the backend creates and uses its own `anatolia_bis` schema there (never `public`), so its tables can't collide with anyone else's. On Render (`RENDER_EXTERNAL_URL` set) the server panics at startup if this is missing — it deliberately refuses to fall back to a throwaway SQLite database on the production web deploy. Locally, an unset `DATABASE_URL` falls back to a SQLite file under `SERVER_DATA_DIR` (default `server/data/dev.db`). |
| `JWT_SECRET`, `JWT_REFRESH_SECRET` | JWT signing secrets. Fall back to fixed local-development values if unset, so `cargo run`/`cargo test` work with zero setup — **must** be set to real random values in production. |
| `ADMIN_SEED_TOKEN`, `ADMIN_USER_CODE`, `ADMIN_PASSWORD`, `ADMIN_EMAIL` | Required together to create the first `SYSTEM_ADMIN` account via `POST /api/v1/admin/seed-admin` (rate-limited to 5 attempts/15 min, constant-time token comparison). Without a seeded admin, no registration can ever be approved. |

Configured, but fails silently if wrong or missing — deserve extra care:

| Variable | What happens if it's missing |
|---|---|
| `RESEND_API_KEY` | Registration/approval/rejection emails are silently skipped (logged as a warning) — the register endpoint still responds `201 Created` regardless of whether the notification email actually went out. |
| `ADMIN_EMAIL` | Falls back to `info@boldkimya.com.tr` if unset. |

Everything else:

| Variable | Description | Required |
|---|---|---|
| `PORT` | Port the server listens on. Defaults to `8080` if unset. | No |
| `ALLOWED_ORIGINS` | Comma-separated list of origins allowed by CORS. If unset, all cross-origin requests are rejected — a deliberate fail-closed default. | No (but effectively required for any browser client) |
| `RUST_LOG` | Log level filter for structured logging (e.g. `info`, `debug`). Defaults to `info`. | No |
| `SERVER_DATA_DIR` | Directory the local SQLite fallback database is written to. Defaults to `server/data`. | No |
| `RESEND_FROM` | Sender address for outgoing email. Defaults to a `resend.dev` sandbox address. | No |
| `APP_URL` | The app's externally-reachable URL, used in emailed links. Falls back to `RENDER_EXTERNAL_URL`, then `http://localhost:8080`. | No |
| `RENDER_EXTERNAL_URL` | Set automatically by Render on a running web service; also the signal the backend uses to decide "this is the production web deploy, `DATABASE_URL` is mandatory here." | Platform-provided |
| `RENDER`, `NODE_ENV` | Either being set to a production value switches the refresh-token cookie to `Secure` and selects `SameSite=Lax`/`None` instead of the dev-only `Strict`. | No |
| `GIT_COMMIT_SHA` | Build-time only (not a runtime env var). Passed as a Docker build arg when `.git` isn't available in the build context; `server/build.rs` falls back to reading the checkout's own commit directly otherwise. | No |

## Frontend (`client/`)

| Variable | Description | Required |
|---|---|---|
| `VITE_API_BASE_URL` | Base URL the frontend uses for API requests. Defaults to `/api` (same-origin) if unset. | No |
