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
| `JWT_SECRET`, `JWT_REFRESH_SECRET`, `APPROVAL_TOKEN_SECRET` | Signing secrets for access tokens, refresh tokens, and registration approval-email links, respectively — three independent secrets, so compromising one token type doesn't compromise the others. Fall back to fixed local-development values if unset, so `cargo run`/`cargo test` work with zero setup. In production (`NODE_ENV=production` or `RENDER` set) all three are **required** and must each be at least 32 bytes — the app panics at startup rather than running with a missing or weak secret. Generate with `openssl rand -hex 32`. |
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
| `ALLOWED_ORIGINS` | Comma-separated list of origins allowed by CORS. The deployed app is single-origin (the backend serves the built frontend itself — see `STATIC_DIR`), so this is normally unset in production; it only matters for local dev when running the frontend's own dev server on a different origin, or for a future cross-origin client (mobile/desktop). If unset, all cross-origin requests are rejected — a deliberate fail-closed default. | No |
| `STATIC_DIR` | Directory the built frontend (`client/dist`) is served from. Defaults to `../client/dist`, which is where a local `cd server && cargo run` finds it relative to `server/`. Render's single-service deploy (`render.yaml`) sets this to `client/dist` instead, since it builds and runs from the repository root. Any request that doesn't match an API route or an existing static file falls back to `index.html` (SPA routing). | No |
| `RUST_LOG` | Log level filter for structured logging (e.g. `info`, `debug`). Defaults to `info`. | No |
| `SERVER_DATA_DIR` | Directory the local SQLite fallback database is written to. Defaults to `server/data`. | No |
| `RESEND_FROM` | Sender address for outgoing email. Defaults to a `resend.dev` sandbox address. | No |
| `APP_URL` | The app's externally-reachable URL, used in emailed links. Falls back to `RENDER_EXTERNAL_URL` (which, since the deploy is single-service, is always the app's one real URL), then `http://localhost:8080`. | No |
| `RENDER_EXTERNAL_URL` | Set automatically by Render on a running web service; also the signal the backend uses to decide "this is the production web deploy, `DATABASE_URL` is mandatory here." | Platform-provided |
| `RENDER`, `NODE_ENV` | Either being set to a production value switches the refresh-token cookie to `Secure`, selects `SameSite=Lax`/`None` instead of the dev-only `Strict`, enables the `Strict-Transport-Security` header, and enforces the production secret-strength checks described above. | No |
| `TRUST_PROXY` | Set to `true` only when this deployment sits behind a reverse proxy you control that sets `X-Forwarded-For` itself. Governs whether login rate limiting and session `ip_address` records trust that header at all — an untrusted deployment ignores it entirely rather than trusting an attacker-controlled value. Defaults to the same value as "is this production" (Render always fronts the app with a trusted proxy); explicitly `false` disables it even in production if you know your deploy has no such proxy. | No |
| `GIT_COMMIT_SHA` | Build-time only (not a runtime env var). Passed as a Docker build arg when `.git` isn't available in the build context; `server/build.rs` falls back to reading the checkout's own commit directly otherwise. | No |
| `SEARCH_DEFAULT_TOP_K`, `SEARCH_MAX_TOP_K` | How many ranked candidates a search returns when the client doesn't request a specific count, and the hard ceiling a client-requested `topK` is clamped to (never rejected outright — see `POST /api/v1/search/face` in `API.md`). Default `10` / `50`. | No |

## Frontend (`client/`)

| Variable | Description | Required |
|---|---|---|
| `VITE_API_BASE_URL` | Base URL the frontend uses for API requests. Defaults to `/api` (same-origin) if unset. | No |
