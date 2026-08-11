# Environment Variables

See `.env.example` for a copyable template. Never commit a real `.env`
file — only placeholders belong in the repository.

## Backend build-time Cargo features

`server/Cargo.toml` defines one opt-in feature: **`onnx-provider`**,
which compiles in the real `BiometricProvider` implementation (YuNet
detection + SFace embedding via ONNX Runtime — see `server/src/biometric/onnx_provider.rs`).
It was off by default on Render's native Rust buildpack — enabling it
there fails to link. The root cause, confirmed empirically (not just
inferred from the error message): `ort`'s "download-binaries" feature
statically links a prebuilt `libonnxruntime.a` at build time, and that
archive requires glibc **>= 2.38** (the ISO C23 additions, e.g.
`__isoc23_strtoll`). Render's buildpack build image, like Debian
"bookworm" (glibc 2.36), is too old; Debian "trixie" (glibc 2.40) links
it cleanly. Once linked, the binary is fully self-contained — no
runtime network dependency for ONNX Runtime itself (`ldd` shows no
`onnxruntime` entry at all); only the YuNet/SFace *model* files are a
runtime download, already documented below (`MODEL_CACHE_DIR`).

**Enabled on Render**: `render.yaml` now deploys `anatolia-bis` as a
`runtime: docker` service (`dockerfilePath: ./Dockerfile`, repository
root, already targeting Debian trixie) rather than the native buildpack,
with `ONNX_PROVIDER=true` set as a service env var — Render forwards
every service env var to the Docker build as a matching `--build-arg`,
which the `Dockerfile`'s `server-builder` stage consumes. `BIOMETRIC_PROVIDER=onnx`
is set accordingly, and `ALLOW_MOCK_BIOMETRICS` is left unset (see the
row below). This has been verified locally — both `cargo build --release
--features onnx-provider` linking cleanly on a glibc 2.39 host, and a
real YuNet/SFace inference run end to end on a sample photo — but a live
Render deployment of the Docker runtime switch still needs to be watched
through its first real deploy (build time, cold-start latency now that
the free plan's ephemeral filesystem means `MODEL_CACHE_DIR` is
re-downloaded on every restart, and memory/CPU headroom on the free
plan) given this project's history of Render build breakage from
under-tested biometric-provider changes.

To build locally on a host you've confirmed can link `ort` (this
repository's own dev/CI environment does, on a glibc >= 2.38 host):

```bash
cargo build --release --features onnx-provider
```

Running a binary built *without* this feature with `BIOMETRIC_PROVIDER=onnx`
set is a clear, immediate startup panic (not a silent fallback to mock) —
see the `BIOMETRIC_PROVIDER` row below.

## Backend (`server/`)

Critical — the cloud/Postgres deploy refuses to start (or immediately
rejects requests) without these; a plain local dev run tolerates most of
them missing by falling back to SQLite and locally-generated defaults:

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string. May point at a database instance shared with another project — the backend creates and uses its own `anatolia_bis` schema there (never `public`), so its tables can't collide with anyone else's. On Render (`RENDER_EXTERNAL_URL` set) the server panics at startup if this is missing — it deliberately refuses to fall back to a throwaway SQLite database on the production web deploy. Locally, an unset `DATABASE_URL` falls back to a SQLite file under `SERVER_DATA_DIR` (default `server/data/dev.db`). |
| `JWT_SECRET`, `JWT_REFRESH_SECRET`, `APPROVAL_TOKEN_SECRET`, `MFA_TOKEN_SECRET` | Signing secrets for access tokens, refresh tokens, registration approval-email links, and login-time MFA challenge tokens, respectively — four independent secrets, so compromising one token type doesn't compromise the others. Fall back to fixed local-development values if unset, so `cargo run`/`cargo test` work with zero setup. In production (`NODE_ENV=production` or `RENDER` set) all four are **required** and must each be at least 32 bytes — the app panics at startup rather than running with a missing or weak secret. Generate with `openssl rand -hex 32`. |
| `ADMIN_SEED_TOKEN`, `ADMIN_USER_CODE`, `ADMIN_PASSWORD`, `ADMIN_EMAIL` | Required together to create the first `SYSTEM_ADMIN` account via `POST /api/v1/admin/seed-admin` (rate-limited to 5 attempts/15 min, constant-time token comparison). Without a seeded admin, no registration can ever be approved. The endpoint **self-disables** once any active `SYSTEM_ADMIN` exists — see `BOOTSTRAP_ENABLED` below. |
| `ALLOW_MOCK_BIOMETRICS` | In production, `BIOMETRIC_PROVIDER` defaults to the non-biometric `MockBiometricProvider` — see the row below. Production refuses to start with it unless this is explicitly set to `true`, a conscious acknowledgment that the deployment is not doing real face comparison. Not required if `BIOMETRIC_PROVIDER=onnx`, and not required outside production. |

Configured, but fails silently if wrong or missing — deserve extra care:

| Variable | What happens if it's missing |
|---|---|
| `RESEND_API_KEY` | Registration/approval/rejection/MFA-code emails are silently skipped (logged as a warning) — the triggering endpoint still responds normally regardless of whether the notification email actually went out. An account enrolling in email-method MFA with this unset will never receive its code. |
| `ADMIN_EMAIL` | Falls back to `info@boldkimya.com.tr` if unset. |
| `TAVILY_API_KEY` | Preferred web-search OSINT provider (`server/src/osint/tavily.rs`) — its free tier needs no payment method at signup, unlike Brave's. Checked before `BRAVE_SEARCH_API_KEY`; if neither is set, web-search evidence collection falls back to `MockWebSearchProvider` (synthetic results, clearly labeled as such). |
| `BRAVE_SEARCH_API_KEY` | Fallback web-search OSINT provider (`server/src/osint/websearch.rs`), used only when `TAVILY_API_KEY` is unset. Requires a paid Brave Search API plan. |
| `CURRENTS_API_KEY` | Preferred news OSINT provider (`server/src/osint/currents.rs`) — its free tier is documented as usable in production, unlike NewsAPI's (dev/localhost-only). Checked before `NEWS_API_KEY`; if neither is set, news evidence collection falls back to `MockNewsProvider`. |
| `NEWS_API_KEY` | Fallback news OSINT provider (`server/src/osint/news.rs`), used only when `CURRENTS_API_KEY` is unset. NewsAPI's own free-tier terms forbid production/commercial use. |

Everything else:

| Variable | Description | Required |
|---|---|---|
| `AUTO_OSINT_AFTER_BIOMETRIC_SEARCH` | When `true`, a completed biometric search automatically runs web/news OSINT evidence collection against its top-scoring candidates — see `search::run_queued_search`/`run_auto_osint`. Uses whichever web-search/news providers are configured above (real or mock, reported honestly either way — see `GET /api/v1/search/{id}/status`'s `externalEvidenceStatus`). Never touches the `AuthorizedSocialProvider` slot or any reverse-image capability, even when `true` — those stay manual-only (`POST /candidates/{id}/evidence/collect`) or `NOT_CONFIGURED`. Defaults to `false` in every environment, including production — this is an explicit opt-in, not a default behavior change. | No |
| `OSINT_AUTO_MAX_CANDIDATES` | Upper bound on how many of a search's top-scoring candidates `AUTO_OSINT_AFTER_BIOMETRIC_SEARCH` runs evidence collection against, regardless of the search's own `topK` — prevents a `topK=50` search from firing 50 external provider calls. A non-positive value is ignored (falls back to the default). Defaults to `5`. | No |

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
| `BIOMETRIC_PROVIDER` | Selects the `BiometricProvider` implementation (`server/src/biometric/`). `"mock"` (default, no real face comparison) or `"onnx"` (real YuNet detection + SFace embedding via ONNX Runtime). Any other value is a hard startup failure in every environment. `"onnx"` downloads and SHA-256-verifies its models at startup; a network failure or hash mismatch is a hard startup panic, never a silent fallback to the mock provider. **Requires the binary to have been built with `cargo build --features onnx-provider`** — see the note below; without it, `BIOMETRIC_PROVIDER=onnx` is a startup panic explaining the missing feature. See `ALLOW_MOCK_BIOMETRICS` above for the mock provider's additional production requirement. | No |
| `MODEL_CACHE_DIR` | Local cache directory `BIOMETRIC_PROVIDER=onnx` downloads/verifies its ONNX model files into. Defaults to `./data/models`. | No |
| `METRICS_TOKEN` | Optional bearer token gating `GET /metrics`. Unset (the default) leaves the endpoint open — the conventional Prometheus scrape posture, since nothing exported there is PII (fixed-cardinality labels only: HTTP method, route template, status code, provider name — never a raw path, user id, or IP). Compared in constant time, same as other secret comparisons in this codebase. | No |
| `BOOTSTRAP_ENABLED` | Explicitly re-opens `POST /api/v1/admin/seed-admin` after it has already self-disabled (see the `ADMIN_SEED_TOKEN` row above). Set to `true` only for a deliberate recovery — e.g. every `SYSTEM_ADMIN` account was lost — and unset it again immediately afterward. | No |
| `ENABLE_SELF_PING` | Set to `true` to enable a periodic self-ping that keeps a Render free-plan instance from cold-starting after ~15 minutes idle (see `main.rs`). **Defaults to disabled** — a background self-callback is surprising, free-plan-specific behavior a deployment shouldn't get automatically just because `RENDER_EXTERNAL_URL` is set. This project's own `render.yaml` sets it explicitly for the free-plan service it deploys. Has no effect outside Render even when set (`RENDER_EXTERNAL_URL` unset). | No |
| `MFA_REQUIRED_ROLES` | Comma-separated role list that must have MFA enrolled (TOTP or email — either satisfies the requirement) before login can complete (see `server/src/mfa.rs`, `API.md`). Defaults to `SYSTEM_ADMIN,SECURITY_ADMIN,REVIEWER`. Set to an empty value (`MFA_REQUIRED_ROLES=`) to disable mandatory MFA entirely — voluntary enrollment remains available to every role either way. | No |
| `REQUIRE_SECOND_REVIEW` | Set to `true` to require a second, different reviewer to finalize a candidate's confirm/reject decision — see `db::record_review_decision`, `API.md`. Defaults to `false` (a single reviewer's decision finalizes it, today's behavior). | No |
| `NATIONAL_ID_ENCRYPTION_KEY` | 64 hex characters (32 raw bytes) — AES-256-GCM key encrypting national ID numbers at rest (see `server/src/national_id.rs`). Falls back to a fixed development value if unset. In production, **required** and must decode to exactly 32 bytes — the app panics at startup otherwise. Generate with `openssl rand -hex 32`. Rotating this key makes every existing `national_id_encrypted` value undecryptable; there is no key-rotation/re-encryption tool yet (see `docs/SECURITY_ARCHITECTURE.md`). | Prod: Yes |

## Frontend (`client/`)

| Variable | Description | Required |
|---|---|---|
| `VITE_API_BASE_URL` | Base URL the frontend uses for API requests. Defaults to `/api` (same-origin) if unset. | No |
