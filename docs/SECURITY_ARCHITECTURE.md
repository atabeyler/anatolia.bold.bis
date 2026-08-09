# Security Architecture

This document describes security-relevant design decisions. See
`SECURITY.md` for the current implementation status and vulnerability
reporting.

## Design principles

- **Candidates, not verdicts**: the biometric engine returns ranked,
  scored candidates for human review. A "Confirmed Identity" status is
  only ever set by an explicit human verification action — never derived
  automatically from a similarity score.
- **Least privilege**: RBAC with five roles — `SYSTEM_ADMIN`,
  `SECURITY_ADMIN`, `OPERATOR`, `REVIEWER`, `AUDITOR`. `OPERATOR` (and
  `REVIEWER`/`SECURITY_ADMIN`/`SYSTEM_ADMIN`) may create searches;
  confirming/rejecting a candidate is restricted to `REVIEWER`,
  `SECURITY_ADMIN`, and `SYSTEM_ADMIN`; `SYSTEM_ADMIN`/`SECURITY_ADMIN`
  handle system configuration and user administration. `AUDITOR` can view
  search/candidate data but cannot create searches or review candidates.
  A newly approved registration is granted `OPERATOR` by default — the
  least-privileged authenticated role — and must be explicitly promoted
  by an admin.

## Implemented today

- Baseline security response headers on every response, including a
  `Content-Security-Policy` and `Permissions-Policy` tuned to the actual
  Vite build (no `unsafe-inline`, no wildcard origins) and a
  production-only `Strict-Transport-Security` (see `SECURITY.md`).
- CORS restricted to an explicit origin allow-list; credentialed
  (cookie-carrying) requests require an explicit origin and header list —
  never a wildcard. The allowed-method list is kept in sync with what the
  frontend actually sends (including `PATCH` for admin user edits).
- Per-request IDs for traceability without logging sensitive payloads.
- A single stable error shape (`ApiError`) — no stack traces or internal
  detail ever reaches the client.
- JWT authentication (15-minute access token in the response body,
  30-day refresh token as an `HttpOnly` cookie backed by a real
  server-side session), bcrypt password hashing, RBAC role enforcement on
  admin and search/candidate routes, layered rate limiting on
  login/registration/admin-seed/forgot-password, and an admin-approval
  gate on every new registration.
- **Centralized secret configuration**: `Config::from_env` (`server/src/config.rs`)
  resolves `JWT_SECRET`, `JWT_REFRESH_SECRET`, and `APPROVAL_TOKEN_SECRET`
  once at process startup and stores them in `AppState` — request
  handlers never re-read the environment per token operation. In
  production, a missing or sub-32-byte secret is a hard startup panic.
- **Session table and refresh-token rotation** (`server/src/db.rs`
  `sessions` table; `server/src/auth.rs` `login`/`refresh`/`logout`/
  `logout_all`): one row per token family, storing only a SHA-256 hash of
  the current refresh token (never the raw value). Every refresh rotates
  the row's hash and expiry and increments `rotation_counter`. Presenting
  a refresh token whose hash doesn't match the session's current
  hash — i.e. a previously rotated-away token — or a token belonging to
  an already-revoked session, revokes the whole family
  (`revoke_session_family`) and forces re-authentication; this is the
  refresh-token-theft/reuse defense. `logout` revokes one session;
  `logout_all` revokes every session for the caller; banning a user
  revokes all of theirs immediately.
- **Approval-token isolation**: registration approve/reject email links
  are signed with `APPROVAL_TOKEN_SECRET` (distinct from both JWT
  secrets) and independently tracked in the `approval_tokens` table as a
  hash with `consumed_at`/`result` — a link works exactly once, whether
  it succeeds or fails, and reuse is rejected even though the JWT itself
  would still verify.
- **Self-service password reset** (`server/src/auth.rs`
  `forgot_password`/`reset_password`): for accounts with an email on file,
  `forgot-password` issues a single-use, hashed, 1-hour-TTL token (reusing
  the `approval_tokens` table with `purpose = "password_reset"`, distinct
  from registration-approval tokens) and emails a reset link directly to
  the account holder; accounts without an email keep the existing
  admin-notification fallback. `reset-password` looks the token up by
  hash, requires the matching purpose, an unconsumed state, and an
  unexpired TTL, and consumes it atomically **before** the password is
  changed — a concurrent replay of the same raw token can never land
  twice. On success it revokes every active session for the account
  (`revoke_all_sessions_for_user`), forcing re-authentication on every
  other signed-in device, and records an `AUTH_PASSWORD_RESET_COMPLETED`
  audit event.
- **Registration-status enumeration protection**: `POST
  /api/v1/auth/register` returns a random, unguessable
  `registrationTrackingToken` (stored on the user row, not derived from
  the user code); `GET /api/v1/auth/registration-status/:trackingToken`
  is the only way to poll status, replacing the old
  `pending-status/:user_code` endpoint that let anyone probe arbitrary
  accounts' approval state by guessing codes.
- Refresh-cookie `SameSite` selection: `Strict` outside production;
  in production, `Lax` for same-origin requests and `None` (with
  `Secure`) only for the one legitimate cross-origin case (a
  desktop/mobile client's local bridge calling the cloud API) — never a
  blanket `None`.
- **Append-only audit trail** (`server/src/audit.rs`, `db::audit_events`):
  every security- or case-relevant action — auth (login/refresh/logout/
  reuse detection), registration approve/reject, user administration
  (create/update/ban/unban/delete), search create/complete/fail, candidate
  confirm/reject, and admin-seed use/failure — is recorded through one
  central `AuditRecorder` rather than ad-hoc `INSERT`s scattered across
  handlers. No code path ever `UPDATE`s or `DELETE`s an `audit_events`
  row. Records never include raw passwords, tokens, national IDs, or
  biometric data — only stable action codes, actor identity, result,
  resource references, and small, explicitly-constructed metadata.
  `GET /api/v1/audit` (server-side paginated and filtered) exposes it to
  `AUDITOR`, `SECURITY_ADMIN`, and `SYSTEM_ADMIN` only — the append-only
  guarantee is only meaningful if reading it is also access-controlled.
  A failed audit write is logged as a warning and never blocks or fails
  the request that triggered it.
- **Transactional search with a status state machine**
  (`db::create_search_with_candidates`): a search row and every one of its
  candidate results are written inside a single database transaction —
  `BEGIN`, insert search (`processing`), insert each candidate, mark
  `completed`, `COMMIT`. Any failure mid-way rolls the whole attempt back
  (no partial candidate list is ever visible), and a separate,
  non-transactional `record_failed_search` call then persists a `failed`
  search row with a `failureCode`/`failureMessageKey` so the failed
  attempt has a durable, queryable record instead of vanishing silently.
  `status` is one of `queued`/`processing`/`completed`/`failed`.
- **Immutable review history** (`verification_events` table,
  `db::record_review_decision`): every confirm/reject on a candidate
  appends a new event row (reviewer, decision, reason, notes, timestamp)
  in the same transaction as the `search_candidates` status update. A
  later decision on the same candidate — e.g. a second reviewer
  correcting the first — adds another event rather than overwriting the
  first; `GET /api/v1/search/{id}/candidates/{id}/history` returns the
  full, ordered trail.
- **Real probe-image validation** (`server/src/image_validation.rs`):
  magic-byte sniff plus an actual decode (JPEG/PNG/WEBP only, via the
  `image` crate), a 10 MB size cap, minimum/maximum pixel dimensions, and
  a decompression-bomb guard on total decoded pixel count — replacing a
  bare "the byte slice is non-empty" check. Failures return one of
  `IMAGE_TOO_LARGE`, `UNSUPPORTED_IMAGE_TYPE`, `IMAGE_DECODE_FAILED`,
  `IMAGE_DIMENSIONS_INVALID` (see `API.md`).
- **Coordinate validation**: `POST /api/v1/search/face` requires latitude
  in `[-90, 90]` and longitude in `[-180, 180]`, and rejects one being
  present without the other — a malformed capture, not a legitimate
  "location unavailable" case.
- **Configurable, server-enforced top-K**: `SEARCH_DEFAULT_TOP_K`/
  `SEARCH_MAX_TOP_K` (see `docs/ENVIRONMENT.md`) replace a compile-time
  constant; a client-requested `topK` above the configured ceiling is
  clamped down server-side, never trusted as-is.
- **Server-side pagination** on search history
  (`GET /api/v1/search?page=&pageSize=`, max page size 200), matching the
  pattern already used by `GET /api/v1/audit`.
- **Production guard against a silent mock biometric provider**
  (`Config::resolve_biometric_provider`, `server/src/config.rs`): only the
  non-biometric `MockBiometricProvider` exists today (see "Not yet
  implemented" below). `BIOMETRIC_PROVIDER` set to anything other than
  `"mock"` is a hard startup failure in every environment. In production,
  running the mock provider at all additionally requires an explicit
  `ALLOW_MOCK_BIOMETRICS=true` — without it, the app refuses to start,
  rather than silently serving deterministic-hash "matches" as if they
  were real biometric comparisons.
- **Last-admin protection** (`server/src/admin.rs`
  `would_remove_last_admin`): `ban_user` and `delete_user_route` both check
  `db::count_active_system_admins` before acting and refuse
  (`409 Conflict`, `LAST_ADMIN_PROTECTED`) if the target is the only
  active `SYSTEM_ADMIN` remaining. Without this, an admin could ban or
  delete themselves (or every other admin, one call at a time) and leave
  the platform with no way to administer itself short of the seed-admin
  bootstrap — which the next bullet also closes off by default.
- **Self-disabling admin bootstrap**: `admin::seed_admin` now checks
  `count_active_system_admins` after the seed-token comparison succeeds;
  if any active admin already exists, it refuses (`403 Forbidden`) even
  though the token is correct and the requested `ADMIN_USER_CODE` is new.
  `BOOTSTRAP_ENABLED=true` is a deliberate, explicit override for
  recovery. This closes a real window: previously, anyone who obtained
  `ADMIN_SEED_TOKEN` after go-live (e.g. through a leaked deployment
  config) could mint themselves an additional `SYSTEM_ADMIN` account
  indefinitely.
- **Request-ID validation** (`server/src/error.rs::request_id`, now the
  single shared implementation used by `admin`/`audit`/`auth`/`search`
  instead of four independent copies): a client-supplied `x-request-id`
  is only trusted if it is 1–128 ASCII letters/digits/`-`/`_`; anything
  else — oversized, empty, or containing other characters — is replaced
  with a generated UUID before it is echoed back or written into an audit
  record.
- **Database constraints on `search_candidates`/`searches`**: a unique
  index on `search_candidates (search_id, candidate_id)` makes "a
  candidate appears at most once per search" a database-enforced
  invariant rather than one relying solely on `create_search_with_candidates`
  never inserting a duplicate; indexes on `searches (created_at,
  case_reference, requested_by)` match the columns `list_searches_page`
  actually filters and sorts by.
- **Readiness endpoint** (`GET /api/health/ready`,
  `server/src/routes/health.rs`): distinct from the existing liveness
  check (`GET /api/health`, which never touches the database and stays
  `200` through a database outage), this runs a trivial query against the
  real backend and returns `503` if it fails — the check an orchestrator
  or load balancer should actually gate traffic on.

## Not yet implemented

MFA, organization/unit-scoped authorization, and enterprise SSO are
planned (see `docs/ROADMAP.md`) but not present in the codebase yet. Do
not assume any of them are active. The admin user list
(`GET /api/v1/admin/users`) is intentionally not yet paginated — a small,
bounded, manually-managed dataset, unlike search history or the audit
trail.
