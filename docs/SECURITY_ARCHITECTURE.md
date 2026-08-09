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

## Not yet implemented

MFA, organization/unit-scoped authorization, enterprise SSO, and real
upload validation (MIME/size/dimension/corruption checks) are planned
(see `docs/ROADMAP.md`) but not present in the codebase yet. Do not
assume any of them are active.
