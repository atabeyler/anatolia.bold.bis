# Security

## Reporting a vulnerability

Report suspected vulnerabilities directly to the repository owner
(info@boldkimya.com.tr) rather than opening a public issue.

## Current state (Phase 3.7 — authentication hardening, audit trail, search/data correctness)

Implemented controls:
- Security response headers on every response: `X-Content-Type-Options`,
  `X-Frame-Options`, `Referrer-Policy`, `Cross-Origin-Opener-Policy`,
  `Content-Security-Policy`, `Permissions-Policy`, plus
  `Strict-Transport-Security` in production only (meaningless, and not
  sent, over plain-HTTP local dev).
- CORS restricted to an explicit `ALLOWED_ORIGINS` allow-list (no wildcard
  origins/headers, since the app sends credentialed/cookie-carrying
  requests); unset means every cross-origin request is rejected, not
  silently allowed. Method list kept in sync with what the frontend
  actually sends, including `PATCH` (admin user edits).
- Per-request IDs (`x-request-id`), propagated through logs and error
  responses, for traceability without logging sensitive payloads.
- Structured (JSON) logging; no raw request/response bodies, secrets, or
  tokens are logged.
- Error responses only ever return the stable `ApiError` shape (see
  `API.md`) — stack traces are never exposed to clients.
- Authentication: JWT access tokens (15 min) plus an `HttpOnly` refresh
  cookie backed by a real server-side session record (see "Sessions"
  below), passwords hashed with bcrypt, never stored or logged in plain
  text.
- **Production secret validation**: `JWT_SECRET`, `JWT_REFRESH_SECRET`,
  and `APPROVAL_TOKEN_SECRET` are three independent secrets, resolved
  once at startup by the central `Config` layer. In production
  (`NODE_ENV=production` or `RENDER` set) the app refuses to start if any
  is unset or shorter than 32 bytes — never a silent fallback to a
  development default. See `docs/ENVIRONMENT.md`.
- **Sessions and refresh-token rotation**: every login creates a
  `sessions` row (hashed refresh token only — the raw token is never
  persisted). Each `POST /api/v1/auth/refresh` rotates the refresh token
  and updates the session in place; presenting an already-rotated-away or
  already-revoked refresh token is treated as token theft and revokes the
  entire token family, forcing re-login. `POST /api/v1/auth/logout`
  revokes that one session; `POST /api/v1/auth/logout-all` revokes every
  session for the authenticated user. Banning a user immediately revokes
  all of their active sessions rather than waiting for their access token
  to expire.
- **Approval tokens are isolated from login tokens**: the registration
  approve/reject email link is signed with its own `APPROVAL_TOKEN_SECRET`
  (not the refresh secret) and is additionally tracked server-side in
  `approval_tokens` (hashed, single-use) — a link can approve or reject a
  registration exactly once.
- **Registration status is not enumerable**: `register` returns an
  unguessable `registrationTrackingToken`; the frontend polls
  `GET /api/v1/auth/registration-status/:trackingToken` with that token,
  not the account's own (guessable) user code, so status can't be probed
  for arbitrary accounts.
- New registrations start in `pending` status and require explicit admin
  approval before they can log in; the first admin account itself can
  only be created through a rate-limited, constant-time-compared seed
  token (`POST /api/v1/admin/seed-admin`).
- RBAC: five roles (`SYSTEM_ADMIN`, `SECURITY_ADMIN`, `OPERATOR`,
  `REVIEWER`, `AUDITOR`); admin routes require `SYSTEM_ADMIN` or
  `SECURITY_ADMIN`. Approved registrations are granted `OPERATOR` (least
  privilege) by default.
- Rate limiting on login: per-account (10/15 min), per-IP (50/15 min),
  and a tight burst window (10/1 min) — the IP-based checks only apply
  when the deployment is configured to trust `X-Forwarded-For` (see
  `TRUST_PROXY` in `docs/ENVIRONMENT.md`); an untrusted proxy header is
  never used to drive rate limiting. Also: registration (20/15 min
  globally), admin seed (5/15 min globally), forgot-password (5/15 min
  per identifier).
- Refresh-token cookie `SameSite`/`Secure` attributes are selected based
  on whether the request is same-origin and whether the server is running
  in production — see `docs/SECURITY_ARCHITECTURE.md`.
- **Append-only audit trail**: every security- or case-relevant action
  (auth success/failure, token reuse detection, registration approve/
  reject, user create/update/ban/unban/delete, search create/complete/
  fail, candidate confirm/reject, admin-seed use/failure) is recorded
  through a single central `AuditRecorder`, never an ad-hoc `INSERT`.
  Nothing ever `UPDATE`s or `DELETE`s an audit row. `GET /api/v1/audit`
  (server-side paginated/filtered) is restricted to `AUDITOR`,
  `SECURITY_ADMIN`, and `SYSTEM_ADMIN`. See `docs/SECURITY_ARCHITECTURE.md`.
- **Transactional search + immutable review history**: a search and all
  of its candidate results are written in one database transaction — a
  failure rolls back rather than leaving a partial result set, and is
  recorded as a `failed` search for traceability. Every confirm/reject
  decision is appended to `verification_events` rather than overwriting
  the previous one.
- **Real probe-image validation**: magic-byte sniff plus an actual decode
  (JPEG/PNG/WEBP only), a 10 MB size cap, dimension limits, and a
  decompression-bomb guard — replacing a bare non-empty-bytes check. See
  `docs/SECURITY_ARCHITECTURE.md`.
- **Coordinate validation**: latitude/longitude are range-checked and
  required to be a matched pair; malformed geolocation data is rejected
  rather than silently stored.
- **Production guard against a silent mock biometric provider**: only the
  non-biometric `MockBiometricProvider` exists today. Production refuses
  to start with it unless `ALLOW_MOCK_BIOMETRICS=true` is explicitly set —
  a conscious acknowledgment, not a silent default. Any `BIOMETRIC_PROVIDER`
  value other than `mock` is a hard startup failure everywhere, since no
  other implementation exists yet. See `docs/SECURITY_ARCHITECTURE.md`.

## Planned (see `docs/ROADMAP.md` and `docs/SECURITY_ARCHITECTURE.md`)

MFA, organization-scoped authorization, and enterprise SSO are designed
but not yet implemented. Do not assume any of them are active until this
document is updated to say otherwise.

## Rules enforced in this repository

- No secrets, real biometric data, real subject photographs, or production
  credentials are ever committed. Only `.env.example` placeholders are
  checked in.
- Raw images are never logged.
