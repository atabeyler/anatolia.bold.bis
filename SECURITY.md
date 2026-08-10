# Security

## Reporting a vulnerability

Report suspected vulnerabilities directly to the repository owner
(info@boldkimya.com.tr) rather than opening a public issue.

See `docs/THREAT_MODEL.md` for what this system defends against (and
what it deliberately does not yet) and `docs/DATA_FLOW.md` for how data
moves through it.

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
  to expire. `GET /api/v1/users/me/sessions` lists a user's own active
  sessions (device/browser string, IP, last used); `DELETE
  /api/v1/users/me/sessions/{id}` revokes one of them individually,
  ownership-checked so a session id belonging to another account is
  treated the same as an unknown one.
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
- **Self-service password reset**: accounts with an email on file receive
  a single-use, hashed, 1-hour-TTL reset token by email
  (`POST /api/v1/auth/forgot-password` →
  `POST /api/v1/auth/reset-password`); the token is consumed atomically
  before the password changes, and a successful reset revokes every
  active session for the account. Accounts without an email keep the
  existing admin-notification fallback. See `docs/SECURITY_ARCHITECTURE.md`.
- **Append-only audit trail**: every security- or case-relevant action
  (auth success/failure, token reuse detection, registration approve/
  reject, user create/update/ban/unban/delete, search create/complete/
  fail, candidate confirm/reject, admin-seed use/failure) is recorded
  through a single central `AuditRecorder`, never an ad-hoc `INSERT`.
  Nothing ever `UPDATE`s or `DELETE`s an audit row. `GET /api/v1/audit`
  (server-side paginated/filtered) is restricted to `AUDITOR`,
  `SECURITY_ADMIN`, and `SYSTEM_ADMIN`. See `docs/SECURITY_ARCHITECTURE.md`.
- **Async search + immutable review history**: `POST /api/v1/search/face`
  returns `202 Accepted` immediately with a queued search id; the
  biometric pipeline runs in a background task and is polled via
  `GET /api/v1/search/{id}/status`. The search and all of its candidate
  results are written in one database transaction when the background
  task finishes — a failure rolls back rather than leaving a partial
  result set, and marks the search `failed` for traceability instead. A
  `SEARCH_COMPLETED` audit write failure downgrades the search to
  `failed` too, so a poller never observes a `completed` status the audit
  trail can't back up. Every confirm/reject/inconclusive decision is
  appended to `verification_events` rather than overwriting the previous
  one.
- **Soft-deleted user accounts**: deleting a user marks `deleted_at`
  and revokes all of their sessions instead of physically removing the
  row, so past search/audit/review history stays attributable to a real
  account rather than an orphaned id. A deleted account cannot log in and
  no longer appears in the admin panel. See
  `docs/SECURITY_ARCHITECTURE.md`.
- **Real probe-image validation**: magic-byte sniff plus an actual decode
  (JPEG/PNG/WEBP only), a 10 MB size cap, dimension limits, and a
  decompression-bomb guard — replacing a bare non-empty-bytes check. See
  `docs/SECURITY_ARCHITECTURE.md`.
- **Coordinate validation**: latitude/longitude are range-checked and
  required to be a matched pair; malformed geolocation data is rejected
  rather than silently stored.
- **Production guard against a silent mock biometric provider**: the
  non-biometric `MockBiometricProvider` is still the default. Production
  refuses to start with it unless `ALLOW_MOCK_BIOMETRICS=true` is
  explicitly set — a conscious acknowledgment, not a silent default. Any
  `BIOMETRIC_PROVIDER` value other than `mock`/`onnx` is a hard startup
  failure everywhere. See `docs/SECURITY_ARCHITECTURE.md`.
- **Real biometric provider (`BIOMETRIC_PROVIDER=onnx`)**: YuNet face
  detection and SFace face embedding, run through ONNX Runtime (`ort`),
  behind the same `BiometricProvider` trait the mock implements. Both
  models are pinned by SHA-256 and fail closed — a hash mismatch or
  download failure at startup is a hard panic, never a silent fallback to
  the mock provider. A search probe or enrollment reference photo that
  fails detection, has more than one face, or fails a real (classical-CV,
  not ML) quality heuristic returns a specific `422` code
  (`NO_FACE_DETECTED`, `MULTIPLE_FACES_DETECTED`, `FACE_TOO_SMALL`,
  `IMAGE_TOO_BLURRY`, `EXCESSIVE_POSE`, `POOR_LIGHTING`,
  `LOW_FACE_QUALITY`) rather than a fabricated result. See
  `docs/SECURITY_ARCHITECTURE.md` for the honest limitations: occlusion
  detection is not implemented, and the detection/alignment math could
  only be tested against synthetic images in this environment (never real
  photographs — the repository must never contain real biometric data).
  Similarity search runs a correct in-memory O(n) scan on every backend,
  plus a native `pgvector`-indexed HNSW path on PostgreSQL when the
  extension can be enabled (`GET /api/health/ready` reports which path is
  active).
- **Metrics** (`GET /metrics`, `server/src/metrics.rs`): Prometheus text
  exposition format — HTTP request count/latency by method+route
  template+status, login failures by reason, biometric search
  duration/outcome by rejection code, OSINT provider outcomes by
  provider. Every label is a fixed, small-cardinality value; nothing
  exported is a raw path, user id, IP address, or other PII, matching
  the existing structured-logging rule. Open by default (conventional
  Prometheus scrape posture); an optional `METRICS_TOKEN` bearer token
  restricts it for deployments that prefer not to expose operational
  counts on an unauthenticated path.
- **Evidence (OSINT) collection**: `POST /api/v1/candidates/{id}/evidence/collect`
  runs a set of provider abstractions
  (`WebSearchProvider`/`NewsProvider`/`AuthorizedSocialProvider`) and
  stores whatever each returns as `candidate_evidence` rows. Web search
  (Tavily, or the Brave Search API) and news (Currents, or NewsAPI.org)
  have real, non-mock implementations, each slot independently enabled
  when one of its API keys (`TAVILY_API_KEY`/`BRAVE_SEARCH_API_KEY` for
  web search, `CURRENTS_API_KEY`/`NEWS_API_KEY` for news — the first of
  each pair takes priority) is configured and falling back to a mock
  otherwise; every real provider sits behind a
  timeout/retry/circuit-breaker wrapper (`osint::resilience`) so a
  struggling upstream degrades gracefully. `AuthorizedSocialProvider`
  remains mock-only — every real candidate social-platform API requires
  its own developer agreement, not available in this environment. One
  provider failing never fails the whole request or blocks the others'
  results (`osint::EvidenceOrchestrator`). Same role restriction as
  candidate enrollment for collecting; anyone who can view search results
  can read what was collected, and — separately from the OSINT layer —
  a candidate-centric entity graph (aliases/usernames/organizations/websites,
  `server/src/db/entity_graph.rs`) records relations a reviewer finds,
  editable from a per-candidate OSINT workspace in the frontend
  (`client/src/components/OsintWorkspace.tsx`). See
  `docs/SECURITY_ARCHITECTURE.md` for what this layer does and does not
  cover.
- **Candidate enrollment**: `POST /api/v1/candidates` and
  `POST /api/v1/candidates/{id}/reference-photos` (restricted to
  `OPERATOR`/`SECURITY_ADMIN`/`SYSTEM_ADMIN`) create candidate records and
  attach biometric templates via the active provider; a revoked template
  (`POST .../templates/{template_id}/revoke`) is excluded from every
  future search but its row is kept for audit history.
- **Last-admin protection**: `POST /api/v1/admin/users/{id}/ban` and
  `DELETE /api/v1/admin/users/{id}` both refuse to act on the only active
  `SYSTEM_ADMIN` account (`409 Conflict`, `LAST_ADMIN_PROTECTED`) — the
  platform can never lock itself out of its own administration through the
  admin panel.
- **Self-disabling admin bootstrap**: `POST /api/v1/admin/seed-admin`
  refuses to create a further admin once one already exists, even with a
  correct `ADMIN_SEED_TOKEN` and a different identity — closing the window
  where a leaked seed token could mint an extra admin account after initial
  bootstrap. `BOOTSTRAP_ENABLED=true` explicitly re-opens it for a
  deliberate recovery.
- **Request-ID validation**: a client-supplied `x-request-id` header is
  bounded to 128 ASCII letters/digits/`-`/`_` before it is echoed into
  responses or written into audit records; anything outside that is
  replaced with a generated UUID rather than passed through.
- **Database constraints**: a unique index on
  `search_candidates (search_id, candidate_id)` makes "one candidate per
  search" a database-enforced invariant, plus indexes on
  `searches (created_at, case_reference, requested_by)` for the columns
  search history is actually filtered/sorted by.
- **Centralized authorization policy**: role-to-action decisions live as
  named functions in `server/src/permission.rs`
  (`can_create_search`/`can_view_search`/`can_review_candidate`/
  `can_view_audit_log`/`can_administer_users`) rather than a role list
  re-declared next to each handler, so a permission has exactly one
  definition. See `docs/SECURITY_ARCHITECTURE.md`.
- **Probe-image EXIF stripping**: a validated probe image is re-encoded
  from its decoded pixel data before use, dropping EXIF/XMP metadata
  (GPS coordinates, device identifiers, capture timestamp) the original
  upload carried. See `docs/SECURITY_ARCHITECTURE.md`.
- **National ID encryption at rest and response masking**: national ID
  numbers are stored as AES-256-GCM ciphertext plus a deterministic
  HMAC-SHA256 lookup hash (`NATIONAL_ID_ENCRYPTION_KEY`), never plaintext;
  admin API responses only ever return the last two digits, decrypted
  server-side solely to build that masked value. See
  `docs/SECURITY_ARCHITECTURE.md`.
- **Role matrix test coverage**: `server/tests/role_matrix.rs` exercises
  every RBAC role against every sensitive endpoint's role gate, checked
  against the policy in `server/src/permission.rs`.
- **Cross-tab sign-out sync**: logging out in one browser tab notifies
  every other open tab of the same origin via `BroadcastChannel`, so a
  stale access token doesn't linger in another tab after logout. See
  `docs/SECURITY_ARCHITECTURE.md`.
- **Rate limiter provider abstraction**: `RateLimiterBackend` trait around
  the existing in-memory limiter (unchanged behavior), so a future
  distributed backend is a drop-in swap. See `docs/SECURITY_ARCHITECTURE.md`.
- **Expired session/token retention job**: `sessions`/`approval_tokens`
  rows past their expiry are purged on a fixed interval instead of
  accumulating forever. See `docs/SECURITY_ARCHITECTURE.md`.
- **Paginated admin user list**: `GET /api/v1/admin/users` is now
  server-side paginated, matching search history and the audit trail.
- **OpenAPI drift guard**: `docs/openapi.json` plus
  `server/tests/openapi_drift.rs`, which fails if a documented route stops
  matching a real one.
- **Multi-factor authentication**: `server/src/mfa.rs`, mandatory by
  default for `SYSTEM_ADMIN`/`SECURITY_ADMIN`/`REVIEWER`
  (`MFA_REQUIRED_ROLES`), voluntary for other roles. Two methods: TOTP
  (RFC 6238, authenticator app) or a 10-minute emailed one-time code, for
  accounts that would rather not install an app. Fail-closed: no
  access/refresh token pair is ever issued to an MFA-gated account without
  MFA actually being satisfied first — see `docs/SECURITY_ARCHITECTURE.md`.
- **Audit hash chaining and mandatory audit**: every audit event is
  chained to the one before it (`sequence`/`previous_hash`/`event_hash`),
  with `GET /api/v1/audit/integrity` able to detect any row altered or
  deleted after the fact. Security-critical actions (search completion,
  verification decisions, ban/unban, MFA changes) use a mandatory audit
  path that refuses to report success if their audit record failed to
  write. See `docs/SECURITY_ARCHITECTURE.md` for what this does and does
  not guarantee (it is tamper-evident, not tamper-proof — there is no
  dedicated append-only database role yet).
- **Organization/unit model and object-level authorization**:
  `organizations`/`organization_units`/`user_memberships`, with searches,
  audit events, and every candidate-scoped route (reference-photo upload,
  templates, evidence, entity graph, possible-duplicates) scoped to the
  actor's organization on every read and write path
  (`candidates::authorize_candidate_scope`). `SYSTEM_ADMIN` is the sole
  role exempt from scoping — holding another privileged role (`AUDITOR`,
  `SECURITY_ADMIN`) does not by itself grant visibility into another
  organization's records. See `docs/SECURITY_ARCHITECTURE.md`. A security
  audit of the candidate-scoped routes found several that loaded a
  candidate but never checked its organization against the caller's,
  unlike search routes — fixed with the shared helper referenced above,
  with regression tests covering the previously-unchecked paths
  (`server/tests/entity_graph.rs`).

## Planned (see `docs/SECURITY_ARCHITECTURE.md`)

Enterprise SSO, SCIM provisioning, thin Android/iOS clients, and a real
`AuthorizedSocialProvider` are designed but not yet implemented. Do not
assume any of these are active until this document is updated to say
otherwise. See `docs/ENTERPRISE_DEPLOYMENT.md` for a fuller institutional
deployment readiness summary.

## Rules enforced in this repository

- No secrets, real biometric data, real subject photographs, or production
  credentials are ever committed. Only `.env.example` placeholders are
  checked in.
- Raw images are never logged.
