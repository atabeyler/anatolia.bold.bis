# API

Base path: `/api/v1`. `GET /api/health` is the one exception, kept
unversioned since it must stay reachable before any API version
negotiation.

A machine-readable companion to this document lives at
`docs/openapi.json` — a lightweight OpenAPI 3.0 spec listing every path
and method below. It is not exhaustively typed (this file is still the
source of truth for request/response shapes, rate limits, and error
codes); its purpose is `server/tests/openapi_drift.rs`, which fails if a
documented path stops corresponding to a real route.

## Error format

All error responses share one shape:

```json
{
  "code": "ERROR_CODE",
  "messageKey": "errors.someError",
  "requestId": "uuid",
  "details": {}
}
```

`code` is a stable, machine-readable identifier. `messageKey` is an i18next
key the frontend resolves to a localized message — the backend never
returns human-readable text directly. `details` is omitted when empty.

`requestId` echoes the client-supplied `x-request-id` header when one is
present and well-formed (ASCII letters/digits/`-`/`_`, 1–128 characters);
otherwise the server generates a fresh UUID. This bounds what ends up in
audit records and logs — an oversized or oddly-charactered header is
treated the same as a missing one rather than passed through.

## Implemented endpoints

### `GET /api/health`

Liveness check only — confirms the process is running, never touches the
database. Always `200 OK` if the server is up at all, even mid database
outage.

**Response `200 OK`**

```json
{
  "status": "ok",
  "version": "<commit-sha>",
  "timestamp": "2026-08-08T12:00:00Z"
}
```

`version` is the exact commit SHA of the running build — compare it against
a pushed commit to confirm a deployment has actually gone live.

### `GET /api/health/ready`

Readiness check: runs a trivial query against the real database backend.
Use this, not `/api/health`, to gate whether traffic should be routed to
this instance. Also reports the active biometric provider and search
mode — read-only facts about how this instance is configured, not
signals of a degraded instance, so they're present on both `200` and
`503` responses.

**Response `200 OK`**
```json
{
  "status": "ready",
  "version": "<commit-sha>",
  "timestamp": "2026-08-08T12:00:00Z",
  "biometricProvider": "mock",
  "biometricSearch": "brute-force",
  "uptimeSeconds": 3600,
  "dbPool": { "size": 5, "idle": 3 }
}
```
`biometricProvider` is `"mock"` or `"onnx"`. `biometricSearch` is
`"pgvector-hnsw"` (indexed PostgreSQL search) or `"brute-force"` (in-memory
linear scan — always this on SQLite, or on Postgres if the `vector`
extension couldn't be enabled). `uptimeSeconds` is an approximation of
process uptime (measured from this process's first readiness check, not
true process start) — useful for spotting an unexpected restart.
`dbPool` reports the connection pool's current `size` (open connections,
in use plus idle) and `idle` count.

**`503 Service Unavailable`** (`{ "status": "not_ready", ... }`, same
extra fields) if the database didn't answer.

### `GET /metrics`

Prometheus text exposition format. Open by default; if `METRICS_TOKEN` is
set, requires `Authorization: Bearer <token>` (**`401 Unauthorized`**
without it). See `server/src/metrics.rs` for exactly which metrics are
exported — every label is a fixed, small-cardinality value (HTTP method,
route template, status code, provider name), never a raw path, user id,
or IP address.

### Authentication

Access tokens are short-lived JWTs (15 minutes) returned in the response
body; the refresh token (30 days) is set as an `HttpOnly` cookie, never
returned in a body, and is backed by a server-side session record — see
`docs/SECURITY_ARCHITECTURE.md` for rotation and reuse-detection details.

#### `POST /api/v1/auth/register`

Creates a new operator account in `pending` status; it cannot log in until
an admin approves it. Rate-limited globally (20 / 15 min).

Request:
```json
{ "firstName": "...", "lastName": "...", "nationalId": "...", "email": "...", "password": "...", "userCode": "..." }
```
`userCode` is 4–20 characters, uppercase letters and digits only.
`nationalId` is exactly 11 digits. Password must be 8+ characters with at
least one uppercase letter, one lowercase letter, one digit, and one
punctuation/special character.

**`201 Created`**: `{ "messageKey": "auth.registrationPending", "registrationTrackingToken": "..." }`
on success — the frontend polls `registration-status` below with this
token, not the user code (see enumeration note there). **`409 Conflict`**
(`CONFLICT`) if the email or user code is already registered.

#### `POST /api/v1/auth/login`

Request: `{ "userCode": "...", "password": "..." }`. Rate-limited per user
code (10 / 15 min), per IP (50 / 15 min, only when `TRUST_PROXY` is
enabled — see `docs/ENVIRONMENT.md`), and by a 1-minute burst window
(10 / 1 min, same IP-trust condition).

**`200 OK`**: `{ "accessToken": "...", "user": { ... } }`, plus the refresh
cookie. This also creates a new session record server-side. **`401
Unauthorized`** (`errors.invalidCredentials`) on a wrong code/password.
**`403 Forbidden`** if the account is banned (`errors.accountBanned`) or
not yet approved (`errors.accountNotApproved`).

If the account has MFA enabled, or its role is listed in
`MFA_REQUIRED_ROLES` and has never enrolled, a correct password does
**not** issue a session. Instead the response is **`200 OK`** with one of:

- `{ "mfaRequired": true, "mfaToken": "...", "userCode": "...", "method": "totp" | "email" }`
  — MFA is already enabled; complete login with `POST
  /api/v1/auth/mfa/challenge/verify`. If `method` is `"email"`, a fresh
  code has already been emailed to the account by this same call — no
  separate request is needed before verifying, though
  `POST /api/v1/auth/mfa/challenge/request-code` can be used to resend one.
- `{ "mfaEnrollmentRequired": true, "mfaToken": "...", "userCode": "..." }`
  — this role requires MFA but none is enrolled yet; complete enrollment
  with `POST /api/v1/auth/mfa/challenge/enroll` +
  `POST /api/v1/auth/mfa/challenge/enroll/confirm`.

See "Multi-factor authentication (MFA)" below.

#### `POST /api/v1/auth/refresh`

Reads the refresh cookie, validates it against the matching session
record, rotates the session to a new refresh token, and returns a new
access token. **`401 Unauthorized`** if the cookie is missing, invalid,
expired, already rotated away, belongs to a revoked session, or the
account is banned/unapproved. Presenting a refresh token that no longer
matches its session's current hash is treated as token theft: the entire
token family is revoked immediately, so every device sharing that family
must log in again.

#### `POST /api/v1/auth/logout`

Revokes the session tied to the refresh cookie and clears it. Always
**`200 OK`**, even if the cookie was missing or already invalid.

#### `POST /api/v1/auth/logout-all`

Requires `Authorization: Bearer <accessToken>`. Revokes every session
belonging to the authenticated user (all devices) and clears the caller's
own refresh cookie.

#### `POST /api/v1/auth/forgot-password`

Request: `{ "identifier": "..." }` (user code or email). Rate-limited per
identifier (5 / 15 min). If the identifier matches an account **with an
email on file**, issues a single-use, hashed, 1-hour password-reset token
and emails the account holder a link
(`{APP_URL}/?resetToken={rawToken}`) to `POST
/api/v1/auth/reset-password` themselves. If the account has no email on
file (e.g. an admin-created account), falls back to emailing `ADMIN_EMAIL`
a request to act on, with an admin then setting a new password via `PATCH
/api/v1/admin/users/{id}`. Always responds **`200 OK`**
(`{ "messageKey": "auth.forgotPasswordReceived" }`) whether or not a
matching account was found, so it can't be used to enumerate registered
user codes/emails.

#### `POST /api/v1/auth/reset-password`

Request: `{ "token": "...", "newPassword": "..." }`. Completes a
self-service reset using the raw token from the emailed reset link. The
token is looked up by its SHA-256 hash (the raw value is never stored) and
must be unconsumed, have `purpose = "password_reset"`, and not be expired
(1 hour TTL); it is consumed atomically before the password is changed, so
it can never be replayed. On success, sets the new password (validated
against the same password policy as registration), revokes **every**
active session for the account, and records an
`AUTH_PASSWORD_RESET_COMPLETED` audit event. Responds **`200 OK`**
(`{ "messageKey": "auth.passwordResetSuccess" }`) on success or **`400
Bad Request`** (`errors.invalidResetToken` or `errors.validation`) if the
token or new password is invalid.

#### `GET /api/v1/auth/registration-status/{trackingToken}`

Polled by the registration form to detect admin approval without a manual
refresh. Takes the unguessable `registrationTrackingToken` returned from
`register` — **not** the account's own user code — so this cannot be used
to enumerate arbitrary accounts' status by guessing codes. An unknown or
expired token returns the same `not_found` shape as a token that never
existed. Response:
`{ "status": "pending" | "approved" | "banned" | "not_found" }`.

#### `GET /api/v1/users/me`

Requires `Authorization: Bearer <accessToken>`. Returns the caller's own
public profile.

### Session/device management

A self-service "where am I signed in"
view over the same `sessions` table that already backs refresh-token
rotation (`db/session.rs`) — no new storage, just new read/write access
patterns over it.

#### `GET /api/v1/users/me/sessions`

Requires `Authorization: Bearer <accessToken>`. Lists the caller's own
active (not revoked, not expired) sessions, most-recently-used first.
Response:
```json
{
  "items": [
    {
      "id": "...", "createdAt": "...", "lastUsedAt": "...", "expiresAt": "...",
      "userAgent": "...", "ipAddress": "...", "isCurrent": true
    }
  ]
}
```
`userAgent`/`ipAddress` are whatever was recorded at that session's login
time — never re-resolved on each list call, so this reflects what was seen
then, not a live lookup. `isCurrent` is true for whichever session the
request's own `refresh_token` cookie belongs to, if that cookie is present
and still valid; it's false (never omitted) for every other row, including
when the cookie is absent (e.g. a non-browser client calling this with
only a bearer token).

#### `DELETE /api/v1/users/me/sessions/{session_id}`

Requires `Authorization: Bearer <accessToken>`. Revokes exactly one of the
caller's own sessions — "sign out this device" for a session other than
(or including) the one making the request, contrasted with `POST
/api/v1/auth/logout-all`'s "sign out everywhere". Ownership-checked: a
`session_id` that exists but belongs to a different user returns the same
**`404 Not Found`** as one that doesn't exist at all, so this endpoint can
never be used to probe or revoke someone else's session.

### Multi-factor authentication (MFA)

Implemented in `server/src/mfa.rs`, with two methods a user can enroll
with:

- **`totp`** — RFC 6238 authenticator-app codes (the original, and still
  the default when `method` is omitted).
- **`email`** — a 6-digit numeric code emailed to the account's address on
  file (via `server/src/email.rs`), valid for 10 minutes; requires the
  account to have an email set, since there is nowhere else to send it.
  Chosen for accounts that would rather not install an authenticator app.

Both methods share the same underlying credential row and the same
recovery-code mechanism; a credential's method is fixed at enrollment
time (re-enrolling can switch it). Two independent flows:

- **Voluntary** — any authenticated user may enroll, confirm, or disable
  MFA on their own account.
- **Login-time challenge** — `mfaToken` values returned by `POST
  /api/v1/auth/login` (see above). These are short-lived (10 minutes),
  single-purpose JWTs signed with a dedicated `MFA_TOKEN_SECRET`; by
  themselves they grant no access — completing the flow still requires a
  correct TOTP/emailed/recovery code (or, for first-time mandatory
  enrollment, completing enrollment itself). No code path issues an
  access/refresh token pair for an MFA-gated account without MFA actually
  being satisfied — this is deliberately fail-closed, not a frontend-only
  redirect.

#### `POST /api/v1/auth/mfa/enroll`

Requires `Authorization: Bearer <accessToken>`. Request (body optional):
`{ "method": "totp" | "email" }` — defaults to `"totp"` if omitted or the
body is empty. For `"totp"`, generates a new secret, stores it as
pending, and returns `{ "method": "totp", "secret": "...", "otpauthUrl":
"otpauth://..." }` for a manual-entry key or QR code. For `"email"`,
generates and emails a 6-digit code, stores its hash as pending, and
returns `{ "method": "email", "emailSentTo": "ad***@example.com" }` (a
masked address, not the raw code). **`400 Bad Request`**
(`errors.mfaEmailNotAvailable`) for `"email"` if the account has no email
on file. Re-calling this replaces any not-yet-confirmed pending
credential, including switching method.

#### `POST /api/v1/auth/mfa/enroll/resend`

Requires `Authorization: Bearer <accessToken>`. Re-sends a fresh emailed
code for a pending `"email"`-method enrollment, replacing the previous
one. Rate-limited per account (5 / 15 min). **`400 Bad Request`**
(`errors.mfaEmailNotAvailable`) if the account has no email; **`409
Conflict`** (`errors.mfaEnrollmentNotStarted`) if there is no pending
email-method enrollment.

#### `POST /api/v1/auth/mfa/enroll/confirm`

Request: `{ "code": "..." }`. Verifies the code against the pending
credential (TOTP-computed or the emailed code, depending on method); on
success activates MFA and returns
`{ "recoveryCodes": ["...", ...] }` — 10 single-use codes, shown this one
time only (only their hashes are stored), valid for either method.
**`401 Unauthorized`** (`errors.invalidMfaCode`) on a wrong or expired
code; **`409 Conflict`** (`errors.mfaEnrollmentNotStarted`) if `enroll`
was never called.

#### `POST /api/v1/auth/mfa/disable`

Request: `{ "password": "...", "code": "..." }`. Requires both the
account's current password and a valid TOTP/emailed/recovery code, so a
stolen access token alone cannot turn MFA off. Deletes the credential and
all recovery codes. If the account's role is in `MFA_REQUIRED_ROLES`, the
next login will require re-enrollment.

#### `POST /api/v1/auth/mfa/challenge/enroll`

Request: `{ "mfaToken": "...", "method": "totp" | "email" }` (from a
`mfaEnrollmentRequired` login response; `method` defaults to `"totp"`).
Same as `enroll` above but authorized by the challenge token instead of a
bearer token — used when a required role has no MFA yet.

#### `POST /api/v1/auth/mfa/challenge/enroll/resend`

Request: `{ "mfaToken": "..." }`. Same as `enroll/resend` above but for
the mandatory, login-time enrollment flow.

#### `POST /api/v1/auth/mfa/challenge/enroll/confirm`

Request: `{ "mfaToken": "...", "code": "..." }`. Confirms enrollment
**and** completes the login that triggered it in the same response:
`{ "accessToken": "...", "user": { ... }, "recoveryCodes": ["...", ...] }`,
plus the refresh cookie.

#### `POST /api/v1/auth/mfa/challenge/verify`

Request: `{ "mfaToken": "...", "code": "..." }` (from a `mfaRequired`
login response). Verifies a TOTP/emailed or recovery code for an account
that already has MFA enabled and, on success, completes login:
`{ "accessToken": "...", "user": { ... } }`, plus the refresh cookie. Rate
limited per account (8 / 15 min) independent of the login rate limits
already applied when the password was checked. **`401 Unauthorized`**
(`errors.invalidMfaCode`) on a wrong code.

#### `POST /api/v1/auth/mfa/challenge/request-code`

Request: `{ "mfaToken": "..." }`. Re-sends a fresh emailed code during
login for an account already enrolled with the `"email"` method — `POST
/api/v1/auth/login` already sends one automatically, so this exists only
for a "didn't receive it" resend. Rate-limited per account (5 / 15 min).
**`400 Bad Request`** (`errors.mfaNotEnabled`) if the account's enrolled
method is not `"email"`.

### Administration

All `/api/v1/admin/*` routes except `seed-admin` and the email-approval
links require a `SYSTEM_ADMIN` or `SECURITY_ADMIN` bearer token.

- `POST /api/v1/admin/seed-admin` — one-time bootstrap of the first
  `SYSTEM_ADMIN` account. Requires an `x-seed-token` header matching
  `ADMIN_SEED_TOKEN`, plus `ADMIN_USER_CODE`/`ADMIN_PASSWORD`/`ADMIN_EMAIL`
  set in the environment. Rate-limited globally (5 / 15 min).
  `201`-equivalent `{ "messageKey": "admin.adminCreated" }` on success;
  `{ "messageKey": "admin.alreadySeeded" }` (still `200`) if that exact
  user code/email is already seeded. **Self-disables** once any active
  `SYSTEM_ADMIN` exists — a further call returns `403 Forbidden`
  regardless of the identity supplied, unless `BOOTSTRAP_ENABLED=true` is
  explicitly set for a deliberate recovery (see `docs/ENVIRONMENT.md`).
  `/admin-seed.html` is a small static form (same origin, no separate CORS
  setup) that calls this endpoint from a browser instead of a terminal.
- `GET /api/v1/admin/users` — server-side paginated user list. Query
  parameters: `page` (1-indexed, default `1`), `pageSize` (default `50`,
  clamped to a maximum of `200`). Response:
  `{ "items": [ <user> ], "page": 1, "pageSize": 50, "total": 42 }`.
  `nationalId` in each returned record is masked to its last two digits
  (e.g. `"*********12"`) — the full value is never sent to a client.
  `PATCH` below only changes it when a new value is explicitly submitted.
- `POST /api/v1/admin/users` — admin creates a user directly (immediately
  approved, no self-registration/approval round trip). Body:
  `{ "userCode": "...", "password": "...", "firstName": "...", "lastName": "...", "nationalId": "...", "email": "...", "isAdmin": false }`.
  `nationalId` (11 digits) and `email` are required; `firstName` and
  `lastName` are optional (`firstName` falls back to the user code,
  `lastName` to empty). Password only requires a minimum of 8 characters
  (the admin chooses it, not the account's eventual owner — contrast with
  `register`'s stronger policy). `isAdmin: true` grants `SYSTEM_ADMIN`
  instead of the default `OPERATOR` role. `409 Conflict` if the user code,
  national ID, or email is already taken.
- `PATCH /api/v1/admin/users/{id}` — admin edits an existing account's
  nickname (first name), national ID, email, and/or resets its password.
  Body: `{ "nickname": "...", "nationalId": "...", "email": "...", "password": "..." }`,
  all fields optional — anything omitted or empty is left unchanged.
  `409 Conflict` if the new national ID or email collides with another
  account.
- `POST /api/v1/admin/users/{id}/approve` — approves a pending
  registration, granting the default `OPERATOR` role.
- `POST /api/v1/admin/users/{id}/reject` — deletes a pending registration.
- `POST /api/v1/admin/users/{id}/ban` — body `{ "reason": "..." }` (optional).
  Immediately revokes all of the user's active sessions, not just future
  logins.
- `POST /api/v1/admin/users/{id}/unban`
- `POST /api/v1/admin/users/{id}/role` — body `{ "role": "SYSTEM_ADMIN" | "SECURITY_ADMIN" | "OPERATOR" | "REVIEWER" | "AUDITOR" }`.
  Immediately revokes all of the user's active sessions, whether the change
  is a promotion or a demotion — a session issued under the old role must
  never keep working under stale claims. `409 Conflict` (`LAST_ADMIN_PROTECTED`)
  if this would demote the last active `SYSTEM_ADMIN`. Records a
  `USER_ROLE_CHANGED` audit event.
- `POST /api/v1/admin/users/{id}/mfa-reset` — removes a target account's
  MFA credential and recovery codes entirely, forcing re-enrollment on its
  next login. This is the recovery path when an account with a
  MFA-required role loses its device/secret: it cannot re-enroll itself
  without first logging in, and it cannot log in without MFA, so an
  administrator must clear the credential first. Records a
  `MFA_RESET_BY_ADMIN` audit event.
- `DELETE /api/v1/admin/users/{id}` — **soft delete**: marks the account
  `deleted_at` and revokes all of its active sessions rather than removing
  the row, so past `searches`/`verification_events`/`audit_events` rows
  that reference this user's id stay attributable. A deleted account
  behaves as fully gone everywhere it matters (cannot log in, does not
  appear in `GET /api/v1/admin/users`). Calling it again on an
  already-deleted account is a harmless no-op (`200 OK`); a genuinely
  unknown id still returns `404 Not Found`.

Both `ban` and `DELETE` refuse to act on the last active `SYSTEM_ADMIN`
account: **`409 Conflict`** (`LAST_ADMIN_PROTECTED`,
`errors.lastAdminProtected`) instead of taking effect, so the platform can
never lock itself out of its own administration.

- `GET /api/v1/admin/biometric-thresholds` — lists every calibrated
  FAR/FRR threshold recorded by `server/src/bin/calibrate.rs --save-threshold`,
  most-recent write per model name+version. Response:
  `{ "items": [ { "id": "...", "modelName": "...", "modelVersion": "...", "threshold": 0.88, "equalErrorRate": 0.02, "pairCount": 40, "createdAt": "..." } ] }`.
  Saving a threshold again for the same model name+version replaces the
  previous row rather than adding a new one.

- `GET /api/v1/admin/connectors` —
  read-only status of each OSINT connector slot (`web_search`, `news`,
  `social`). Response:
  `{ "items": [ { "slot": "web_search", "providerName": "brave-web-search", "isMock": false } ] }`.
  Configuration itself stays environment-variable-based
  (`BRAVE_SEARCH_API_KEY`/`NEWS_API_KEY`, see `docs/ENVIRONMENT.md`), the
  same pattern every other provider toggle in this codebase already uses
  — this endpoint reports which provider ended up active in each slot,
  it does not accept writes.

- `GET /api/v1/admin/review/{token}` — HTML approve/reject page linked from
  the admin's registration-notification email (valid 3 days, single-use;
  signed with `APPROVAL_TOKEN_SECRET`, independent of the JWT secrets —
  see `docs/SECURITY_ARCHITECTURE.md`). Viewing this page does not consume
  the token; only the approve/reject actions below do.
- `POST /api/v1/admin/quick-approve/{token}` / `POST /api/v1/admin/quick-reject/{token}` —
  the review page's own form targets. Each token can be consumed exactly
  once; a repeat request (double-click, retried email link) is rejected
  the same as an expired or invalid one.

### Organizations and units

All routes below require `SYSTEM_ADMIN` (`permission::can_manage_organizations`)
— narrower than `can_administer_users`, since changing the organization
structure is inherently a cross-organization concern. See "Organization/unit
model" in `docs/SECURITY_ARCHITECTURE.md`.

- `POST /api/v1/admin/organizations` — body `{ "name": "..." }`. Returns
  `{ "id": "...", "name": "...", "createdAt": "..." }`.
- `GET /api/v1/admin/organizations` — lists every organization.
- `POST /api/v1/admin/organizations/{organization_id}/units` — body
  `{ "name": "...", "parentUnitId": "..." }` (`parentUnitId` optional,
  nests the unit under an existing one within the same organization).
- `GET /api/v1/admin/organizations/{organization_id}/units` — lists the
  units within one organization.
- `POST /api/v1/admin/memberships` — body
  `{ "userId": "...", "organizationId": "...", "organizationUnitId": "..." }`
  (`organizationUnitId` optional). Assigns a user to an organization —
  the only place an organization id is ever attached to a user; always
  chosen by an administrator, never accepted from the member themselves.
  Idempotent (assigning the same membership twice is a no-op).
- `DELETE /api/v1/admin/memberships` — body
  `{ "userId": "...", "organizationId": "..." }`. Removes a user's
  membership in that organization.

A search is stamped with its creator's organization automatically at
creation time (resolved from their membership, never client-supplied).
`GET /api/v1/search`, `GET /api/v1/search/{id}`,
`GET /api/v1/search/{id}/candidates`,
`GET /api/v1/search/{id}/candidates/{id}/history`, and `GET /api/v1/audit`
are all scoped accordingly: **`SYSTEM_ADMIN`** sees every organization's
records; every other role only sees its own organization's, plus any
record with no owning organization at all. Out of scope for a
single-object endpoint (`GET /api/v1/search/{id}` etc.) returns
**`403 Forbidden`**; the list endpoints filter server-side instead.

### Search workflow

All routes below require `Authorization: Bearer <accessToken>`.

#### `POST /api/v1/search/face`

Multipart form: `caseReference`, `purpose`, `image` (file), optional
`topK` (integer; defaults to `SEARCH_DEFAULT_TOP_K`, clamped to
`SEARCH_MAX_TOP_K` — never rejected for being too large, just capped), and
optional `latitude`/`longitude` (the operator's captured geolocation, sent
by the frontend from `useGeolocation`'s last known coordinate — the
sign-in screen requests it on load and shows an explicit "unavailable"
message on denial rather than a synthetic fallback coordinate; either
both coordinates must be present and in range, or neither — one without
the other is
**`400 Bad Request`** `errors.invalidCoordinates`). Requires `OPERATOR`,
`REVIEWER`, `SECURITY_ADMIN`, or `SYSTEM_ADMIN`.

The image is validated before anything else touches it (see
`server/src/image_validation.rs`): magic-byte sniff plus a real decode,
JPEG/PNG/WEBP only, max 10 MB, dimensions between 32px and 8000px per side,
and a decompression-bomb guard on total decoded pixel count. A failure
returns **`400 Bad Request`** with one of these codes:

| `code` | Meaning |
|---|---|
| `IMAGE_TOO_LARGE` | Over 10 MB. |
| `UNSUPPORTED_IMAGE_TYPE` | Not a JPEG/PNG/WEBP magic byte sequence. |
| `IMAGE_DECODE_FAILED` | Right magic bytes, but the file doesn't actually decode (corrupted/truncated). |
| `IMAGE_DIMENSIONS_INVALID` | Below the minimum size, above the maximum size, or above the total-pixel decompression-bomb guard. |

A passing image is also sanitized: what reaches the biometric provider is
a fresh re-encode of the decoded pixel data, not the original upload
bytes, which strips any EXIF/XMP metadata (GPS coordinates, device
make/model, capture timestamp) the original file carried.

**Async search flow.** Validation (image, case reference,
purpose, coordinates) happens synchronously and can still fail this
request directly with `400`/`403` as described above. Once validation
passes, the request does **not** wait for the biometric pipeline to run:
it writes a `queued` search row and returns **`202 Accepted`**
immediately —

```json
{ "search": { "id": "...", "status": "queued", "caseReference": "...", "purpose": "...", "topK": 10, "createdAt": "...", "startedAt": null, "completedAt": null } }
```

— while the active `BiometricProvider` (`BIOMETRIC_PROVIDER` — `mock` by
default, or `onnx` for the real YuNet/SFace pipeline; see
`docs/SECURITY_ARCHITECTURE.md`) runs against every enrolled candidate's
stored templates in a background task. Poll
**`GET /api/v1/search/{search_id}/status`** until `search.status` is no
longer `queued`/`processing`:

```json
{
  "search": {
    "id": "...", "caseReference": "...", "purpose": "...", "requestedByName": "...",
    "status": "completed", "latitude": 41.0082, "longitude": 28.9784, "topK": 10,
    "startedAt": "...", "completedAt": "...", "failureCode": null, "failureMessageKey": null,
    "createdAt": "..."
  },
  "candidates": [
    { "id": "...", "candidateId": "...", "referenceCode": "CAND-0001", "fullName": "...", "score": 0.87, "status": "pending", "reviewedByName": null, "reviewedAt": null }
  ]
}
```
`candidates` is ranked highest score first, capped at `topK`. `score` is a
similarity value in `[0, 1]` — never a match/no-match verdict; see
"Candidates, not verdicts" in CLAUDE.md. Same view-role and object-level
authorization as the rest of the search workflow.

A search that fails ends up `status: "failed"` with `failureCode`/
`failureMessageKey` set, rather than an HTTP error — there's no HTTP
response left in-flight by the time the background task knows the
outcome. The search row and every one of its candidate results are
written in a single database transaction (`db::finalize_queued_search`)
— a persistence failure never leaves a partial candidate list visible;
the search is instead marked `failed` (`SEARCH_PERSIST_FAILED`). The
probe image itself is never persisted; only its derived scores are.

Under `BIOMETRIC_PROVIDER=onnx`, the probe image is run through a real
pipeline (face detection → quality gating → alignment → embedding) before
any candidate comparison happens. A probe the pipeline can't use marks
the search `failed` with one of these `failureCode`s instead of producing
ranked candidates:

| `failureCode` | Meaning |
|---|---|
| `NO_FACE_DETECTED` | No face found in the probe image. |
| `MULTIPLE_FACES_DETECTED` | More than one face found; exactly one is required. |
| `FACE_TOO_SMALL` | The detected face is too small relative to the image. |
| `IMAGE_TOO_BLURRY` | Laplacian-variance blur check failed. |
| `EXCESSIVE_POSE` | Landmark-symmetry pose check failed (face too rotated). |
| `POOR_LIGHTING` | Mean-brightness check failed (too dark or too bright). |
| `LOW_FACE_QUALITY` | Detector confidence below the search-time threshold. |
| `BIOMETRIC_PROVIDER_UNAVAILABLE` | The provider itself couldn't run (e.g. a transient inference error; startup-time model failures are a fail-closed process panic, not a runtime state). |
| `AUDIT_WRITE_FAILED` | The search's own completion audit record failed to write — the search is downgraded to `failed` rather than ever reporting `completed` on an untrustworthy basis (the MANDATORY-audit guarantee, applied to the async path). |

#### `GET /api/v1/search/{search_id}/status`

The polling endpoint described above: current search metadata plus its
candidates (empty until the pipeline has produced any). Same role
requirement and shape as the `202`/final payloads above. **`404 Not Found`**
if the search doesn't exist.

`search.status` is one of `queued`, `processing`, `completed`, `failed`
(state machine; `cancelled` is defined in the schema but has no code
path that reaches it yet — cancelling an in-flight search is not
implemented). `failureCode`/`failureMessageKey` are only set on a
`failed` search.

#### `GET /api/v1/search`

Server-side paginated search history. Query parameters: `page` (1-indexed,
default `1`), `pageSize` (default `50`, clamped to a maximum of `200`).
Requires `OPERATOR`, `REVIEWER`, `SECURITY_ADMIN`, `SYSTEM_ADMIN`, or
`AUDITOR` (the latter is read-only oversight — see
docs/SECURITY_ARCHITECTURE.md).

**`200 OK`**: `{ "items": [ <search> ], "page": 1, "pageSize": 50, "total": 137 }`.

#### `GET /api/v1/search/{search_id}`

Returns one search's metadata (same shape as the `search` object above).
Same role requirement as `GET /api/v1/search`.

#### `GET /api/v1/search/{search_id}/candidates`

Returns that search's ranked candidates (same shape as the `candidates`
array above). Same role requirement as `GET /api/v1/search`.

#### `GET /api/v1/search/{search_id}/candidates/{candidate_id}/history`

The full, immutable review history for one candidate within one search —
every `verification_events` row, oldest first, not just the current
status (see "Immutable review history" in
`docs/SECURITY_ARCHITECTURE.md`). Same role requirement as
`GET /api/v1/search`.

**`200 OK`**:
```json
[
  { "id": "...", "reviewerName": "...", "decision": "confirmed", "reason": "clear match", "notes": null, "createdAt": "..." },
  { "id": "...", "reviewerName": "...", "decision": "rejected", "reason": "corrected on second review", "notes": null, "createdAt": "..." }
]
```

#### `GET /api/v1/candidates/{candidate_id}`

Returns `{ "id": "...", "referenceCode": "...", "fullName": "...", "notes": "..." }`.
Same role requirement as `GET /api/v1/search`.

#### `POST /api/v1/candidates/{candidate_id}/verify`

Body: `{ "searchId": "...", "reason": "...", "notes": "..." }` (`reason`/
`notes` optional). Requires `REVIEWER`, `SECURITY_ADMIN`, or
`SYSTEM_ADMIN`. The one explicit human verification action that sets a
candidate's status to `confirmed` ("Confirmed Identity") for that search —
never derived automatically from a score. Appends a new
`verification_events` row rather than overwriting any prior decision on
the same candidate (see the history endpoint above). Returns the updated
candidate row (current status only — fetch the history endpoint for the
full trail).

If `REQUIRE_SECOND_REVIEW=true` (four-eyes review): a `confirmed`/
`rejected` decision on a candidate that isn't already
`needs_second_review` only ever moves it *to* `needs_second_review` — it
does not finalize it. A second, *different* reviewer's subsequent
`verify`/`reject` call on that same candidate is what finalizes it, to
whatever that second reviewer decided. The same reviewer supplying both
the first and the "final" decision gets **`409 Conflict`**
(`SAME_REVIEWER_FORBIDDEN`, `errors.sameReviewerForbidden`) instead — see
`docs/SECURITY_ARCHITECTURE.md`.

#### `POST /api/v1/candidates/{candidate_id}/reject`

Same shape and role requirement as `verify`, sets status to `rejected`
(subject to the same four-eyes behavior above when enabled).

#### `POST /api/v1/candidates/{candidate_id}/inconclusive`

Same shape and role requirement as `verify`, sets status to `inconclusive`.
Neither a positive nor a negative identification — unlike `confirmed`/
`rejected`, an `inconclusive` candidate is not closed out: it still
appears wherever "needs review" candidates are surfaced, so a later
decision (by the same or a different reviewer) can still confirm or
reject it. Not subject to four-eyes — an `inconclusive` decision never
finalizes anything regardless of `REQUIRE_SECOND_REVIEW`.

### Candidate enrollment

All routes below require `Authorization: Bearer <accessToken>` and
`OPERATOR`, `SECURITY_ADMIN`, or `SYSTEM_ADMIN`
(`permission::can_manage_candidates`).

#### `POST /api/v1/candidates`

Body: `{ "referenceCode": "...", "fullName": "...", "notes": "..." }`
(`notes` optional). Creates a bare candidate record with no biometric
template attached — enrollment of a reference photo is a separate step
(below), since the two can fail independently. A duplicate
`referenceCode` returns **`409 Conflict`**.

**`200 OK`**: `{ "id": "...", "referenceCode": "...", "fullName": "...", "notes": "..." }`.

#### `POST /api/v1/candidates/{candidate_id}/reference-photos`

Multipart form field `image`, validated the same way a search probe is
(magic-byte sniff, real decode, size/dimension limits — see
`POST /api/v1/search/face` above). Runs the active `BiometricProvider`'s
enrollment pipeline and stores the resulting template.

Under `BIOMETRIC_PROVIDER=mock` (the default), this **always** returns
**`503 Service Unavailable`** (`BIOMETRIC_PROVIDER_UNAVAILABLE`) — the
mock provider performs no real face embedding, so there is nothing
genuine to enroll; this is a deliberate honesty guarantee, not a bug.
Under `BIOMETRIC_PROVIDER=onnx`, the same rejection codes as the search
endpoint apply (`NO_FACE_DETECTED`, `MULTIPLE_FACES_DETECTED`, etc.).

**`200 OK`**:
```json
{
  "id": "...", "candidateId": "...", "modelName": "sface", "modelVersion": "2021dec",
  "embeddingDimension": 128, "qualityScore": 0.94, "sourceReference": null,
  "createdAt": "...", "revokedAt": null
}
```

#### `GET /api/v1/candidates/{candidate_id}/templates`

Every template ever enrolled for this candidate, including revoked ones,
newest first. Same shape as the object above, wrapped in `{ "items": [...] }`.
Available to anyone who can view search results
(`permission::can_view_search`), not just `can_manage_candidates`.

#### `POST /api/v1/candidates/{candidate_id}/templates/{template_id}/revoke`

Marks a template `revoked_at` (kept, not deleted, for audit/history) so it
is excluded from every future search — see `db::list_active_templates`.
**`404 Not Found`** if the template doesn't exist or is already revoked.

### Evidence (OSINT)

All routes below require `Authorization: Bearer <accessToken>`. Provider
abstractions (`WebSearchProvider`/`NewsProvider`/`AuthorizedSocialProvider`),
per-provider failure isolation, timeout/retry/circuit-breaker resilience,
and real (non-mock) web-search and news providers are implemented; a
real `AuthorizedSocialProvider` and reverse image search are not — see
`docs/ENTERPRISE_DEPLOYMENT.md`.

#### `POST /api/v1/candidates/{candidate_id}/evidence/collect`

Requires `OPERATOR`, `SECURITY_ADMIN`, or `SYSTEM_ADMIN`
(`permission::can_manage_candidates`). Body: `{ "query": "..." }` —
typically the candidate's full name or another identifying string.

Runs every configured `WebSearchProvider`/`NewsProvider`/
`AuthorizedSocialProvider` and stores whatever each one returns.
Web search uses the Brave Search API and news uses NewsAPI.org when
`BRAVE_SEARCH_API_KEY`/`NEWS_API_KEY` are set (each independently; see
`docs/ENVIRONMENT.md`), falling back to that slot's mock implementation
when its key is unset — a deployment with neither key set behaves exactly
like before (mock-only). There is no real `AuthorizedSocialProvider`
implementation yet — see that trait's doc comment in
`server/src/osint/mod.rs` for why. Real providers apply a timeout, one
retry, and a circuit breaker (opens after 3 consecutive failures, a
30-second cooldown) — see `server/src/osint/resilience.rs`. **One
provider failing does not fail the request** — its failure is reported
per-provider in `providerErrors` instead, and every other provider's
results are still stored (`osint::EvidenceOrchestrator::collect`). Every
evidence item with a URL also automatically becomes a `website` entity
relation (see "Entity graph" below).

**`200 OK`**:
```json
{
  "items": [
    {
      "id": "...", "candidateId": "...", "sourceType": "web_search",
      "providerName": "mock-web-search", "title": "...", "url": "...",
      "snippet": "...", "confidenceScore": 0.62, "collectedBy": "...",
      "createdAt": "..."
    }
  ],
  "providerErrors": [ { "provider": "...", "error": "..." } ]
}
```
`confidenceScore` is the provider's own relevance confidence — never a
match/no-match verdict; a human reviewer decides what evidence means, same
"candidates, not verdicts" principle as biometric scores.

#### `GET /api/v1/candidates/{candidate_id}/evidence`

Every evidence item ever collected for this candidate, newest first.
Available to anyone who can view search results
(`permission::can_view_search`), not just `can_manage_candidates`.

**`200 OK`**: `{ "items": [ <evidence item, same shape as above> ] }`.

### Entity resolution

#### `GET /api/v1/candidates/{candidate_id}/possible-duplicates`

Requires `Authorization: Bearer <accessToken>`,
`permission::can_view_search`, and the same organization-scoping check as
the entity graph routes below. Conservative, **advisory-only** entity
resolution over non-biometric signals (`server/src/entity_resolution.rs`):
Jaro-Winkler name similarity (default threshold `0.90`), any candidates
sharing an OSINT evidence URL with this one, and any candidates sharing an
alias/username/organization entity-graph relation with this one. Never
merges or auto-links anything — it only surfaces other candidate records a
human reviewer may want to compare, same "candidates, not verdicts"
principle as biometric scores. Deliberately does not use the national ID
field for matching — it's encrypted specifically so it can't be used for
fuzzy/plaintext comparison (see `national_id.rs`). Not implemented:
phonetic matching, geography/temporal signals (no real per-candidate
location/time data exists to compare).

Each match reports exactly which signal(s) fired via `matchedSignals`
(one or more of `name_similarity`, `shared_evidence_url`, `shared_alias`,
`shared_username`, `shared_organization`) instead of a single blended
score, so a reviewer can judge the strength of a match themselves.

**`200 OK`**:
```json
{
  "items": [
    {
      "candidateId": "...", "referenceCode": "...", "fullName": "...",
      "nameSimilarity": 0.97, "sharedEvidenceUrls": [],
      "matchedSignals": ["name_similarity"]
    }
  ]
}
```

### Entity graph

Candidate-centric relations to aliases, usernames, organizations, and
websites (`server/src/db/entity_graph.rs`). A star graph around the candidate, not
a general node-to-node graph. `website` relations are recorded
automatically from evidence URLs (see above); `alias`/`username`/
`organization` (and additional `website`) relations are recorded manually
by a human reviewer. Always advisory — a relation is a claim with
provenance, never an automatic identity merge. Both routes are
organization-scoped the same way searches are
(`permission::can_view_scoped_resource`): a candidate with an owning
organization is only visible to members of that organization (or
`SYSTEM_ADMIN`); an orgless/legacy candidate stays visible to anyone who
passes the role check.

#### `GET /api/v1/candidates/{candidate_id}/entity-graph`

Requires `permission::can_view_search`, plus the organization-scoping
check above. **`403 Forbidden`** if the candidate belongs to an
organization the caller isn't a member of.

**`200 OK`**:
```json
{
  "candidateId": "...",
  "items": [
    {
      "id": "...", "candidateId": "...", "relationType": "website",
      "value": "https://example.test/profile", "evidenceId": "...",
      "addedBy": null, "createdAt": "..."
    }
  ]
}
```
`relationType` is one of `alias`, `username`, `organization`, `website`.
`evidenceId` is set for automatically-recorded `website` relations,
`null` otherwise. `addedBy` is the reviewer's user id for manually-added
relations, `null` for automatic ones.

#### `POST /api/v1/candidates/{candidate_id}/entity-graph`

Requires `OPERATOR`, `SECURITY_ADMIN`, or `SYSTEM_ADMIN`
(`permission::can_manage_candidates`), plus the organization-scoping
check above. Body: `{ "relationType": "alias", "value": "..." }`.
**`400 Bad Request`** (`VALIDATION_ERROR`) for an unknown `relationType`
or an empty `value`. Records a `CANDIDATE_ENTITY_RELATION_ADDED` audit
event.

### Audit trail

#### `GET /api/v1/audit`

Requires `AUDITOR`, `SECURITY_ADMIN`, or `SYSTEM_ADMIN`. Server-side
paginated, filtered read over the append-only `audit_events` table (see
`docs/SECURITY_ARCHITECTURE.md`) — no endpoint ever exposes a way to
modify or delete an audit event.

Query parameters (all optional):

| Parameter | Meaning |
|---|---|
| `dateFrom`, `dateTo` | RFC3339 timestamps; inclusive range. |
| `actor` | Exact match on the acting user's ID (not user code). |
| `action` | Exact match on the action constant, e.g. `AUTH_LOGIN_FAILED`. |
| `caseReference` | Exact match. |
| `resourceType` | Exact match, e.g. `user`, `search`, `session`. |
| `result` | `success`, `failure`, or `denied`. |
| `page` | 1-indexed; defaults to `1`. |
| `pageSize` | Defaults to 50; clamped server-side to a maximum of 200 regardless of what's requested. |

**`200 OK`**:
```json
{
  "items": [
    {
      "id": "...", "timestamp": "...", "actorUserId": "...", "actorUserCode": "OPER01",
      "actorRole": "OPERATOR", "action": "SEARCH_CREATED", "requestId": "...",
      "caseReference": "CASE-001", "resourceType": "search", "resourceId": "...",
      "result": "success", "source": "api", "ipAddress": null, "userAgent": "...",
      "metadata": { "candidateCount": 5 }, "organizationId": null, "organizationUnitId": null,
      "sequence": 137, "previousHash": "...", "eventHash": "..."
    }
  ],
  "page": 1,
  "pageSize": 50,
  "total": 137
}
```

#### `GET /api/v1/audit/integrity`

Requires `AUDITOR`, `SECURITY_ADMIN`, or `SYSTEM_ADMIN` — same restriction
as reading the trail itself. Recomputes the hash chain over every audit
event (see "Audit hash chaining" in `docs/SECURITY_ARCHITECTURE.md`) and
reports whether it's intact.

**`200 OK`**:
```json
{
  "eventsChecked": 137,
  "intact": true,
  "breaks": []
}
```

A `breaks` entry (`{ "sequence": 42, "eventId": "...", "reason": "..." }`)
means a stored row no longer reproduces its own hash, or no longer
chains from the previous row's hash — i.e. something altered or deleted
an audit row after it was written.

## Planned endpoints

The following are designed but not implemented. Do not call them.

```
GET  /api/v1/connectors
POST /api/v1/connectors/{connector_id}/query
```
