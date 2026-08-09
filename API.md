# API

Base path: `/api/v1`. `GET /api/health` is the one exception, kept
unversioned since it must stay reachable before any API version
negotiation.

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

## Implemented endpoints

### `GET /api/health`

Liveness/readiness check.

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

### Administration

All `/api/v1/admin/*` routes except `seed-admin` and the email-approval
links require a `SYSTEM_ADMIN` or `SECURITY_ADMIN` bearer token.

- `POST /api/v1/admin/seed-admin` — one-time bootstrap of the first
  `SYSTEM_ADMIN` account. Requires an `x-seed-token` header matching
  `ADMIN_SEED_TOKEN`, plus `ADMIN_USER_CODE`/`ADMIN_PASSWORD`/`ADMIN_EMAIL`
  set in the environment. Rate-limited globally (5 / 15 min). Idempotent:
  `201`-equivalent `{ "messageKey": "admin.adminCreated" }` the first time,
  `{ "messageKey": "admin.alreadySeeded" }` (still `200`) on a repeat call
  once that user code/email already exists. `/admin-seed.html` is a small
  static form (same origin, no separate CORS setup) that calls this
  endpoint from a browser instead of a terminal.
- `GET /api/v1/admin/users` — list all users.
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
- `DELETE /api/v1/admin/users/{id}`
- `GET /api/v1/admin/review/{token}` — HTML approve/reject page linked from
  the admin's registration-notification email (valid 3 days, single-use;
  signed with `APPROVAL_TOKEN_SECRET`, independent of the JWT secrets —
  see `docs/SECURITY_ARCHITECTURE.md`). Viewing this page does not consume
  the token; only the approve/reject actions below do.
- `POST /api/v1/admin/quick-approve/{token}` / `POST /api/v1/admin/quick-reject/{token}` —
  the review page's own form targets. Each token can be consumed exactly
  once; a repeat request (double-click, retried email link) is rejected
  the same as an expired or invalid one.

### Search workflow

All routes below require `Authorization: Bearer <accessToken>`.

#### `POST /api/v1/search/face`

Multipart form: `caseReference`, `purpose`, `image` (file), optional
`topK` (integer; defaults to `SEARCH_DEFAULT_TOP_K`, clamped to
`SEARCH_MAX_TOP_K` — never rejected for being too large, just capped), and
optional `latitude`/`longitude` (the operator's captured geolocation, sent
by the frontend from `useGeolocation`'s last known coordinate — see
`docs/ROADMAP.md`'s "Operator geolocation"; either both coordinates must be
present and in range, or neither — one without the other is
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

Runs the `BiometricProvider` (currently `MockBiometricProvider` — see
CLAUDE.md) over every known candidate. The search row and every one of its
candidate results are written in a single database transaction (see
`db::create_search_with_candidates`) — a persistence failure never leaves
a partial candidate list visible; the attempt is instead recorded as a
`failed` search (see the status table below) and the request returns
**`500 Internal Server Error`**. The probe image itself is never
persisted; only its derived scores are.

**`200 OK`**:
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
"Candidates, not verdicts" in CLAUDE.md.

`search.status` is one of `queued`, `processing`, `completed`, `failed`
(state machine; `cancelled` is reserved for the async-search milestone in
`docs/ROADMAP.md` and not reachable yet). `failureCode`/
`failureMessageKey` are only set on a `failed` search.

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

#### `POST /api/v1/candidates/{candidate_id}/reject`

Same shape and role requirement as `verify`, sets status to `rejected`.

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
      "metadata": { "candidateCount": 5 }, "organizationId": null, "organizationUnitId": null
    }
  ],
  "page": 1,
  "pageSize": 50,
  "total": 137
}
```

## Planned endpoints

The following are designed but not implemented. Do not call them.

```
GET  /api/v1/connectors
POST /api/v1/connectors/{connector_id}/query
```
