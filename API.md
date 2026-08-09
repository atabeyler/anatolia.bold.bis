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
identifier (5 / 15 min). Does not reset anything itself — there is no
self-service reset flow. If the identifier matches an account, emails
`ADMIN_EMAIL` a request to act on; an admin then sets a new password via
`PATCH /api/v1/admin/users/{id}`. Always responds **`200 OK`**
(`{ "messageKey": "auth.forgotPasswordReceived" }`) whether or not a
matching account was found, so it can't be used to enumerate registered
user codes/emails.

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

Multipart form: `caseReference`, `purpose`, `image` (file), plus optional
`latitude`/`longitude` (the operator's captured geolocation, sent by the
frontend from `useGeolocation`'s last known coordinate — see
`docs/ROADMAP.md`'s "Operator geolocation"). Requires `OPERATOR`,
`REVIEWER`, `SECURITY_ADMIN`, or `SYSTEM_ADMIN`. Runs the
`BiometricProvider` (currently `MockBiometricProvider` — see CLAUDE.md)
over every known candidate and stores the result. The probe image itself
is never persisted; only its derived scores are.

**`200 OK`**:
```json
{
  "search": { "id": "...", "caseReference": "...", "purpose": "...", "requestedByName": "...", "status": "completed", "latitude": 41.0082, "longitude": 28.9784, "createdAt": "..." },
  "candidates": [
    { "id": "...", "candidateId": "...", "referenceCode": "CAND-0001", "fullName": "...", "score": 0.87, "status": "pending", "reviewedByName": null, "reviewedAt": null }
  ]
}
```
`candidates` is ranked highest score first, capped at 5. `score` is a
similarity value in `[0, 1]` — never a match/no-match verdict; see
"Candidates, not verdicts" in CLAUDE.md.

#### `GET /api/v1/search`

Lists every search. Requires `OPERATOR`, `REVIEWER`, `SECURITY_ADMIN`,
`SYSTEM_ADMIN`, or `AUDITOR` (the latter is read-only oversight — see
docs/SECURITY_ARCHITECTURE.md).

#### `GET /api/v1/search/{search_id}`

Returns one search's metadata (same shape as the `search` object above).
Same role requirement as `GET /api/v1/search`.

#### `GET /api/v1/search/{search_id}/candidates`

Returns that search's ranked candidates (same shape as the `candidates`
array above). Same role requirement as `GET /api/v1/search`.

#### `GET /api/v1/candidates/{candidate_id}`

Returns `{ "id": "...", "referenceCode": "...", "fullName": "...", "notes": "..." }`.
Same role requirement as `GET /api/v1/search`.

#### `POST /api/v1/candidates/{candidate_id}/verify`

Body: `{ "searchId": "..." }`. Requires `REVIEWER`, `SECURITY_ADMIN`, or
`SYSTEM_ADMIN`. The one explicit human verification action that sets a
candidate's status to `confirmed` ("Confirmed Identity") for that search —
never derived automatically from a score. Returns the updated candidate
row.

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
