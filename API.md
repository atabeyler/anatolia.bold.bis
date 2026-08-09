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
returned in a body. See `docs/SECURITY_ARCHITECTURE.md`.

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

**`201 Created`** on success. **`409 Conflict`** (`CONFLICT`) if the email
or user code is already registered.

#### `POST /api/v1/auth/login`

Request: `{ "userCode": "...", "password": "..." }`. Rate-limited per user
code (10 / 15 min).

**`200 OK`**: `{ "accessToken": "...", "user": { ... } }`, plus the refresh
cookie. **`401 Unauthorized`** (`errors.invalidCredentials`) on a wrong
code/password. **`403 Forbidden`** if the account is banned
(`errors.accountBanned`) or not yet approved (`errors.accountNotApproved`).

#### `POST /api/v1/auth/refresh`

Reads the refresh cookie, returns a new access token. `401 Unauthorized`
if the cookie is missing, invalid, or the account is banned/unapproved.

#### `POST /api/v1/auth/logout`

Clears the refresh cookie.

#### `POST /api/v1/auth/forgot-password`

Request: `{ "identifier": "..." }` (user code or email). Rate-limited per
identifier (5 / 15 min). Does not reset anything itself — there is no
self-service reset flow. If the identifier matches an account, emails
`ADMIN_EMAIL` a request to act on; an admin then sets a new password via
`PATCH /api/v1/admin/users/{id}`. Always responds **`200 OK`**
(`{ "messageKey": "auth.forgotPasswordReceived" }`) whether or not a
matching account was found, so it can't be used to enumerate registered
user codes/emails.

#### `GET /api/v1/auth/pending-status/{userCode}`

Polled by the registration form to detect admin approval without a manual
refresh. Response: `{ "status": "pending" | "approved" | "banned" | "not_found" }`.

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
- `POST /api/v1/admin/users/{id}/unban`
- `DELETE /api/v1/admin/users/{id}`
- `GET /api/v1/admin/review/{token}` — HTML approve/reject page linked from
  the admin's registration-notification email (valid 7 days).
- `POST /api/v1/admin/quick-approve/{token}` / `POST /api/v1/admin/quick-reject/{token}` —
  the review page's own form targets.

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

Lists every search (any authenticated, approved user).

#### `GET /api/v1/search/{search_id}`

Returns one search's metadata (same shape as the `search` object above).

#### `GET /api/v1/search/{search_id}/candidates`

Returns that search's ranked candidates (same shape as the `candidates`
array above).

#### `GET /api/v1/candidates/{candidate_id}`

Returns `{ "id": "...", "referenceCode": "...", "fullName": "...", "notes": "..." }`.

#### `POST /api/v1/candidates/{candidate_id}/verify`

Body: `{ "searchId": "..." }`. Requires `REVIEWER`, `SECURITY_ADMIN`, or
`SYSTEM_ADMIN`. The one explicit human verification action that sets a
candidate's status to `confirmed` ("Confirmed Identity") for that search —
never derived automatically from a score. Returns the updated candidate
row.

#### `POST /api/v1/candidates/{candidate_id}/reject`

Same shape and role requirement as `verify`, sets status to `rejected`.

## Planned endpoints

The following are designed but not implemented. Do not call them.

```
GET  /api/v1/connectors
POST /api/v1/connectors/{connector_id}/query
```
