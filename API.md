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
{ "firstName": "...", "lastName": "...", "email": "...", "password": "...", "userCode": "..." }
```
`userCode` is 4–20 characters, uppercase letters and digits only. Password
must be 8+ characters with at least one uppercase letter, one lowercase
letter, one digit, and one punctuation/special character.

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
  set in the environment. Rate-limited globally (5 / 15 min).
- `GET /api/v1/admin/users` — list all users.
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

## Planned endpoints

The following are designed but not implemented. Do not call them.

```
POST /api/v1/search/face
GET  /api/v1/search
GET  /api/v1/search/{search_id}
GET  /api/v1/search/{search_id}/candidates

GET  /api/v1/candidates/{candidate_id}
POST /api/v1/candidates/{candidate_id}/verify
POST /api/v1/candidates/{candidate_id}/reject

GET  /api/v1/audit

GET  /api/v1/connectors
POST /api/v1/connectors/{connector_id}/query
```
