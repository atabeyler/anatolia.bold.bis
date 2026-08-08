# API

Base path: `/api/v1` (planned). Phase 1 exposes only the unversioned health
endpoint below; every other endpoint listed in `docs/ROADMAP.md` is planned
and not yet implemented.

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

Liveness/readiness check. Not versioned under `/api/v1` since it must stay
reachable before any API version negotiation.

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

## Planned endpoints

The following are designed but not implemented. Do not call them.

```
POST /api/v1/auth/login
POST /api/v1/auth/refresh
POST /api/v1/auth/logout

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

GET  /api/v1/users/me
```
