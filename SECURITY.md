# Security

## Reporting a vulnerability

Report suspected vulnerabilities directly to the repository owner
(info@boldkimya.com.tr) rather than opening a public issue.

## Current state (Phase 2)

Implemented controls:
- Security response headers (`X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `Strict-Transport-Security`,
  `Cross-Origin-Opener-Policy`) applied to every response.
- CORS restricted to an explicit `ALLOWED_ORIGINS` allow-list; unset means
  every cross-origin request is rejected, not silently allowed.
- Per-request IDs (`x-request-id`), propagated through logs and error
  responses, for traceability without logging sensitive payloads.
- Structured (JSON) logging; no raw request/response bodies are logged.
- Error responses only ever return the stable `ApiError` shape (see
  `API.md`) — stack traces are never exposed to clients.
- Authentication: JWT access tokens (15 min) plus an `HttpOnly` refresh
  cookie (30 days), passwords hashed with bcrypt, never stored or logged
  in plain text.
- New registrations start in `pending` status and require explicit admin
  approval before they can log in; the first admin account itself can
  only be created through a rate-limited, constant-time-compared seed
  token (`POST /api/v1/admin/seed-admin`).
- RBAC: five roles (`SYSTEM_ADMIN`, `SECURITY_ADMIN`, `OPERATOR`,
  `REVIEWER`, `AUDITOR`); admin routes require `SYSTEM_ADMIN` or
  `SECURITY_ADMIN`. Approved registrations are granted `OPERATOR` (least
  privilege) by default.
- Rate limiting: login (10/15 min per user code), registration (20/15 min
  globally), admin seed (5/15 min globally).
- Refresh-token cookie `SameSite`/`Secure` attributes are selected based
  on whether the request is same-origin and whether the server is running
  in production — see `docs/SECURITY_ARCHITECTURE.md`.

## Planned (see `docs/ROADMAP.md` and `docs/SECURITY_ARCHITECTURE.md`)

MFA, enterprise SSO, upload validation, audit logging, and biometric data
retention controls are designed but not yet implemented. Do not assume any
of them are active until this document is updated to say otherwise.

## Rules enforced in this repository

- No secrets, real biometric data, real subject photographs, or production
  credentials are ever committed. Only `.env.example` placeholders are
  checked in.
- Raw images are never logged.
