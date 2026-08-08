# Security

## Reporting a vulnerability

Report suspected vulnerabilities directly to the repository owner
(info@boldkimya.com.tr) rather than opening a public issue.

## Current state (Phase 1)

The application currently exposes a single unauthenticated endpoint,
`GET /api/health`, which returns only a status flag, the running build's
commit SHA, and a timestamp — no user, case, or biometric data of any kind
exists yet.

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

## Planned (see `docs/ROADMAP.md` and `docs/SECURITY_ARCHITECTURE.md`)

Authentication (JWT/session, MFA, SSO), RBAC, rate limiting, upload
validation, audit logging, and biometric data retention controls are all
designed but not yet implemented. Do not assume any of them are active
until this document is updated to say otherwise.

## Rules enforced in this repository

- No secrets, real biometric data, real subject photographs, or production
  credentials are ever committed. Only `.env.example` placeholders are
  checked in.
- Raw images are never logged.
