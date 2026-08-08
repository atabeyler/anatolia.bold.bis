# Security Architecture

This document describes security-relevant design decisions. See
`SECURITY.md` for the current implementation status and vulnerability
reporting.

## Design principles

- **Candidates, not verdicts**: the biometric engine returns ranked,
  scored candidates for human review. A "Confirmed Identity" status is
  only ever set by an explicit human verification action — never derived
  automatically from a similarity score.
- **Least privilege**: RBAC with five roles — `SYSTEM_ADMIN`,
  `SECURITY_ADMIN`, `OPERATOR`, `REVIEWER`, `AUDITOR`. `OPERATOR` may
  create searches; `REVIEWER` may confirm/reject candidate matches;
  `AUDITOR` has read-only audit access; `SYSTEM_ADMIN`/`SECURITY_ADMIN`
  handle system configuration and user administration. A newly approved
  registration is granted `OPERATOR` by default — the least-privileged
  authenticated role — and must be explicitly promoted by an admin.
- **Append-only audit (planned)**: every sensitive action (login,
  search creation, image upload, candidate review, connector queries,
  user/role changes) is written to an audit log that cannot be edited or
  deleted through the application.
- **Authorized sources only (planned)**: the system never scrapes social
  platforms wholesale. Data access goes through connector abstractions
  with a declared authorization type, allowed query capabilities, and
  rate limits.
- **Privacy by default (planned)**: raw uploaded images are not retained
  beyond a configurable, short retention window. Embeddings and identity
  records follow separate storage policies. Raw image data is never
  logged.

## Implemented today

- Baseline security response headers on every response (see
  `SECURITY.md`).
- CORS restricted to an explicit origin allow-list; credentialed
  (cookie-carrying) requests require an explicit origin and header list —
  never a wildcard.
- Per-request IDs for traceability without logging sensitive payloads.
- A single stable error shape (`ApiError`) — no stack traces or internal
  detail ever reaches the client.
- JWT authentication (15-minute access token in the response body,
  30-day refresh token as an `HttpOnly` cookie), bcrypt password hashing,
  RBAC role enforcement on admin routes, per-key rate limiting on
  login/registration/admin-seed, and an admin-approval gate on every new
  registration.
- Refresh-cookie `SameSite` selection: `Strict` outside production;
  in production, `Lax` for same-origin requests and `None` (with
  `Secure`) only for the one legitimate cross-origin case (a
  desktop/mobile client's local bridge calling the cloud API) — never a
  blanket `None`.

## Not yet implemented

MFA, enterprise SSO, upload validation (MIME/size/dimension/corruption
checks), audit logging, and retention policies are all planned (see
`docs/ROADMAP.md`) but not present in the codebase yet. Do not assume any
of them are active.
