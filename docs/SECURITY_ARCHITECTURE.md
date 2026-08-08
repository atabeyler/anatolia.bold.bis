# Security Architecture

This document describes security-relevant design decisions. See
`SECURITY.md` for the current implementation status and vulnerability
reporting.

## Design principles

- **Candidates, not verdicts**: the biometric engine returns ranked,
  scored candidates for human review. A "Confirmed Identity" status is
  only ever set by an explicit human verification action — never derived
  automatically from a similarity score.
- **Least privilege (planned)**: RBAC with five roles — `SYSTEM_ADMIN`,
  `SECURITY_ADMIN`, `OPERATOR`, `REVIEWER`, `AUDITOR`. `OPERATOR` may
  create searches; `REVIEWER` may confirm/reject candidate matches;
  `AUDITOR` has read-only audit access; `SYSTEM_ADMIN` handles system
  configuration.
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
- CORS restricted to an explicit origin allow-list.
- Per-request IDs for traceability without logging sensitive payloads.
- A single stable error shape (`ApiError`) — no stack traces or internal
  detail ever reaches the client.

## Not yet implemented

Authentication, MFA, SSO, RBAC enforcement, rate limiting, upload
validation (MIME/size/dimension/corruption checks), audit logging, and
retention policies are all planned (see `docs/ROADMAP.md`) but not present
in the Phase 1 codebase. Do not assume any of them are active.
