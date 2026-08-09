# Threat Model

This is a working threat model for the implemented system — what it
actually defends against today, and what it deliberately does not yet
address. It complements `docs/SECURITY_ARCHITECTURE.md` (which describes
individual controls) and `docs/DATA_FLOW.md` (which traces how data
moves). Written from an attacker-capability perspective, using a
lightweight STRIDE-style pass over the system's main assets.

## Assets

1. **Account credentials and sessions** — passwords, JWTs, refresh
   tokens, approval/reset tokens.
2. **Personal data** — national ID, email, name, submitted probe images,
   coarse geolocation attached to a search.
3. **Audit trail integrity** — the append-only record of who did what.
4. **Search/review integrity** — candidate rankings and the human
   confirm/reject/inconclusive decisions on them.
5. **Administrative control** — the ability to approve/ban/delete
   accounts and change system configuration.
6. **Service availability** — the API being reachable and responsive.

## Trust boundaries

- **Browser/mobile/desktop client ↔ backend**: untrusted. Every request
  is treated as attacker-controlled input regardless of client type.
- **Backend ↔ PostgreSQL**: trusted, but every query is parameterized
  (SQLx) — no string-concatenated SQL anywhere in the codebase.
- **Backend ↔ Resend (email)**: trusted third party for delivery only;
  failure to send is logged and never blocks or fails the triggering
  request (registration, password reset, etc. still succeed even if the
  notification email doesn't go out).
- **Backend ↔ mock biometric provider**: currently in-process, no network
  boundary. A future real provider (`docs/ROADMAP.md` Phase 4) is
  expected to stay server-side — never on-device — precisely so this
  boundary remains centrally governed and auditable rather than being
  pushed onto a client the operator doesn't fully control.

## Threats and mitigations

### Spoofing (impersonating a user or admin)

| Threat | Mitigation |
|---|---|
| Credential stuffing / brute force against login | Per-account, per-IP, and burst-window rate limiting (`server/src/ratelimit.rs`); bcrypt hashing means a database leak alone doesn't yield usable passwords. |
| Stolen/replayed refresh token | Hash-only storage, rotation on every use, reuse triggers whole-family revocation (`docs/SECURITY_ARCHITECTURE.md`). |
| Forged JWT | Signed with `JWT_SECRET`, required ≥32 bytes and non-default in production (`Config::from_env` panics otherwise). |
| Guessing another account's registration/approval status | `registrationTrackingToken` is random and unguessable, not the user code. |
| Minting an extra `SYSTEM_ADMIN` after go-live via a leaked `ADMIN_SEED_TOKEN` | `seed_admin` self-disables once any active admin exists; `BOOTSTRAP_ENABLED=true` is a deliberate, logged override. |
| Approval/reject/reset email link reused by an attacker who intercepts it in transit | Single-use (`consumed_at`), independently signed from login tokens, short TTL. |

### Tampering (modifying data in flight or at rest)

| Threat | Mitigation |
|---|---|
| Altering audit records to hide an action | `audit_events` is append-only at the application layer — no code path issues `UPDATE`/`DELETE` against it. **Not yet mitigated**: nothing at the database-permission layer prevents a compromised backend process (or direct DB access) from doing so — see "Not yet addressed" below. |
| Overwriting a prior review decision | Every confirm/reject/inconclusive appends a new `verification_events` row rather than mutating one; the full trail is retrievable. |
| Tampering with a search result mid-creation (partial writes) | `create_search_with_candidates` is one database transaction — a failure rolls back entirely, never leaving a half-written candidate list. |
| Malicious/malformed probe image (corrupt file, decompression bomb, wrong format) | Magic-byte sniff, real decode, size cap, dimension/pixel-count limits (`image_validation.rs`) — validated before touching the database or the provider. |

### Repudiation (denying an action happened)

| Threat | Mitigation |
|---|---|
| A user denying they performed a sensitive action | Every auth, admin, search, and review action is recorded in `audit_events` with actor identity, timestamp, and request id. |
| An admin denying they approved/rejected/banned an account | Same — admin actions are actor-attributed audit events, and approval-link actions record `metadata: {"source": "email_link"}` to distinguish panel actions from email one-clicks. |

### Information disclosure

| Threat | Mitigation |
|---|---|
| Enumerating valid user codes/emails via `forgot-password` or registration-status | Both return an identical response regardless of whether a match exists. |
| Stack traces / internal errors leaking to the client | Single stable `ApiError` shape (`code`, `messageKey`, `requestId`) — no internal detail ever serialized to a response. |
| Sensitive data in logs | Structured JSON logging with no raw request/response bodies, secrets, tokens, or biometric data included. |
| Cross-origin reading of credentialed responses | CORS allow-list is explicit (never a wildcard when `allow_credentials` is set); unset `ALLOWED_ORIGINS` fails closed. |
| An admin's `x-request-id` header being used to inject junk into audit records | Validated to 1–128 ASCII letters/digits/`-`/`_`; anything else is replaced with a generated UUID. |
| National ID stored and returned in plaintext | **Not yet addressed** — see below. |

### Denial of service

| Threat | Mitigation |
|---|---|
| Login/registration/admin-seed/forgot-password flooding | Layered rate limits (per-account, per-IP where `TRUST_PROXY` is enabled, and global burst windows) on every one of these endpoints. |
| Oversized or decompression-bomb image uploads exhausting memory/CPU | 10 MB cap before decode, pixel-count cap after decode, applied before the bytes reach the biometric provider. |
| A single client requesting an unbounded number of ranked candidates | `topK` is clamped server-side to `SEARCH_MAX_TOP_K`, never trusted as sent. |
| Backend outage from database unavailability going undetected | `GET /api/health/ready` fails fast (`503`) against a real query, distinct from the liveness check that would otherwise mask a database outage. |
| **Not yet addressed**: no global request-rate ceiling outside the specific endpoints above; no dependency on a WAF/CDN layer is assumed. | Left to the deployment platform (Render) and is explicitly out of scope for the application layer today. |

### Elevation of privilege

| Threat | Mitigation |
|---|---|
| A newly approved user starting with more than minimum privilege | Approval always grants `OPERATOR` (least privilege); promotion is a separate explicit admin action. |
| An admin locking the platform out of its own administration (banning/deleting the last admin) | `would_remove_last_admin` refuses the action with `409 Conflict`. |
| A banned/deleted user's still-valid access token continuing to work | Ban and soft-delete both immediately revoke every active session for the account, not just future logins. |
| Role-based route access bypass | `require_role` checked on every admin/search/candidate/audit route; RBAC roles are a fixed, closed set (`server/src/roles.rs`). |
| **Not yet addressed**: revoking a *downgraded* (not banned/deleted) user's stale-privilege session | No role-change endpoint exists in the API today, so this specific gap has no live exploit path yet — but adding one without also revoking sessions on downgrade would reopen it. Tracked as `docs/HARDENING_CHECKLIST.md` item 11. |

## Explicitly out of scope today (tracked, not ignored)

These are known gaps, not oversights — each has a reason it isn't done
yet, recorded in `docs/HARDENING_CHECKLIST.md`:

- **Organization/unit-scoped authorization** (item 12): every authorized
  role currently sees all data platform-wide; there is no per-organization
  data boundary. This is a large, deliberate architectural decision
  awaiting the repository owner's input, not a hardening oversight.
- **Real biometric matching** (items 20–26): the only `BiometricProvider`
  implementation is a mock that hashes the uploaded bytes — it performs
  no actual face comparison. Production requires an explicit
  `ALLOW_MOCK_BIOMETRICS=true` acknowledgment specifically so this
  limitation cannot be silently deployed and mistaken for the real thing.
- **MFA** (item 10): password-only authentication today.
- **National ID protection at rest** (item 32): stored in plaintext, not
  encrypted or masked in admin responses.
- **OSINT/connector layer** (P2 appendix): not started — any future work
  here must use only authorized, licensed data sources and must never
  bypass a platform's own protections (login walls, CAPTCHAs, rate
  limits), per the project's own constraints.
- **Database-level audit tamper resistance**: append-only is enforced in
  application code, not by database permissions (e.g. a `REVOKE UPDATE,
  DELETE` grant for the application's own database role, or WORM storage).
  A compromised backend process with full database credentials could
  still alter or delete audit rows directly.

## Reporting

Suspected vulnerabilities should be reported per `SECURITY.md`, not
opened as public issues.
