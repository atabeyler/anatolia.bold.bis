# Data Flow

This document traces how data moves through the system for the two flows
that matter most from a privacy/security standpoint: registration/
authentication, and a biometric search. It describes what is actually
implemented today — see `docs/ROADMAP.md` for what is planned but not yet
built.

## Registration and admin approval

1. A prospective operator submits `POST /api/v1/auth/register` (first
   name, last name, national ID, email, password, user code). The
   password is hashed with bcrypt before it ever reaches the database —
   the plaintext value is never stored or logged.
2. The account is created in `pending` status. A random, unguessable
   `registrationTrackingToken` is generated and returned to the caller;
   the frontend polls `GET /api/v1/auth/registration-status/:trackingToken`
   with it to detect approval, rather than the account's own (guessable)
   user code — see `docs/SECURITY_ARCHITECTURE.md` for why.
3. If `RESEND_API_KEY` is configured, an admin-notification email is sent
   containing a single-use, time-limited approval link, signed with
   `APPROVAL_TOKEN_SECRET` and independently tracked (hashed) in
   `approval_tokens`.
4. An admin approves or rejects the request (`POST
   /api/v1/admin/users/{id}/approve|reject`, or the emailed one-click
   link). Approval grants the `OPERATOR` role by default; rejection hard
   deletes the row, since nothing else in the database can reference an
   unapproved account's id yet.
5. Every step is recorded through the central `AuditRecorder`
   (`server/src/audit.rs`) into the append-only `audit_events` table:
   actor, action, result, and a small set of non-sensitive metadata —
   never the password, never the national ID.

## Login and session lifecycle

1. `POST /api/v1/auth/login` verifies the bcrypt hash, checks
   `is_approved`/`is_banned`/`deleted_at`, and on success issues a
   short-lived (15 min) JWT access token in the response body plus a
   30-day refresh token as an `HttpOnly` cookie.
2. The refresh token is never stored in the database in raw form — only
   its SHA-256 hash, in a `sessions` row, alongside a `token_family_id`
   used for reuse detection.
3. Each `POST /api/v1/auth/refresh` rotates the session to a new refresh
   token/hash. Presenting an already-rotated-away or already-revoked
   refresh token is treated as token theft and revokes the entire token
   family, forcing every device sharing it to re-authenticate.
4. Banning or soft-deleting a user (see below) immediately revokes every
   active session for that account — a short-lived access token issued
   before the action would otherwise keep working until it naturally
   expires.

## Password reset

1. `POST /api/v1/auth/forgot-password` looks the account up by user code
   or email. If it has an email on file, a single-use, hashed, 1-hour-TTL
   token is created (reusing the `approval_tokens` table with
   `purpose = "password_reset"`) and a reset link is emailed directly to
   the account holder. Accounts without an email fall back to notifying
   the admin, who resets the password from the management panel.
2. `POST /api/v1/auth/reset-password` looks the token up by hash, checks
   purpose/expiry/consumed state, consumes it atomically, sets the new
   password, and revokes every active session for the account.
3. The response to `forgot-password` is identical whether or not a
   matching account exists, so the endpoint cannot be used to enumerate
   registered user codes or email addresses.

## Biometric search

1. An authorized user (`OPERATOR`/`REVIEWER`/`SECURITY_ADMIN`/
   `SYSTEM_ADMIN`) submits `POST /api/v1/search/face`: a case reference,
   a purpose string, an optional lat/lon pair, an optional `topK`, and a
   probe image as multipart form data.
2. The image is validated synchronously, before anything else touches it
   (`server/src/image_validation.rs`): magic-byte sniff, a 10 MB size
   cap, an actual decode (JPEG/PNG/WEBP only), dimension limits, and a
   decompression-bomb guard on total decoded pixel count. A search row
   is only ever created *after* this passes — malformed uploads never
   reach the biometric provider or the database at all.
3. Once validation passes, a `queued` search row is written and the
   request returns **`202 Accepted`** immediately with that row's id —
   the biometric pipeline itself runs in a background task, not inline
   with the request (madde 18-19's async search flow; see
   `docs/SECURITY_ARCHITECTURE.md`). The caller polls `GET
   /api/v1/search/{id}/status` until the search leaves `queued`/
   `processing`.
4. In that background task, the active `BiometricProvider`
   (`BIOMETRIC_PROVIDER=mock` or `onnx`) ranks enrolled candidates
   against the probe image and returns a bounded list (`topK`, clamped to
   `SEARCH_MAX_TOP_K`) of `(candidate_id, score)` pairs. **Under `mock`
   (still the default), the score is a deterministic hash of the
   uploaded bytes — it is not a real face comparison**; see `SECURITY.md`
   for the production guard that refuses to run this mode silently.
   Under `onnx`, the probe is run through a real detect → quality-gate →
   align → embed pipeline (`server/src/biometric/`) and compared by
   cosine similarity against stored templates (`db/biometric.rs`) — see
   `docs/SECURITY_ARCHITECTURE.md` for exactly what that pipeline
   guarantees and its documented limitations.
5. The search row, its `search_candidates` rows, and their `pending`
   review status are written inside a single database transaction
   (`db::finalize_queued_search`) — a failure mid-way rolls back entirely
   rather than leaving a partial candidate list visible, and marks the
   search `failed` for traceability instead. There is no HTTP response
   left in-flight at this point, so a mandatory-audit write failure
   (madde 17) downgrades a would-be `completed` search to `failed`
   rather than reporting an untrustworthy success to a poller.
6. The probe image bytes themselves are **not persisted** — they exist
   only for the duration of the background task, passed to the provider
   and then dropped. Only the resulting scores and candidate references
   are stored. (Retention/discard policy for a future real biometric provider
   that may need to keep intermediate embeddings is tracked as planned
   work — see `docs/ROADMAP.md` Phase 4.)
7. Ranked candidates, once the poller observes `status: "completed"`, are
   **candidates, not verdicts** — every one of them is `pending` until a
   human reviewer acts.

## Review and audit trail

1. A `REVIEWER`/`SECURITY_ADMIN`/`SYSTEM_ADMIN` calls one of `POST
   /api/v1/candidates/{id}/verify`, `.../reject`, or
   `.../inconclusive`. Each call appends a new row to
   `verification_events` (reviewer, decision, reason, notes, timestamp)
   in the same transaction as the `search_candidates` status update — a
   later decision on the same candidate adds another event rather than
   overwriting the previous one. `GET
   /api/v1/search/{id}/candidates/{id}/history` returns the full,
   ordered trail.
2. Only `verify` sets "Confirmed Identity" — this is always an explicit
   human action, never derived automatically from a similarity score.
3. Every security- or case-relevant action across the system (auth,
   registration, user administration, search create/complete/fail,
   candidate review, admin-seed use) is written through the same central
   `AuditRecorder` into the append-only `audit_events` table. No code
   path ever `UPDATE`s or `DELETE`s an audit row. `GET /api/v1/audit`
   (server-side paginated/filtered) exposes it to `AUDITOR`,
   `SECURITY_ADMIN`, and `SYSTEM_ADMIN` only.

## Account deletion

- Deleting an established account (`DELETE /api/v1/admin/users/{id}`) is
  a **soft delete**: `deleted_at` is set and every active session is
  revoked, but the row itself is kept, because `searches.requested_by`,
  `verification_events.reviewer_user_id`, and
  `audit_events.actor_user_id` can all reference that account's id. A
  hard delete would leave those pointing at nothing. Every read path that
  should treat a deleted account as gone (login, session/token
  validation, admin listing) filters on `deleted_at IS NULL`.
- Rejecting a still-pending, never-approved registration is unaffected by
  the above and remains a hard delete — nothing else in the database can
  reference that id yet.

## Data that is never persisted or logged

- Plaintext passwords (bcrypt hash only).
- Raw refresh tokens, approval tokens, or password-reset tokens (SHA-256
  hash only).
- Probe image bytes (used transiently for one request, then discarded).
- Any of the above in structured (JSON) application logs.
