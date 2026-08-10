# Roadmap

Implemented incrementally. Each phase below is marked `[x]`/`[ ]` per
item — a phase heading does not imply everything under it is done; check
the individual items.

## Phase 1 — Repository foundation (this phase)

- [x] Repository rules (`AGENTS.md`, `CLAUDE.md`)
- [x] Backend shell (Rust/Axum), `GET /api/health` reporting the live commit SHA
- [x] Frontend shell (React/TypeScript/Vite)
- [x] i18n system, 6 languages (en, tr, de, fr, ar, ru), Arabic RTL
- [x] Docker (backend, frontend, docker-compose with PostgreSQL)
- [x] CI (backend tests/clippy, frontend typecheck/test/build)

## Phase 2 — Authentication foundation

- [x] User model and SQLx-managed schema (PostgreSQL production, SQLite local fallback)
- [x] RBAC roles (SYSTEM_ADMIN, SECURITY_ADMIN, OPERATOR, REVIEWER, AUDITOR); approved registrations default to OPERATOR
- [x] JWT auth (register/login/refresh/logout), bcrypt password hashing, per-key rate limiting
- [x] Admin-approval workflow for new registrations, admin user administration (approve/reject/ban/unban/delete), rate-limited admin bootstrap (`seed-admin`)
- [ ] Session/device management UI (server-side session model exists as of Phase 3.5 — no UI to list/revoke individual sessions yet), MFA, enterprise SSO

## Phase 3 — Search workflow

- [x] Mock biometric provider (`BiometricProvider` trait)
- [x] Search request creation (case reference + purpose required)
- [x] Candidate results (top-K), candidate detail view, human confirm/reject
- [x] Attach the operator's captured location (see "Operator geolocation"
      below) to searches

## Phase 3.5 — Authentication hardening

- [x] Centralized, production-fail-fast secret validation (`JWT_SECRET`,
      `JWT_REFRESH_SECRET`, `APPROVAL_TOKEN_SECRET` — see
      `docs/SECURITY_ARCHITECTURE.md`)
- [x] Server-side `sessions` table; refresh-token rotation with
      reuse/theft detection revoking the whole token family
- [x] `POST /api/v1/auth/logout-all`; banning a user revokes its active
      sessions immediately
- [x] Registration approval tokens isolated from login tokens
      (`APPROVAL_TOKEN_SECRET`, `approval_tokens` table, single-use)
- [x] Registration-status polling by unguessable tracking token instead
      of the account's own user code (enumeration fix)
- [x] Login rate limiting layered with per-IP and burst windows (in
      addition to the existing per-account window)
- [x] CORS method list includes `PATCH`; CSP and Permissions-Policy
      headers; HSTS restricted to production
- [x] TOTP MFA (`server/src/mfa.rs`), mandatory by default for
      `SYSTEM_ADMIN`/`SECURITY_ADMIN`/`REVIEWER` (`MFA_REQUIRED_ROLES`),
      voluntary for other roles; fail-closed login-time challenge, hashed
      recovery codes, admin reset endpoint — see
      `docs/SECURITY_ARCHITECTURE.md`
- [x] Organization/unit-scoped authorization — see Phase 3.7 below

## Phase 3.6 — Audit trail

- [x] Append-only `audit_events` table (PostgreSQL/SQLite), never
      `UPDATE`d or `DELETE`d by any code path
- [x] Central `AuditService`/`AuditRecorder` (`server/src/audit.rs`) —
      handlers call one consistent API instead of ad-hoc `INSERT`s
- [x] Events wired into auth (login/refresh/logout/logout-all/token
      reuse/password reset request), registration (created/approved/
      rejected), user administration (created/updated/banned/unbanned/
      deleted), search (created/completed/failed), candidate (confirmed/
      rejected), and admin-seed (used/failed)
- [x] `GET /api/v1/audit`, server-side paginated and filtered
      (date range, actor, action, case reference, resource type, result),
      restricted to `AUDITOR`/`SECURITY_ADMIN`/`SYSTEM_ADMIN`
- [x] Frontend Audit Logs screen (filters, pagination, expandable detail),
      all 6 locales
- [x] Organization/unit-scoped audit visibility (`db/org.rs`,
      `permission::can_view_scoped_resource`) — see Phase 3.7

## Phase 3.7 — Search/data correctness

- [x] Transactional search creation (`db::create_search_with_candidates`):
      search row + every candidate result written in one transaction; a
      failure rolls back and is recorded as a `failed` search rather than
      leaving a partial candidate list or vanishing silently
- [x] Search status state machine (`queued`/`processing`/`completed`/
      `failed`, `started_at`/`completed_at`/`failure_code`/
      `failure_message_key`); `cancelled` reserved for the async-search
      milestone below
- [x] Configurable `SEARCH_DEFAULT_TOP_K`/`SEARCH_MAX_TOP_K` replacing a
      compile-time constant; client-requested `topK` clamped server-side
- [x] Server-side pagination on search history (`GET /api/v1/search`)
- [x] Coordinate validation (latitude/longitude range + paired-presence)
- [x] Immutable review history (`verification_events` table) — every
      confirm/reject decision preserved, not just the current status;
      `GET /api/v1/search/{id}/candidates/{id}/history`
- [x] Real probe-image validation (magic-byte sniff + decode, JPEG/PNG/
      WEBP, size/dimension limits, decompression-bomb guard) replacing a
      bare non-empty-bytes check
- [x] Organization/unit-scoped authorization — `organizations`/
      `organization_units`/`user_memberships` tables
      (`server/src/db/org.rs`); searches and audit events are stamped
      with the actor's organization at creation time and scoped
      accordingly on every read path, with `SYSTEM_ADMIN` as the sole
      global exception; see `docs/SECURITY_ARCHITECTURE.md`. Not yet
      covering `candidates` — no real enrollment pipeline exists yet to
      stamp them from (Phase 4)
- [x] Pagination for the admin user list — `GET /api/v1/admin/users` is
      server-side paginated

## Phase 4 — Production biometric provider

- [x] Real `BiometricProvider` implementation (ONNX Runtime via `ort`,
      server-side): YuNet face detection + SFace face embedding
      (`server/src/biometric/`), selected via `BIOMETRIC_PROVIDER=onnx`.
      Both models are pinned by SHA-256 and fetched from the OpenCV Zoo at
      startup; a hash mismatch or download failure is a hard startup
      failure, never a silent fallback to the mock provider. See
      `docs/SECURITY_ARCHITECTURE.md` for exactly what this pipeline does
      and does not guarantee — in particular, its detection/alignment math
      could only be verified against synthetic (non-face) test images in
      this environment, never real photographs, since the repository must
      never contain real biometric data
- [x] Candidate enrollment pipeline — `POST /api/v1/candidates`,
      `POST /api/v1/candidates/{id}/reference-photos`,
      `GET /api/v1/candidates/{id}/templates`,
      `POST /api/v1/candidates/{id}/templates/{template_id}/revoke`; see
      `API.md`
- [x] Vector database provider abstraction — `db::biometric` stores
      embeddings as JSON and performs a real O(n) cosine-similarity Top-K
      scan (`db::top_k_matches`), filtered to non-revoked,
      model/version-compatible templates only. This is a deliberate
      interim choice, not the final architecture: it avoids depending on
      the `pgvector` extension (not guaranteed available in every
      deployment) but is not an indexed ANN search. `pgvector` (or another
      dedicated vector store, behind the same provider-abstraction
      principle) is the documented upgrade path once ANN indexing is
      actually needed
- [x] Image quality assessment (blur, brightness, face angle, multiple
      faces) — real classical-CV heuristics (Laplacian-variance blur,
      brightness-histogram lighting, landmark-symmetry pose,
      face-size ratio) in `server/src/biometric/quality.rs`, distinct from
      Phase 3.7's format/size/dimension validation, which only checks the
      file is a genuine, well-formed image, not that it contains a usable
      face. Occlusion detection is explicitly **not implemented** — no
      reliable heuristic exists without a trained model, and a fake check
      would violate CLAUDE.md's "never fake unimplemented capabilities"
      rule
- [ ] FAR/FRR/ROC calibration tooling against a real labeled dataset — not
      implemented; no authorized labeled biometric dataset exists in this
      environment to calibrate against

## Phase 5 — Authorized connectors and administration

- [x] OSINT/evidence provider abstraction — a first, deliberately scoped
      slice: `WebSearchProvider`/`NewsProvider`/`AuthorizedSocialProvider`
      traits, `SourceRegistry`, and an `EvidenceOrchestrator` that isolates
      one provider's failure from the others (`server/src/osint/`); mock
      implementations only (no authorized real OSINT API access exists in
      this environment); `candidate_evidence` storage and
      `POST/GET /api/v1/candidates/{id}/evidence[/collect]`. See `API.md`.
      **Not implemented**: a real connector, declared per-connector
      authorization type/capabilities/rate limits, entity graph, reverse
      image search, and an OSINT-specific frontend UI — each is its own,
      larger piece of work
- [x] Conservative entity resolution over non-biometric signals —
      `server/src/entity_resolution.rs`,
      `GET /api/v1/candidates/{id}/possible-duplicates`: Jaro-Winkler name
      similarity plus shared OSINT-evidence-URL detection, advisory only
      (never auto-merges/links candidates). Not implemented: phonetic
      matching, a persisted entity graph
- [x] Secondary verification workflow — `REQUIRE_SECOND_REVIEW` four-eyes
      policy (`db::record_review_decision`); see
      `docs/SECURITY_ARCHITECTURE.md`
- [ ] Administration screens
- [ ] Thin Android/iOS clients (capture/upload + result display; no on-device inference)

## Phase 6 — Hardening

- [x] Observability — `GET /metrics` (`server/src/metrics.rs`), Prometheus
      text format: HTTP request count/latency by method+route+status,
      login failures by reason, biometric search duration/outcome, OSINT
      provider outcomes. All labels are fixed-cardinality, no PII. Not
      covered: DB connection pool gauges
- [x] Performance benchmarks — `server/benches/biometric_pipeline.rs`
      (`cargo bench`, via `criterion`): probe-image validation/decode,
      template vector search, face alignment, quality checks, and a
      SQLite-backed DB-path example. Real ONNX inference and a
      Postgres-backed DB path are deliberately not benchmarked here — see
      the file's own doc comment for why
- [ ] Security tests
- [ ] Institutional deployment hardening

## Operator geolocation

The sign-in screen requests the browser's real geolocation on load (no
synthetic fallback coordinate on denial — an explicit "unavailable"
message instead) and displays it alongside the running app version. The
captured coordinate is exposed via `useGeolocation`'s
`getLastKnownLocation()`; `POST /api/v1/search/face` sends it along as
optional `latitude`/`longitude` form fields, and the search-results view
displays it when present.
