# Roadmap

Implemented incrementally. Each phase below is marked `[x]`/`[ ]` per
item — a phase heading does not imply everything under it is done; check
the individual items.

## Explicitly out of scope for V1

Deliberately deferred to a later release rather than blocking V1 — each
has a real reason it's excluded (external dependency this environment
doesn't have, or a scope large enough to be its own milestone), not a
placeholder waiting to be filled with a fake implementation:

- **Enterprise SSO** (SAML/OIDC) and **SCIM provisioning** — see "Identity
  and access" in `docs/ENTERPRISE_DEPLOYMENT.md`.
- **Thin Android/iOS clients** — capture/upload + result display only, no
  on-device inference (see Phase 5 below); not started.
- **Advanced occlusion detection** — no reliable heuristic exists without
  a trained model; a fake check would violate this project's rule against
  faking unimplemented capabilities (see Phase 4 below).
- **A real `AuthorizedSocialProvider`** — every candidate social-platform
  API requires its own developer agreement, not available in this
  environment (see Phase 5 below).
- **Reverse image search** (see Phase 5 below).
- **Full institutional deployment / HA / SIEM / HSM infrastructure** — load
  balancing beyond a single instance, a shared (non-in-memory) rate
  limiter, SIEM/log-pipeline integration, and hardware security module
  key storage. See "Scaling and availability" and "Data protection" in
  `docs/ENTERPRISE_DEPLOYMENT.md` for what exists today instead.

None of these block V1 closure; each is called out again in its own
phase below with the specific reason it's excluded.

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
- [x] TOTP multi-factor authentication (`server/src/mfa.rs`) — voluntary
      enrollment for any role, mandatory for `MFA_REQUIRED_ROLES`; see
      `API.md`
- [x] Session/device management — `GET/DELETE /api/v1/users/me/sessions[/{id}]`
      over the `sessions` table Phase 3.5 already introduced, plus a
      self-service "Sessions" tab in Settings
      (`client/src/components/SettingsOverlay.tsx`) listing every active
      device (browser/OS string, IP, last used, which one is the current
      request) with a "sign out this device" action, ownership-checked
      server-side so a session id can never be used to probe or revoke
      another account's session
- [ ] Enterprise SSO

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

- [x] Transactional search finalization (`db::finalize_queued_search`):
      search row + every candidate result written in one transaction; a
      failure rolls back and is recorded as a `failed` search rather than
      leaving a partial candidate list or vanishing silently
- [x] Search status state machine (`queued`/`processing`/`completed`/
      `failed`, `started_at`/`completed_at`/`failure_code`/
      `failure_message_key`) — now the real, reachable async flow (see
      Phase 6 below), not just a conceptual one; `cancelled` is defined
      in the schema but has no code path that reaches it yet
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
- [x] Async search flow — `POST /api/v1/search/face` returns `202
      Accepted` with a queued search id immediately; the biometric
      pipeline runs in a background task, polled via `GET
      /api/v1/search/{id}/status`. A deliberate response-contract change
      (the endpoint previously returned a synchronous `200` with the
      finished result), made with the repository owner's explicit choice
      of `202` + polling over `202` + SSE/WebSocket — the latter adds
      connection-management complexity disproportionate to a pipeline
      that completes in seconds, not minutes. See `API.md`

## Phase 4 — Production biometric provider

- [x] Real `BiometricProvider` implementation (ONNX Runtime via `ort`,
      server-side): YuNet face detection + SFace face embedding
      (`server/src/biometric/`), selected via `BIOMETRIC_PROVIDER=onnx`.
      Both models are pinned by SHA-256 and fetched from the OpenCV Zoo at
      startup; a hash mismatch or download failure is a hard startup
      failure, never a silent fallback to the mock provider. The active
      provider (and biometric search mode) is reported at
      `GET /api/health/ready`. See `docs/SECURITY_ARCHITECTURE.md` for
      exactly what this pipeline does and does not guarantee — in
      particular, its detection/alignment math could only be verified
      against synthetic (non-face) test images in this environment, never
      real photographs, since the repository must never contain real
      biometric data. Building the `onnx-provider` feature on Render
      requires switching that service to a Docker-based deploy (Debian
      "trixie", glibc >= 2.38) — the native Rust buildpack's older glibc
      cannot link `ort`'s prebuilt runtime; see `docs/ENVIRONMENT.md` for
      the verified root cause and the Docker path, not yet exercised as a
      live Render deployment
- [x] Candidate enrollment pipeline — `POST /api/v1/candidates`,
      `POST /api/v1/candidates/{id}/reference-photos`,
      `GET /api/v1/candidates/{id}/templates`,
      `POST /api/v1/candidates/{id}/templates/{template_id}/revoke`; see
      `API.md`
- [x] Vector database provider abstraction — `db::biometric` stores
      embeddings as JSON (both backends) for a real, correct O(n)
      cosine-similarity Top-K scan (`db::top_k_matches`), and, on
      PostgreSQL, *also* as a native `vector(128)` column behind a real
      HNSW index using cosine distance (the `pgvector` extension —
      `db::biometric::ensure_pgvector_index`). `db::search_top_k` chooses
      explicitly between the indexed and brute-force paths based on
      whether the extension could be enabled at startup (not every
      managed Postgres host allow-lists it) — `AppState::pgvector_search_ready`,
      reported at `GET /api/health/ready`. Verified against a real local
      Postgres 16 + pgvector 0.6 instance: `server/tests/pgvector_search.rs`
      confirms the indexed and brute-force paths agree on ranking and
      score for a small dataset (opt-in, `PGVECTOR_TEST_DATABASE_URL`)
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
- [x] FAR/FRR/ROC calibration tooling — `server/src/bin/calibrate.rs`
      supports `--format text|json|csv` output and, with
      `--model-name`/`--model-version`/`--save-threshold`, persists the
      computed threshold and equal-error-rate to a new
      `biometric_thresholds` table (`db::save_calibrated_threshold`, upsert
      per model name+version), visible to admins at
      `GET /api/v1/admin/biometric-thresholds`. No authorized labeled
      biometric dataset exists in this environment, so the tool has only
      been run against its own synthetic self-test pairs, never a real
      calibration dataset — an operator with real labeled data runs this
      CLI against it before trusting a threshold in production

## Phase 5 — Authorized connectors and administration

- [x] OSINT/evidence provider abstraction: `WebSearchProvider`/
      `NewsProvider`/`AuthorizedSocialProvider` traits, `SourceRegistry`,
      an `EvidenceOrchestrator` that isolates one provider's failure from
      the others (`server/src/osint/`), and real (non-mock) web-search
      (Brave Search API) and news (NewsAPI.org) providers with a
      timeout/retry/circuit-breaker wrapper (`server/src/osint/resilience.rs`) —
      `EvidenceOrchestrator::from_env` uses the real provider when
      `BRAVE_SEARCH_API_KEY`/`NEWS_API_KEY` is set, the mock otherwise,
      independently per slot. `candidate_evidence` storage and
      `POST/GET /api/v1/candidates/{id}/evidence[/collect]`. See `API.md`.
      Connector status is now visible read-only at
      `GET /api/v1/admin/connectors` (which provider is active in each
      slot, real or mock) — see `osint::EvidenceOrchestrator::provider_status`'s
      doc comment for why this stops at reporting rather than adding
      runtime enable/disable: configuration stays environment-variable
      based, the same pattern every other provider toggle in this
      codebase uses. A per-candidate OSINT frontend workspace now exists
      (`client/src/components/OsintWorkspace.tsx`, opened from a
      candidate row on the dashboard): trigger evidence collection, view
      collected evidence, view/add entity-graph relations, and view
      possible duplicates, all in one place — previously only an evidence
      *count* badge existed in the frontend, with no way to actually
      collect evidence or view entity-graph relations from the UI at all.
      **Not implemented**: a real `AuthorizedSocialProvider` (every
      candidate social-platform API requires its own developer agreement,
      not available in this environment — see that trait's doc comment),
      per-connector rate-limit configuration (there is no runtime-tunable
      rate limit to report or change today), and reverse image search —
      each is its own, larger piece of work
- [x] Conservative entity resolution over non-biometric signals —
      `server/src/entity_resolution.rs`,
      `GET /api/v1/candidates/{id}/possible-duplicates`: Jaro-Winkler name
      similarity, shared OSINT-evidence-URL detection, and shared
      alias/username/organization entity-graph relations, advisory only
      (never auto-merges/links candidates). Each possible match now reports
      exactly which signal(s) fired (`matchedSignals` — `name_similarity`,
      `shared_evidence_url`, `shared_alias`, `shared_username`,
      `shared_organization`) instead of a single blended score. Not
      implemented: phonetic matching, geography/temporal signals (no real
      per-candidate location/time data exists to compare)
- [x] Entity graph — candidate-centric relations to aliases, usernames,
      organizations, and websites (`server/src/db/entity_graph.rs`,
      `GET/POST /api/v1/candidates/{id}/entity-graph`). `website`
      relations are recorded automatically from evidence URLs; `alias`/
      `username`/`organization` relations are recorded manually by a human
      reviewer — there is no automatic name/username/organization
      extraction from evidence text (real NLP work, not attempted).
      Always advisory, never an automatic merge. Organization-scoped the
      same way searches are (`permission::can_view_scoped_resource`),
      which required extending `candidates`/`create_candidate` to actually
      stamp and read `organization_id` — previously present as a column
      but never enforced (see `docs/SECURITY_ARCHITECTURE.md`)
- [x] Secondary verification workflow — `REQUIRE_SECOND_REVIEW` four-eyes
      policy (`db::record_review_decision`); see
      `docs/SECURITY_ARCHITECTURE.md`
- [x] Administration screens — `client/src/pages/AdminPage.tsx` has three
      tabs: Users (existing user management), Organizations
      (`OrganizationsPanel.tsx`, backed by `orgClient.ts`: create
      organizations, create/list units per organization, assign
      memberships by user/organization ID), System (`SystemPanel.tsx`,
      backed by `systemClient.ts`: readiness/biometric provider/search-mode
      status, calibrated threshold list, OSINT connector status, an
      on-demand audit-chain integrity check). Session/device management
      is self-service rather than an admin screen — see "Session/device
      management" under Phase 2. MFA-policy configuration stays
      environment-variable-only (`MFA_REQUIRED_ROLES`, see
      `docs/ENVIRONMENT.md`) — a dedicated screen for editing it at
      runtime is **not implemented**
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
- [x] Security regression: organization-scope enforcement was audited
      across every candidate-scoped route and found inconsistent — several
      routes (`POST /candidates/{id}/reference-photos`,
      `GET /candidates/{id}/templates`,
      `POST /candidates/{id}/templates/{template_id}/revoke`,
      `GET/POST /candidates/{id}/evidence[/collect]`,
      `GET /candidates/{id}/possible-duplicates`) loaded the candidate but
      never checked the requester's organization against it, unlike
      search routes. Fixed with a shared
      `candidates::authorize_candidate_scope` helper, applied to every
      route above plus the entity-graph route; covered by 2 new
      regression tests in `server/tests/entity_graph.rs` asserting a
      different organization's member is refused on each of these routes
- [ ] Institutional deployment hardening

## Operator geolocation

The sign-in screen requests the browser's real geolocation on load (no
synthetic fallback coordinate on denial — an explicit "unavailable"
message instead) and displays it alongside the running app version. The
captured coordinate is exposed via `useGeolocation`'s
`getLastKnownLocation()`; `POST /api/v1/search/face` sends it along as
optional `latitude`/`longitude` form fields, and the search-results view
displays it when present.
