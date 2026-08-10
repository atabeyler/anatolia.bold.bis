# Enterprise Deployment Readiness

A single reference point for what an institution considering Anatolia
B.I.S. for production use actually gets today, and what it deliberately
does not yet get. This document does not introduce new capabilities — it
consolidates and cross-references what `docs/ARCHITECTURE.md`,
`docs/SECURITY_ARCHITECTURE.md`, `docs/DEPLOYMENT.md`, and
`docs/ENVIRONMENT.md` already describe, organized around the questions an
enterprise buyer or deployer actually asks. Where something is genuinely
unimplemented, it is labeled that way rather than described in
aspirational terms — see CLAUDE.md's "never claim a feature is
implemented or tested unless it was actually run and verified."

## Identity and access

- **Authentication**: user code + password (bcrypt), JWT access tokens
  (15 min) plus rotating refresh-token sessions (30 days) — see
  `docs/SECURITY_ARCHITECTURE.md`.
- **Multi-factor authentication**: TOTP (RFC 6238), voluntary for any
  role, mandatory for `MFA_REQUIRED_ROLES` (default
  `SYSTEM_ADMIN,SECURITY_ADMIN,REVIEWER`) — see `server/src/mfa.rs`,
  `API.md`.
- **RBAC**: five fixed roles (`SYSTEM_ADMIN`, `SECURITY_ADMIN`,
  `OPERATOR`, `REVIEWER`, `AUDITOR`) — see `docs/ARCHITECTURE.md`. Not
  configurable per-deployment; adding a custom role requires a code
  change, not an admin-panel action.
- **Organization/unit model**: candidates, searches, and evidence can be
  scoped to an organization; a non-`SYSTEM_ADMIN` user only sees records
  belonging to an organization they're a member of (`permission::can_view_scoped_resource`)
  — see `docs/SECURITY_ARCHITECTURE.md`. This is single-tenant-per-schema
  scoping *within* one deployment, not multi-tenant database isolation —
  every organization in one deployment shares the same database schema
  and the same encryption keys.
- **Session/device management**: a user can see every active session
  (device/browser string, IP, last used) and revoke one individually,
  self-service (`GET/DELETE /api/v1/users/me/sessions[/{id}]`) — see
  `API.md`.
- **Not implemented**: enterprise SSO (SAML/OIDC), SCIM provisioning,
  per-organization custom roles, IP allow-listing, a break-glass
  emergency-access workflow beyond the existing admin-bootstrap
  self-disable/re-enable mechanism (`docs/SECURITY_ARCHITECTURE.md`).

## Data protection

- **Encryption in transit**: TLS terminates at Render (or whatever
  reverse proxy/load balancer fronts a self-hosted deployment) — this
  application does not terminate TLS itself.
- **Encryption at rest**: `national_id` is AES-256-GCM encrypted
  (`server/src/national_id.rs`, `NATIONAL_ID_ENCRYPTION_KEY`). Everything
  else (names, biometric templates, evidence, audit trail) relies on the
  database's own at-rest encryption, if any — this application does not
  add a second layer for those fields. Rotating `NATIONAL_ID_ENCRYPTION_KEY`
  makes every existing encrypted value undecryptable; there is no
  key-rotation/re-encryption tool (see `docs/SECURITY_ARCHITECTURE.md`).
- **Audit trail**: append-only, hash-chained `audit_events` table with an
  on-demand integrity check (`GET /api/v1/audit/integrity`) — see
  `docs/SECURITY_ARCHITECTURE.md`. Tamper-evident, not tamper-proof: a
  database-level actor with direct write access could still rewrite the
  chain and recompute hashes; this is out of scope for an
  application-layer control.
- **Backups**: manual procedure only, documented in `docs/DEPLOYMENT.md`
  — no automated backup job exists. An enterprise deployment must set one
  up before going live with real data.
- **Secrets management**: environment variables only (`docs/ENVIRONMENT.md`).
  No integration with a secrets manager (Vault, AWS Secrets Manager, etc.)
  — a deployment that requires one must inject secrets into the process
  environment through its own tooling.

## Scaling and availability

- **Deployment topology**: one service, one process (Rust/Axum, serving
  both API and built frontend) — see `docs/ARCHITECTURE.md`. There is no
  built-in horizontal-scaling story (no shared session store beyond the
  database itself, no distributed rate limiter — see below); running
  multiple instances behind a load balancer is possible in principle
  (all durable state is in Postgres) but has not been tested.
- **Rate limiting**: in-process, in-memory (`InMemoryRateLimiter`) — not
  shared across instances. Running more than one instance divides the
  effective rate limit by the instance count rather than enforcing it
  globally.
- **Database**: PostgreSQL in production (SQLite is a local-dev-only
  fallback, never used in production — `docs/ARCHITECTURE.md`). Biometric
  search uses a native `vector(128)` column behind an HNSW index when the
  `pgvector` extension is available (`GET /api/health/ready` reports
  which path is active); not every managed Postgres offering allow-lists
  extensions, so confirm `pgvector` availability before assuming the
  indexed path.
- **Biometric inference**: the real ONNX provider (`BIOMETRIC_PROVIDER=onnx`)
  requires the `onnx-provider` Cargo feature and a Docker-based deploy on
  a new-enough glibc. This path has been
  verified to compile and link correctly but **has not been exercised as
  a live production deployment** — an institution enabling it should
  treat the first rollout as a verification step, not an assumed-safe
  flip.
- **Connectors**: real OSINT web-search/news providers are optional,
  independently enabled per provider via API key
  (`BRAVE_SEARCH_API_KEY`/`NEWS_API_KEY`), with a timeout/retry/circuit-breaker
  wrapper isolating one provider's outage from the others
  (`server/src/osint/resilience.rs`). Status is visible read-only at
  `GET /api/v1/admin/connectors`.

## Observability

- **Health/readiness**: `GET /api/health` (liveness) and
  `GET /api/health/ready` (readiness — DB connectivity, active biometric
  provider/search mode, process uptime, DB connection pool size/idle
  count).
- **Metrics**: `GET /metrics`, Prometheus text format — HTTP request
  count/latency by method+route+status, login failures by reason,
  biometric search duration/outcome, OSINT provider outcomes. All labels
  are fixed-cardinality; nothing exported is PII. Optionally gated by
  `METRICS_TOKEN`.
- **Logging**: structured JSON via `tracing`, no built-in log shipping —
  an enterprise deployment is expected to collect stdout/stderr with its
  own log pipeline (Render's own log viewer, a sidecar, etc.).
- **Not implemented**: distributed tracing, alerting rules/dashboards
  (this application exposes metrics; building dashboards/alerts on top of
  them is left to the deploying institution), a dedicated
  connector-rate-limit or circuit-breaker-state view beyond the basic
  real-vs-mock status `GET /api/v1/admin/connectors` reports.

## Incident response

- **Account compromise**: an admin can ban a user (revokes every active
  session immediately) or reset their MFA credential; a user can revoke
  an individual session or every session (`logout-all`) themselves.
- **Refresh-token reuse detection**: reusing an already-rotated refresh
  token revokes its entire session family, not just the reused token —
  see `docs/SECURITY_ARCHITECTURE.md`.
- **Last-admin protection**: banning, deleting, or demoting the last
  active `SYSTEM_ADMIN` is refused, so the platform can never lock itself
  out of its own administration.
- **Admin bootstrap recovery**: `POST /api/v1/admin/seed-admin`
  self-disables once any `SYSTEM_ADMIN` exists; `BOOTSTRAP_ENABLED=true`
  deliberately re-opens it for recovery if every admin account is lost —
  see `docs/SECURITY_ARCHITECTURE.md`.
- **Not implemented**: a documented incident-response runbook beyond the
  mechanisms above, automated anomaly detection/alerting on the audit
  trail or metrics.

## Compliance posture

This is a platform capability summary, not a compliance certification —
no claim is made here about GDPR, KVKK, SOC 2, ISO 27001, or any other
specific framework's requirements being met. Institutions with a
compliance obligation should map their specific requirements against the
mechanisms described in this document and `docs/SECURITY_ARCHITECTURE.md`
/ `docs/THREAT_MODEL.md` themselves, engaging their own compliance
function — this repository does not represent that mapping as complete.

## Summary: before going live with real data

1. Provision a dedicated (not shared-schema) Postgres instance if
   isolation from other workloads matters, and confirm whether `pgvector`
   is available.
2. Set every `sync: false` / required secret in `docs/ENVIRONMENT.md`
   (JWT secrets, `NATIONAL_ID_ENCRYPTION_KEY`, admin bootstrap
   credentials) — never rely on the documented development fallbacks.
3. Set up an automated backup job (see `docs/DEPLOYMENT.md` — none
   exists today) and test a restore before relying on it.
4. Decide whether the real ONNX biometric provider is required, and if
   so, run its own verification pass against the target deployment
   environment before enabling it for real searches.
5. Decide on `MFA_REQUIRED_ROLES` and `REQUIRE_SECOND_REVIEW` policy for
   the institution's own risk tolerance — both default to a permissive
   posture.
6. If horizontal scaling is required, be aware the rate limiter is
   per-instance, not shared, until that's addressed.
