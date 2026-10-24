# Nigrani — Complete Feature Requirements

What this system requires to control and manage protest-site access: register
every site and gate, vet and credential press attendees, screen and log every
crossing (card-scan or manual override), watch crowd flow live, investigate
incidents with forensic evidence, and keep every action attributable and
tamper-evident. Five roles run it: **SuperAdmin, SiteCommander, GateOperator,
VerificationOfficer, ForensicAnalyst** — permissions checked per request.

Status legend: ✅ shipped · ◐ recorded requirement, not yet built.

---

## 1. Identity, roles & account control

| # | Feature | Requirement it serves | Status |
|---|---------|----------------------|--------|
| 1.1 | Operator provisioning — create operators per role (`POST /users`) | Only vetted staff hold credentials | ✅ |
| 1.2 | Account deactivation/reactivation (`/users/:id/deactivate|reactivate`, never self) | Remove access the moment an operator is pulled off duty, without destroying their audit trail (actor FK is `RESTRICT` — deletion is refused, attribution is never lost) | ✅ |
| 1.3 | Login lockout — 5 bad passwords → 15-min lock; locked logins fail identically to bad credentials (no oracle); any success resets strikes; unlock endpoint (never self) | Credential-stuffing resistance on an ops console that gates physical sites | ✅ |
| 1.4 | Self-service password change (`POST /auth/password`, kills other sessions) | Compromised credential is revocable by the operator | ✅ |
| 1.5 | JWT access tokens (15-min TTL) + **rotating refresh tokens**; replaying a revoked refresh burns the whole session family | Stolen refresh tokens can't be replayed | ✅ |
| 1.6 | Single & all-device logout (`/auth/logout`, `/auth/logout/all`) | A pulled operator is logged out everywhere instantly | ✅ |
| 1.7 | Session validation on every request — token dies as a clean `401` if its user is deleted/deactivated | Deactivation takes effect immediately, not at token expiry | ✅ |
| 1.8 | Per-request permission checks, SuperAdmin bypass; permission-gated roster filters (`/users/assignable?perm=`) | Least-privilege assignment of duty/cases | ✅ |
| 1.9 | Rate limiting on auth + public KYC (per-instance counters) | Brute-force and spam throttling | ✅ |
| 1.10 | Cluster-wide rate-limit quota | Limits hold across replicas | ◐ (out-of-scope note) |
| 1.11 | Access-token allowlist (instant single-token revocation) | Kill one stolen access token mid-TTL | ◐ (15-min TTL is the mitigation) |
| 1.12 | Card expiry TTL + re-issuance flow, per-print card serials, offline CRL (plain-JSON export; revocation evidence covered by the hash-chained audit) | Credential lifecycle beyond revocation | ✅ |

## 2. Site & gate topology (the physical layout being controlled)

| # | Feature | Status |
|---|---------|--------|
| 2.1 | Register protest sites (name, location) — `POST /sites` | ✅ |
| 2.2 | Register gates per site with direction `entry`/`exit`/`both` — `POST /sites/:sid/gates` | ✅ |
| 2.3 | Search/filter sites & gates (`?q=`), archived-visibility toggle (`?include=archived`) | ✅ |
| 2.4 | Retirement: archive/restore sites and gates — `POST .../archive/archive|restore`; site with live gates refuses (`409`); acting on archived rows is `410 Gone`; lists hide retired rows | ✅ |
| 2.5 | **Gate duty officers** — assign an active user holding `entries:write` to a gate (`POST .../duty {user_id|null}`, audited, topology-fanned); gate responses carry the duty officer; `GET /my/duty` returns the caller's own posts | ✅ |
| 2.6 | Console overview counts (`GET /stats`: sites, gates, crossings-24h, pending press, open cases) | ✅ |

## 3. Press / protester credentialing (KYC)

| # | Feature | Status |
|---|---------|--------|
| 3.1 | **Public accreditation application** (no login, rate-limited 10/min per IP): full name, organization, document type, document number | ✅ |
| 3.2 | **Duplicate document blocking** — blind index (case/space-insensitive per document type) refuses a live pending duplicate (`409`); decided rows don't block and resurfacing shows as `prior_decisions` ("repeat ×N" badge on the review desk) | ✅ |
| 3.3 | **PII encryption at rest** — KYC identity data AES-256-GCM under `BIOMETRIC_KEY`; key unset → endpoints fail closed (500, never plaintext) | ✅ |
| 3.4 | Reviewer queue with status + text search (`GET /kyc/applications?status=&q=`) | ✅ |
| 3.5 | Approve/reject with decision immutability (`409` on re-decide); rejections require an actionable note | ✅ |
| 3.6 | **HMAC-signed press cards** + scannable **QR PNG** issued per approval | ✅ |
| 3.7 | **Card revocation** — approved-only, idempotent, no un-revoke; a revoked card scans as `revoked` at every gate instantly | ✅ |
| 3.8 | Gate-side verification `POST /kyc/verify` → `{valid, reason ∈ ok|bad_signature|revoked|not_approved|expired|superseded}` | ✅ |
| 3.9 | **Card lifecycle** — first print lazily mints serial `SG-<app-hex>-<print#>` + 90-day expiry (concurrent prints share one serial); `POST /kyc/applications/:id/reissue` rotates the serial + refreshes expiry and archives the old serial (scans of it answer `superseded`); `GET /kyc/crl` exports revoked/expired/superseded as a downloadable JSON attachment; review desk shows serial/print count/expiry + reissue button, kiosk maps the new deny reasons | ✅ |

## 4. Gate screening & crossing control

| # | Feature | Status |
|---|---------|--------|
| 4.1 | Kiosk per gate post — operator picks site + gate (or auto-mounts from duty roster) | ✅ |
| 4.2 | **Card-scan entry** — `press_card` payload HMAC-verified AND liveness-checked; revoked/unapproved treated like forgeries (`403`) | ✅ |
| 4.3 | **Manual override** — audited operator decision to admit/deny without a card (gates must keep moving when tech fails) | ✅ |
| 4.4 | Entry/exit direction on every crossing event | ✅ |
| 4.5 | Live crossing log per gate (`GET .../log`) | ✅ |
| 4.6 | **Snapshot capture** at the gate (JPEG ≤ 5 MB → S3 key), streaming retrieval, 15-min presigned share links | ✅ |
| 4.7 | Every scan/override lands in the realtime stream | ✅ |

## 5. Crowd-flow monitoring & situational awareness

| # | Feature | Status |
|---|---------|--------|
| 5.1 | **Realtime event stream** (`GET /events?token=` WebSocket): `crossing`, `kyc_decided`, `topology`, `incident{created|status|assigned|linked}`; hint semantics — REST stays source of truth; clients reconnect with backoff | ✅ |
| 5.2 | **Heatmap** — 24h per-gate entry/exit totals per site (`GET /sites/:sid/heatmap`), proportional bars on the console | ✅ |
| 5.3 | Dashboard KPI row auto-refreshing every 30 s + live indicator on the console | ✅ |
| 5.4 | Live gate heat: which entry is surging right now | ✅ (via 4.5 + 5.2) |
| 5.5 | Historical occupancy / density trends beyond 24h; surge alerts & thresholds | ◐ (not required by any shipped slice) |

## 6. Forensics & identification

| # | Feature | Status |
|---|---------|--------|
| 6.1 | **Face-embedding enrollment** — 512-d vectors (pgvector) `POST /forensics/embeddings` | ✅ |
| 6.2 | **Cosine-similarity search** with threshold/limit/site scoping → ranked matches | ✅ |
| 6.3 | Forensic bench UI live over the event stream (no manual refresh) | ✅ |
| 6.4 | Fuzzy duplicate matching, photo-hash duplicates (KYC-side) | ◐ (out-of-scope note) |

## 7. Incident management

| # | Feature | Status |
|---|---------|--------|
| 7.1 | File cases per site (`POST /sites/:sid/incidents`); list with status/assignee filters | ✅ |
| 7.2 | **Enforced workflow** — `open → investigating → resolved → closed` (+ reopen); illegal jumps `409` | ✅ |
| 7.3 | Assignment to users holding `incidents:write` (`400` otherwise) | ✅ |
| 7.4 | **Evidence links** — `entry | embedding | snapshot | note` attached to a case; entry links must cite a real crossing at that site | ✅ |
| 7.5 | Incident events fan out live to all consoles | ✅ |

## 8. Accountability & tamper-evidence

| # | Feature | Status |
|---|---------|--------|
| 8.1 | **Hash-chained audit log** — every mutation appends `actor, action, entity, detail, prev_hash, hash` | ✅ |
| 8.2 | Chain verifier `GET /audit/verify` → `{ok, checked, first_bad}` — any tampering is detectable | ✅ |
| 8.3 | Global audit (SuperAdmin) + site-scoped audit (commanders) | ✅ |
| 8.4 | Structured errors everywhere: `{error, request_id}` with `X-Request-ID` echo; status guide 400/401/403/404/409/410/429/500 | ✅ |

## 9. Data governance, retention & export

| # | Feature | Status |
|---|---------|--------|
| 9.1 | **Per-entity retention policies** (`retain_days`, incl. `incidents`, `incident_links`) | ✅ |
| 9.2 | Retention **dry-run preview** mirroring the real run before it executes | ✅ |
| 9.3 | Retention run (SuperAdmin) purging expired rows | ✅ |
| 9.4 | **Orphan snapshot collection** — S3 keys with no DB row, dry-run by default | ✅ |
| 9.5 | **Site export** — gates + crossing logs + incidents (status/assignee) + evidence links as JSON (`GET /sites/:sid/export`) | ✅ |
| 9.6 | Backup runbooks: `pg_dump` for Postgres, `aws s3 sync` for snapshots | ✅ |
| 9.7 | Courtroom export packs, case merging | ◐ (out-of-scope note) |

## 10. Ops, deployment & integrity

| # | Feature | Status |
|---|---------|--------|
| 10.1 | `docker compose` stack (pgvector DB + LocalStack S3 + API); split-process dev mode | ✅ |
| 10.2 | **Demo reset** — truncate + reseed, refused in `APP_ENV=production`, truthful truncate report | ✅ |
| 10.3 | Migrations 0001–0017 (schema, forensics, retention, fingerprints, lockout, retirement, audit-actor, revocation, gate duty, card lifecycle) | ✅ |
| 10.4 | **46 integration tests** in an isolated `nigrani_test` DB (`TEST_DATABASE_URL`) with cold-start serialization; clippy `-D warnings`; `tsc -b` + `oxlint` | ✅ |
| 10.5 | Production hardening: `APP_ENV=production` blocks default seeding; `JWT_SECRET` ≥ 32 chars | ✅ |
| 10.6 | Kubernetes manifests, TLS termination, CI pipelines | ◐ (out-of-scope note) |

## 11. Console UX (UX4G 2.0 India theme)

| # | Feature | Status |
|---|---------|--------|
| 11.1 | GoI "Saffron Green Navy" palette, Noto Sans (Hindi + English), tricolor identity strip, bilingual brand | ✅ |
| 11.2 | GIGW 3.0 accessibility: skip-to-content, **A−/A/A+ text-size switcher**, keyboard focus rings, AA contrast throughout | ✅ |
| 11.3 | Role-scoped consoles: SuperAdmin (everything), SiteCommander (sites/gates/kiosk/scoped audit), GateOperator (kiosk), VerificationOfficer (review desk + duty roster), ForensicAnalyst (bench + heatmap) | ✅ |
| 11.4 | Public press application page (no login, tricolor-branded) | ✅ |
| 11.5 | Live indicator, KPI cards, proportional heat bars, expandable audit feed with chain verdict | ✅ |

---

## Shipped system summary

- **Control loop**: register topology → credential people → screen crossings → watch flow live → investigate incidents → purge on retention → prove it all in the audit chain.
- **Monitoring of protesters** is by design *credential- and crossing-based*: press attendees are KYC-vetted and QR-tracked per gate; every crossing (card or manual) is logged with direction and time; snapshots and 512-d embeddings support post-hoc identification; heatmaps and the realtime stream give commanders live gate-level flow.
- **Trust guarantees**: hash-chained audit, rotating-refresh session families, revoked-card liveness, duplicate-document blind index, encrypted PII at rest, fail-closed crypto.

## Recorded-but-unbuilt requirements (◐ above)

Cluster rate-limit quota · access-token allowlist · K8s/TLS/CI · SLA
timers/escalation, case merging, courtroom packs · fuzzy/photo-hash duplicate
matching · occupancy trends beyond 24h and surge alerting.
