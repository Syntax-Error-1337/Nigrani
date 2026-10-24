# Nigrani

Protest-site access management: RBAC API (Rust/axum) + operations console
(Vite/React). Phases 1–4 shipped plus hardening: provisioning, audit trail,
retention, QR cards, demo reset, capture review, incident lifecycle +
realtime, KYC duplicates + revocation, card lifecycle (expiry, per-print
serials, reissue, offline CRL), login lockout, topology retirement,
snapshot lifecycle.

Console styling follows the UX4G 2.0 "Saffron Green Navy" India theme: GoI
portal palette, Noto Sans (Hindi + English), GIGW 3.0 accessibility
patterns (skip link, A−/A/A+ text-size switcher, AA contrast).

## Quick start

```sh
docker compose up -d db s3   # db is the pgvector image
cd backend && cp .env.example .env && cargo run     # :8080
cd frontend && npm install && npm run dev           # :5173
```

Seeded logins (password `password`): `superadmin`, `commander`,
`gate`, `verifier`, `analyst`.

Public press accreditation (no login): `http://localhost:5173/press`.
Gate kiosk: sign in as `gate`, pick a site and gate post.

Roles: SuperAdmin, SiteCommander, GateOperator, VerificationOfficer,
ForensicAnalyst. Permissions checked per request; SuperAdmin bypasses.

## Auth & accounts

- `GET /health` → `ok`
- `GET /stats` (needs `sites:read`) → `{sites, gates, crossings_24h, pending_kyc, open_incidents}` — the console's dashboard overview row
- `POST /auth/login` `{username, password}` → access JWT + rotating refresh
  replaying a revoked token burns the whole session family (`401 reused`)
- `POST /auth/logout` / `/auth/logout/all` → revoke one / all sessions
  (logout-all also kills sibling access tokens mid-TTL)
- `POST /auth/revoke-access` → instantly kill the **presented** access token
  (self-revocation only; idempotent). Access tokens are allowlisted: every
  request (and the `/events` WS upgrade) requires the minted `jti` row to be
  live, so deactivation, lockout, logout-all, and self-revocation all take
  effect immediately — not at the 15-min expiry
- `GET /auth/me` → own identity + `locked_until` when locked
- `GET /users` (needs `users:read`); `POST /users` (needs `users:write`)
- `POST /users/:id/deactivate|reactivate` (needs `users:write`, never self)
- `POST /users/:id/unlock` (needs `users:write`, never self) → clears
  lockout strikes + lock
- `POST /auth/password` (self-service change, kills other sessions)
- Lockout: 5 consecutive bad passwords → 15-min lock; locked logins `401`
  identically to bad credentials (no oracle); any success resets strikes

## Topology

- `GET/POST /sites` (`?q=`, `?include=archived`), `GET/POST
  /sites/:site_id/gates` (same filters)
- `POST /sites/:id/archive/archive|restore` (needs `sites:write`);
  `POST /sites/:sid/gates/:gid/archive/archive|restore` (needs
  `gates:write`)
- Gate duty: `POST /sites/:sid/gates/:gid/duty` `{user_id|null}` (needs
  `gates:write`) — assigns the gate's duty officer (active user holding
  `entries:write`, else `400`; unknown → `404`; `null` clears). Gate
  responses carry `duty_officer`/`duty_username`. `GET /my/duty` → the
  caller's own duty roster (`gate_id, gate_name, direction, site_id,
  site_name`). VerificationOfficers hold `entries:write` and can staff
  gates; the console's Gate duty panel lists assigned gates and mounts the
  kiosk for the selected post
- Archiving a site with live gates → `409`; crossings/incidents/creates
  on archived rows → `410 Gone`; lists hide archived by default

## Press KYC

- `POST /kyc/applications` (public, 10/min per IP) → pending application
- Resubmitting a document with a live pending row → `409` (blind-index
  match, case/space-insensitive, per document type); decided rows don't
  block — re-application surfaces as `prior_decisions` ("repeat ×N")
- **Fuzzy duplicates** (migration 0022): at submit the application is
  compared in memory against recent rows — name similarity, decrypted
  document-number similarity (normalized Levenshtein ≥ 0.85), and SHA-256
  photo-hash equality for `data:` URL photos (2 MB cap). Flags persist
  ids-only (`kyc_duplicates`) and never block; the queue shows
  "dup? name 0.92"-style badges, the submit response carries them too
- `GET /kyc/applications?status=&q=` (needs `kyc:review`) → reviewer queue
- `POST /kyc/applications/:id/decide` `{decision, note?}` — decided rows
  immutable (`409` on re-decide)
- `GET /kyc/applications/:id/press-card` → HMAC-signed card payload; the
  first print lazily mints a per-print serial (`SG-<app-hex>-<print#>`) and
  a 90-day expiry (`card_print_count` grows per print)
- `GET /kyc/applications/:id/press-card.png` → scannable QR image
- `POST /kyc/applications/:id/reissue` (needs `kyc:review`, approved +
  unrevoked) → rotates the serial, refreshes the 90-day expiry, archives
  the old serial as `superseded` (audited `kyc.card_reissued`)
- `POST /kyc/applications/:id/revoke-card` (needs `kyc:review`,
  approved-only, idempotent, no un-revoke)
- `POST /kyc/verify` → `{valid, reason, application_id}` where reason ∈
  `ok|bad_signature|revoked|not_approved|expired|superseded`
- `GET /kyc/crl` (needs `kyc:review`) → offline CRL as a downloadable JSON
  attachment (`{generated_at, revoked, expired, superseded}`; plain JSON —
  revocation evidence stays covered by the hash-chained audit)

## Gate ops

- `POST /sites/:site_id/gates/:gate_id/events` (needs `entries:write`) →
  screening event; `press_card` payloads HMAC-verified AND liveness-checked
  (revoked/unapproved/expired/superseded → `403` like forgeries); `manual`
  is the audited operator override
- `GET /sites/:site_id/gates/:gate_id/log` → recent crossings
- `POST /snapshots` (JPEG ≤ 5MB, needs `entries:write`) → `{key}`;
  `GET /snapshots/:key` (streams JPEG) / `/snapshots/:key/share`
  (15-min presigned URL) need `gates:read`

## Forensics

- `POST /forensics/embeddings` (needs `forensics:search`) → store 512-d vector
- `POST /forensics/search` `{embedding, threshold?, limit?, site_id?}` →
  cosine-ranked matches `{id, distance}`
- `GET/POST /sites/:site_id/incidents` → file/list cases
- `POST .../incidents/:iid/status` `{status}` → workflow
- `POST .../incidents/:iid/merge` `{into}` → same-site case merge: evidence
  links move to the survivor, absorbed case closes as `merged_into`
  (read-only after; chains and self-merges refused)
- `GET .../incidents/:iid/pack` → courtroom export: self-contained JSON with
  the case, evidence resolved to real rows (crossing rows, 512-d vectors,
  snapshot keys, notes), the site's audit slice, and the hash-chain verdict
- SLA: new cases carry `sla_due_at` (created + 72h); an open/investigating
  case past due reports `overdue: true` and escalates lazily — the first
  list read stamps `escalated_at`, audits, and fans out `escalated`
- `POST .../incidents/:iid/assign` `{user_id}` → assignee must hold
  `incidents:write` (`400` otherwise)
- `POST/GET .../incidents/:iid/links` `{kind: entry|embedding|snapshot|note,
  ref_id?, note?}` → evidence attachments
- `GET /sites/:site_id/heatmap` → 24h per-gate entry/exit totals
- `GET /sites/:site_id/trends?hours=168` (2..=720, needs `gates:read`) → hourly
  entry/exit buckets across the site — occupancy trends beyond the 24h view
- `GET|POST /sites/:site_id/surge` → per-site surge alerting: set/clear a
  threshold (entries/hour/gate, 1..=10000, needs `sites:write`); crossing it
  fires one deduped alert per gate-hour, audited, fanned out live on
  `/events` as `surge`
- Forensic bench updates live over the event stream (no manual refresh)

## Realtime

- `GET /events?token=` → WebSocket stream: `crossing`, `kyc_decided`,
  `topology`, `incident{created|status|assigned|linked}`. Hint semantics —
  REST stays source of truth; clients reconnect with backoff.

## Audit

- Every mutation appends a hash-chained row (`actor, action, entity,
  detail, prev_hash, hash`); `GET /audit` (SuperAdmin),
  `GET /sites/:site_id/audit` (scoped), `GET /audit/verify` →
  `{ok, checked, first_bad}`
- Deleting a user with trail history is refused (actor FK is RESTRICT) —
  silent attribution loss is impossible; deactivate instead

## Retention & snapshots

- `GET /admin/retention/policies` / `POST .../policies/:entity`
  `{retain_days}` / `POST /admin/retention/run` (all SuperAdmin) →
  per-entity windows incl. `incidents`, `incident_links`
- `GET /sites/:site_id/export` → gates + logs + incidents (with status/
  assignee) + evidence links as JSON
- `POST /admin/snapshots/collect` `{dry_run?}` (SuperAdmin, dry-run
  default) → orphan S3-key collection with counts; Retention panel shows
  the orphan console

## Demo reset

- `POST /admin/demo/reset` (SuperAdmin, refused with `APP_ENV=production`)
  → truncates ops data, reseeds users + Jantar Mantar + Gates 1–4

## Errors

Every error is `{error, request_id}` (`X-Request-ID` echo). Status guide:
`400` validation, `401` credentials (incl. locked — deliberate),
`403` permission/scan-denied, `404` missing, `409` state conflict,
`410` archived/retired, `429` rate limit, `500` storage/crypto unavailable.

## Console tour

- SuperAdmin: everything — sites/gates + Archive buttons, Operators
  (provision/deactivate/unlock), ReviewDesk (+ repeat + revoked badges),
  Kiosk, Forensic bench (status/assign/links), heatmap, Audit trail +
  verifier, Retention (policies/purge/export + orphan console)
- SiteCommander: sites/gates, kiosk, audit (scoped)
- GateOperator: kiosk (card + manual + snapshot)
- VerificationOfficer: review desk (decide, revoke, reissue, press cards,
  CRL export)
- ForensicAnalyst: bench + heatmap + incidents

## Tests

```sh
docker compose up -d db
cd backend && cargo test        # 31 integration tests (live DB)
cargo clippy --all-targets -- -D warnings
cd ../frontend && npx tsc -b && npx oxlint
```

## Layout

- `backend/src/{api,core,domain,infrastructure}` + `backend/migrations`
  (0015 to date: incidents, retention, fingerprints, lockout, retirement,
  audit-actor, revocation)
- `backend/tests/slice.rs` — RBAC, KYC + duplicates + revocation, gate
  scans, forensics, incidents + realtime, lockout, retirement, snapshots,
  retention, audit chain, ops
- `frontend/src` — `App.tsx` routes, `Login.tsx`, `Dashboard.tsx`,
  `PressApply.tsx`, `ReviewDesk.tsx`, `Kiosk.tsx`, `ForensicBench.tsx`,
  `OperatorsPanel.tsx`, `RetentionPanel.tsx`, `AuditTrail.tsx`,
  `events.ts` (shared WS stream), `session.ts` (zustand), `api.ts`
  (tanstack-query)
- `docs/` — per-slice scope notes (`*_SLICE.md`) + `SCOPE.md`

## Deploy

```sh
docker compose up --build -d   # db + s3 + api; API on :8080
```

Local dev stays split-process (`cargo run` + `npm run dev`); the `api`
service is for a single-host staging box. Production secrets come from the
environment (`JWT_SECRET`, `APP_ENV=production` blocks default seeding).

## Backups

```sh
# Postgres (roles, logs, embeddings, incidents)
docker exec protest-db-1 pg_dump -U nigrani nigrani > backup.sql
# Snapshots (S3 bucket)
aws --endpoint-url http://127.0.0.1:4566 s3 sync \
  s3://nigrani-snapshots ./backup-snapshots
```

## Out of scope (recorded)

- Rate-limit counters are Postgres-backed and shared across replicas
  (migration 0019); a dedicated Redis tier is not used. The `/events` WS
  upgrade path enforces the same allowlist; long-lived sockets past a
  revocation close on their next client action
- SLA timers/escalation, case merging, courtroom export packs — all shipped
  (see incidents section); SLA is a 72h constant, escalation is lazy
  (stamped by the first read that sees a breached case, audited + fanned
  out); merging is same-site, no chains, evidence links move; packs are
  self-contained JSON (case + resolved evidence + site audit slice +
  chain verdict)
- Fuzzy duplicate matching, photo-hash duplicates — both shipped (see KYC
  section): flagged at submit, ids-only persistence, never blocking; the
  partial UNIQUE index remains a PostgreSQL-level idea (the blind-index
  check makes it redundant at this scale)

## Deployment & CI

- `k8s/nigrani.yaml`: 2-replica Deployment with `/health` probes, Service,
  cert-manager TLS Ingress (termination at the ingress controller), and a
  sticky-session Ingress for the WS stream. Secrets come from a
  `nigrani-secrets` Secret (`kubectl create secret generic nigrani-secrets
  --from-literal=database-url=... --from-literal=jwt-secret=...
  --from-literal=biometric-key=... --from-literal=aws-key-id=...
  --from-literal=aws-secret=...`).
- `.github/workflows/ci.yml`: backend job (clippy `-D warnings` +
  `cargo test` against a fresh `nigrani_test` on pgvector/LocalStack
  services) and frontend job (`tsc -b` + `oxlint`).
