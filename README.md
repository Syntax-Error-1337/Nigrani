# Nigrani

Protest-site access management: RBAC API (Rust/axum) + operations console
(Vite/React). Phases 1–4 shipped plus hardening: provisioning, audit trail,
retention, QR cards, demo reset, capture review, incident lifecycle +
realtime, KYC duplicates + revocation, login lockout, topology retirement,
snapshot lifecycle.

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
- `POST /auth/login` `{username, password}` → access JWT + rotating refresh
  replaying a revoked token burns the whole session family (`401 reused`)
- `POST /auth/logout` / `/auth/logout/all` → revoke one / all sessions
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
- Archiving a site with live gates → `409`; crossings/incidents/creates
  on archived rows → `410 Gone`; lists hide archived by default

## Press KYC

- `POST /kyc/applications` (public, 10/min per IP) → pending application
- Resubmitting a document with a live pending row → `409` (blind-index
  match, case/space-insensitive, per document type); decided rows don't
  block — re-application surfaces as `prior_decisions` ("repeat ×N")
- `GET /kyc/applications?status=&q=` (needs `kyc:review`) → reviewer queue
- `POST /kyc/applications/:id/decide` `{decision, note?}` — decided rows
  immutable (`409` on re-decide)
- `GET /kyc/applications/:id/press-card` → HMAC-signed card payload
- `GET /kyc/applications/:id/press-card.png` → scannable QR image
- `POST /kyc/applications/:id/revoke-card` (needs `kyc:review`,
  approved-only, idempotent, no un-revoke)
- `POST /kyc/verify` → `{valid, reason, application_id}` where reason ∈
  `ok|bad_signature|revoked|not_approved`

## Gate ops

- `POST /sites/:site_id/gates/:gate_id/events` (needs `entries:write`) →
  screening event; `press_card` payloads HMAC-verified AND liveness-checked
  (revoked/unapproved → `403` like forgeries); `manual` is the audited
  operator override
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
  open→investigating→resolved→closed (+ reopen); illegal jumps `409`
- `POST .../incidents/:iid/assign` `{user_id}` → assignee must hold
  `incidents:write` (`400` otherwise)
- `POST/GET .../incidents/:iid/links` `{kind: entry|embedding|snapshot|note,
  ref_id?, note?}` → evidence attachments
- `GET /sites/:site_id/heatmap` → 24h per-gate entry/exit totals
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
- VerificationOfficer: review desk (decide, revoke, press cards)
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

- Card expiry TTLs (needs re-issuance flow), per-print serials, offline CRLs
- Shared rate-limit quota across replicas (per-instance counters)
- Access-token allowlist (15-min TTL is the mitigation)
- Kubernetes manifests, TLS termination, CI pipelines
- SLA timers/escalation, case merging, courtroom export packs
- Fuzzy duplicate matching, photo-hash duplicates, partial UNIQUE index
