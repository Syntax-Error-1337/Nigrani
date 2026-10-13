# Nigrani

Protest-site access management: RBAC API (Rust/axum) + operations console
(Vite/React). Shipped: Phase 1 core + Phase 2 press KYC.

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

## API

- `GET /health` → `ok`
- `POST /auth/login` `{username, password}` → access JWT + rotating refresh
- `POST /auth/refresh` `{refresh_token}` → fresh pair, old token revoked;
  replaying a revoked token burns the whole session family (`401 reused`)
- `GET /auth/me`, `GET /users` (needs `users:read`)
- `GET/POST /sites`, `GET/POST /sites/:site_id/gates`
- `POST /kyc/applications` (public, 10/min per IP) → pending application
- `GET /kyc/applications?status=` (needs `kyc:review`) → reviewer queue
- `POST /kyc/applications/:id/decide` `{decision: approved|rejected}` —
  decided rows immutable (`409` on re-decide)
- `GET /kyc/applications/:id/press-card` → HMAC-signed card payload
  (paste into any QR generator for gate scans)
- `POST /kyc/verify` → `{valid, application_id}` card check for gate roles
- `POST /sites/:site_id/gates/:gate_id/events` (needs `entries:write`) →
  screening event; card payloads HMAC-verified
- `GET /sites/:site_id/gates/:gate_id/log` → recent crossings
- `POST /snapshots` (JPEG ≤ 5MB) / `GET /snapshots/:key` → S3 snapshots
- `GET /events?token=` → WebSocket stream of crossings, KYC decisions, topology
- `POST /forensics/embeddings` (needs `forensics:search`) → store 512-d vector
- `POST /forensics/search` → cosine-ranked matches `{id, distance}`
- `GET/POST /sites/:site_id/incidents`, `GET /sites/:site_id/heatmap`

Roles: SuperAdmin, SiteCommander, GateOperator, VerificationOfficer,
ForensicAnalyst. Permissions checked per request; SuperAdmin bypasses.

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

## Tests

```sh
docker compose up -d db
cd backend && cargo test        # 10 integration tests (live DB)
cargo clippy --all-targets -- -D warnings
```

## Layout

- `backend/src/{api,core,domain,infrastructure}` + `backend/migrations`
- `backend/tests/slice.rs` — RBAC denial, KYC roundtrip, reuse burn,
  rate limit, input validation
- `frontend/src` — `App.tsx` routes, `Login.tsx`, `Dashboard.tsx`,
  `PressApply.tsx`, `ReviewDesk.tsx`, `session.ts` (zustand),
  `api.ts` (tanstack-query)
- `docs/SCOPE.md` — slice scope and manual verification steps

## Out of scope (recorded)

- QR image rendering (payload returned; use any QR generator)
- Shared rate-limit quota across replicas (per-instance counters)
- Access-token allowlist (15-min TTL is the mitigation)
- Kubernetes manifests, TLS termination, CI pipelines
