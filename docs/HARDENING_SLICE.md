# Production Hardening — Scope Note (t19, sprint s7)

## Threats ranked (this slice fixes 1–3; 4+ recorded, out of scope)
1. **Login brute force** — `/auth/login` + `/auth/refresh` unlimited.
   Fix: reuse the `Limiter` (per-IP, strict: 20/min login, 30/min refresh).
2. **Unbounded list reads** — sites/gates/kyc/incidents/logs take `limit`
   but no `offset`; a large table is one `?limit=200` × paging client away
   from full scans. Fix: `offset` param (capped) on all list endpoints.
3. **Snapshot egress via API** — downloads proxy bytes through axum.
   Fix: `GET /snapshots/:key/share` → presigned S3 URL (15 min); keep
   direct download as fallback.
4. Recorded, NOT this slice: JWT allowlist/revocation on logout, shared
   rate-limit quota across replicas, request-id tracing, argon2 tuning.

## Acceptance
- 21 rapid logins from one IP → `429`; refresh flood → `429`.
- `?limit=5&offset=10` honored on sites/gates/kyc/incidents/logs;
  `offset` > 10_000 → `400`.
- `/snapshots/:key/share` returns `{url}` usable with plain curl (no auth
  header); kiosk uses it for snapshot links.
- Full suite green; clippy/tsc/oxlint clean.
