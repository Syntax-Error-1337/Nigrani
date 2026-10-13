# Audit Trail — Scope Note (t34, sprint s12)

## Why
Law-enforcement system with zero reconstruction story: today nobody can
answer "who approved this press card" or "who logged this entry" except
via scattered `decided_by`/`recorded_by` columns. A single append-only
trail fixes that.

## Design
- Migration `0006_audit.sql`: `audit_log` table
  (seq BIGSERIAL PK, at TIMESTAMPTZ, actor UUID NULL, action TEXT,
  entity TEXT, entity_id UUID NULL, detail JSONB, prev_hash TEXT,
  hash TEXT). Hash chain: `sha256(prev_hash || seq || at || actor ||
  action || entity || entity_id || detail)` — tamper-evident, cheap to
  verify offline.
- Writer helper `audit(pool, actor, action, entity, entity_id, detail)`:
  best-effort (logs warning on failure, never fails the mutation).
- Captured: logins (success/fail), KYC submit/decide, gate events,
  incident create, site/gate create. NOT captured: reads, searches
  (volume), refreshes.
- `GET /sites/:site_id/audit?limit=&offset=` — needs `users:read`
  (SuperAdmin + commander/analyst-equivalent roles holding it); global
  `GET /audit` for SuperAdmin only.
- `GET /audit/verify` — recomputes the chain, returns `{ok, checked,
  first_bad}` (SuperAdmin only).

## Out
Long-term retention/archival jobs, signed (asymmetric) checkpoints,
per-field diff capture (detail JSON carries before/after where cheap).

## Acceptance
- Decide a KYC app → row appears with actor + decision; gate event → row.
- Tamper one row's detail via SQL → `/audit/verify` names its seq.
- Viewer 403s for gate role; suite green; clippy clean.
