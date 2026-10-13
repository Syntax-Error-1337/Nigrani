# Data Retention — Scope Note (t37, sprint s13)

## Why
Every entity accumulates forever: KYC PII (encrypted but eternal),
embeddings, entry logs, audit rows, refresh tokens. A protest-management
system holding biometric-adjacent data with no expiry story is the
biggest remaining real gap.

## Design
- Policy table `retention_policies` (entity TEXT PK, retain_days INT):
  seeded defaults — `kyc_applications: 365`, `face_embeddings: 180`,
  `entry_logs: 365`, `refresh_tokens: 30`, `audit_log: NEVER (0 = keep)`.
- `POST /admin/retention/run` (SuperAdmin): purges expired rows per
  policy in dependency order (embeddings → entry_logs → kyc →
  refresh_tokens), returns per-entity counts. Audit log itself is
  append-only and records the purge run.
- `GET/PUT /admin/retention/policies` (SuperAdmin): view/tune windows.
- `GET /sites/:site_id/export` (needs `sites:read`): JSON export of the
  site's gates + recent logs + incidents (data-portability counterpart).
- FK discipline: embeddings/entry_logs reference KYC rows — purge
  order + `ON DELETE SET NULL` keeps referential integrity; audit rows
  reference purged entities by UUID only (no FK → no breakage).

## Out
Automatic scheduled purges (cron wiring is deployment-specific; the
endpoint is the primitive), per-subject erasure requests UI, S3 object
lifecycle rules (documented in README backups section).

## Acceptance
- Seed an old row (backdated), run purge → row gone, counts reported,
  audit row records the run.
- Policy PUT honored (e.g. embeddings → 1 day purges them).
- Export returns the site's data as JSON; 403 for gate role on admin
  endpoints; suite green; clippy clean.
