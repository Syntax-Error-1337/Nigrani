# Demo Reset + Search — Scope Note (t43, sprint s15)

## Why
Dev DB holds 89 sites / 520 KYC rows / 96 logs, nearly all automated-test
and manual-verification residue. Every dashboard list is unusable noise,
and reviewers can't find real entries. Two fixes, one slice.

## Design
- `POST /admin/demo/reset` (SuperAdmin, blocked when
  `APP_ENV=production`): truncates operational tables in FK order
  (audit_log → face_embeddings → entry_logs → incidents → gates →
  kyc_applications → sites → refresh_tokens), re-seeds roles/permissions
  grans, users, Jantar Mantar + Gate 1–4, default retention policies.
  Returns per-table counts. Audit trail restarts (records the reset as
  its own genesis row AFTER truncate).
- Search (server-side ILIKE, all roles holding the read perm):
  - `GET /sites?q=` name/location match.
  - `GET /kyc/applications?q=` full_name/organization/document match
    (matches on CIPHERTEXT for encrypted rows — documented limitation;
    name/org are plaintext and cover the reviewer workflow).
  - `GET /sites/:id/gates?q=` name match.
- Frontend: search inputs on sites list, gates list, review queue
  (debounced 250ms, existing tanstack-query keys gain the `q` param).

## Out
Full-text (pg_trgm) indexes — ILIKE with existing B-tree + limit is fine
at this scale; encrypted-field search (needs blind-index scheme,
recorded).

## Acceptance
- Reset on dev → 1 site + 4 gates + 5 users + policies; audit genesis row.
- Reset with APP_ENV=production → refused (423 or 403 + clear error).
- `?q=jantar` narrows sites; `?q=` queue narrows applicants; suite green.
