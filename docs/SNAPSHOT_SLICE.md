# Snapshot Lifecycle — Scope Note (t73, sprint s25)

## Gap
Snapshots are write-only strays: `POST /snapshots` mints a UUID key and
stores bytes, but nothing tracks references. Upload-then-abandon (kiosk
staged photo never attached to an event) and purge-deleted entry_logs
both leave S3 objects with no DB row pointing at them — unbounded orphan
growth in the bucket, invisible to every current endpoint. Uploads aren't
audit-logged either (who stored 5MB, when?).

## Design
- Reference query: keys referenced by `entry_logs.snapshot_key`
  (non-empty). Orphan = bucket key NOT in that set. S3 `ListObjectsV2`
  (paginated, 1000/page) vs one `SELECT DISTINCT snapshot_key` — set
  difference in Rust.
- `POST /admin/snapshots/collect` (SuperAdmin-only, reuse the retention
  `superadmin` guard shape): `{ "dry_run": true }` (default) reports
  `{ "orphans": [keys...capped 500], "orphan_count", "referenced_count" }`
  WITHOUT deleting; `{ "dry_run": false }` deletes orphans (batched
  DeleteObjects, 1000/batch) and reports `{ "deleted": n }`. Audit
  `snapshots.collected` with counts (never key lists — keys are
  content-addressed secrets in the audit trail sense; counts suffice).
- `upload_snapshot` audit-logs `snapshot.uploaded` (actor, key, byte size
  in detail — size is operational, fine for the trail).
- Storage: add `list_keys` (paginated prefix scan) + `delete_keys`
  (batch) to SnapshotStore. No new deps (aws_sdk_s3 already imported).
- Tests: store-gated — TestServer carries `snapshots: None`, so the
  collect endpoint returns 503-style 500 without storage (mirrors the
  existing `snapshot_without_storage_is_unavailable` test: assert the
  unavailable shape, NOT collection). Real collection proven LIVE against
  LocalStack (protest-s3-1): upload 2 orphans + 1 attached, dry-run lists
  2, collect deletes 2, attached survives.

## Out
TTL auto-expiry on upload (needs lifecycle policy support per backend);
quota per operator; reference-counted delete on entry_log purge
(checked per-row S3 deletes inside purge — slow; batch collect is better).

## Acceptance
- Unit-shape test without storage (503 path) + live LocalStack proof:
  dry-run count, delete count, attached survival, audit row present.
- Suite green; clippy clean.
