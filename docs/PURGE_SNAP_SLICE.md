# Purge–Snapshot Coupling — Scope Note (t85, sprint s29)

## Gap
`run_purge` deletes expired `entry_logs` rows but leaves their S3 snapshot
objects behind: every purge run MANUFACTURES orphans that only the manual
`snapshots/collect` endpoint later cleans. The lifecycle is split-brain —
DB retention and object retention run on independent clocks with an
operator in the middle. s25 built the collector; this slice wires it in.

## Design
- Capture-then-delete: BEFORE purging `entry_logs`, SELECT DISTINCT
  `snapshot_key` of rows about to expire (same window predicate). AFTER
  the row purge, diff against still-referenced keys; the difference is
  purge-dereferenced (deleted by THIS run specifically — never touches
  pre-existing orphans; those stay the collector's job, attribution clean).
- Deletion policy: purge deletes dereferenced keys from S3 when storage is
  configured; when `snapshots: None`, keys are REPORTED not deleted
  (report carries `snapshots_dereferenced` + `snapshots_deleted`).
  No new query param — purge is already SuperAdmin-confirmed and
  audit-logged; coupling is the documented behavior, `PurgeReport` gains
  two fields.
- Audit: `retention.purge` detail gains the two snapshot counts
  (existing test asserts `purged.face_embeddings == 1` — additive only).
- Failure posture: S3 delete failure does NOT fail the purge (DB purge
  already committed; objects become regular orphans for the next collect).
  Logged loudly via tracing::error, counted as `snapshots_delete_failed`.

## Out
Cross-run orphan attribution in the report; per-key S3 delete inside
entry_log purge transactions (slow — batch post-commit is better, kept).

## Acceptance
- Purge with an expired snapshot-bearing log → key gone from bucket
  (live S3) or reported (no storage); pre-existing orphans untouched by
  purge (collector-only); counts in report + audit detail.
- Suite green (incl. existing purge assertions); clippy clean; live proof.
