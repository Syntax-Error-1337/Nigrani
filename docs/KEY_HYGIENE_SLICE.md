# Snapshot-Key Hygiene — Scope Note (t94, sprint s32)

## Gap
`record_event` stores `snapshot_key` VERBATIM: no format check (slashes,
`..`, 10KB garbage all accepted into the column) and no existence check
against S3. Consequences: (a) a typo'd key creates a crossing whose bench
photo 404s — silent evidence rot at ingest; (b) format inconsistency —
`share/download` and incident-link validation reject `/` and `..`, but
ingest accepts them, so such rows are write-only poison (can never be
viewed); (c) edge-agent bugs (wrong bucket/key scheme) go undetected for
weeks until a forensic review hits the hole.

## Design
- Format gate (always, storage or not): non-empty keys must be
  `Uuid.jpg` shape — `<uuid>.jpg`, no `/`, no `..` — mirroring what
  `upload_snapshot` mints (`format!("{}.jpg", Uuid::new_v4())`). Empty
  stays allowed (crossings without photos are normal). Violations → 400.
  Single shared helper `valid_snapshot_key` in routes_gate; incident-link
  `snapshot` validation keeps its own (looser — links may cite legacy
  keys; NOT tightened here).
- Existence gate (only when `state.snapshots` configured): HEAD-equivalent
  via `store.get` metadata... cheaper: add `SnapshotStore::exists` using
  `head_object` (no body transfer). Unknown key → 404 `snapshot not
  found`. When storage is None (tests/dev without S3): skip existence
  (format still enforced) — ingest must not hard-require S3.
- Cost: one HEAD per photo-bearing crossing — acceptable (crossings are
  human-rate, not machine-rate; bulk ingest doesn't exist).
- Audit: none new (rejected writes aren't audited, consistent).

## Out
Backfill scrub of existing bad keys; key-scheme versioning; S3→DB
reconciliation report (partially covered by s25 collect).

## Acceptance
- `snapshot_key: "../../x"` → 400; `snapshot_key: <random-uuid>.jpg`
  (not in bucket) → 404 with storage, 200 without; valid uploaded key →
  200; empty → 200.
- Suite green (incl. no-storage test server paths); clippy clean; live
  curl proof against LocalStack.
