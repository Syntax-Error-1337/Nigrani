# Purge Dry-Run Preview — Scope Note (t133, sprint s45)

## Gap
`POST /admin/retention/run` deletes across 6 tables + S3 in one shot with
zero preview. Operators either trust the windows blind or never press the
button (observed: residue accumulates because the button feels lethal).
s25 gave snapshot collection a dry-run; the bigger gun has none. The
panel's "Run purge" sits next to "Load policies" with no intermediate
step.

## Design
- `POST /admin/retention/preview` (SuperAdmin, same guard): per-entity
  COUNT(*) with the identical window predicates as `purge_older_than`
  (same table/column/window mapping — factor a shared
  `PURGABLE: &[(&str, &str)]` constant so predicates can't drift) plus
  `snapshots_dereferenced` computed the s29 way (doomed-minus-referenced,
  no deletes). Response mirrors PurgeReport shape with a `dry_run: true`
  marker: `{purged: {entity: count}, snapshots_dereferenced, dry_run}`.
- No audit row for previews (reads; keeps the trail for real mutations —
  consistent with all other GET/dry-run paths). No S3 calls (counts only).
- Panel: PREVIEW button next to RUN PURGE rendering `Would purge —
  k: v, ...` in the report line; run stays as-is (two-step is opt-in,
  not forced — purge stays one click for scripted ops).

## Out
Scheduled purges; per-row preview lists; mandatory confirm gate.

## Acceptance
- Preview counts equal a subsequent real purge's counts (prove live:
  preview → run → same numbers, then zeros on re-preview).
- Suite green; clippy/tsc clean; live curl + UI proof.
