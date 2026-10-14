# Snapshot Collect Console — Scope Note (t76, sprint s26)

## Gap
`POST /admin/snapshots/collect` (s25) is curl-only: no operator surface
shows orphan counts, previews strays, or triggers collection. The
RetentionPanel is the natural home (same SuperAdmin audience, same
"dangerous lifecycle ops" family as purge) but knows nothing about it.

## Design
- New `SnapshotCollect` block inside RetentionPanel (same section, below
  the policies table — one import, no new route/panel):
  - `CHECK ORPHANS` button → dry-run; renders
    `N orphaned snapshots · M referenced` + first-8 key prefixes as a
    preview list (prefixes only: full UUID keys in DOM are copy-paste
    bait; the API already caps at 500 — show 8, count the rest).
  - `COLLECT ORPHANS` button → real delete; renders `Deleted N`.
  - Both reuse the panel's `notice`/`report` lines (no new state chrome).
  - Unavailable storage surfaces the API's 500 as
    `Snapshot storage unavailable` (same wording family as the existing
    kiosk/snapshot fallbacks).
- No backend change. No new files.

## Out
Per-key delete buttons; age histogram of orphans; scheduled collection.

## Acceptance
- tsc + oxlint clean.
- Live UI proof as superadmin: upload a stray via kiosk path (or direct
  POST), CHECK shows ≥1, COLLECT clears to 0, counts render in DOM.
