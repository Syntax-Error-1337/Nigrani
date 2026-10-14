# Archived Visibility — Scope Note (t88, sprint s30)

## Gap
s23 shipped Archive/Restore buttons but the dashboard can never SHOW
archived rows: `useSites`/`useGates` never pass `?include=archived`, so
archiving is a one-way door in the UI (restore exists only via curl).
Worse, the failure mode is silent confusion: an operator archives the
wrong gate, it vanishes, and nothing in the console explains where it
went or how to undo.

## Design
- Hooks gain an `archived: boolean` flag threaded into the query string
  (`?include=archived` when true) AND the queryKey (cache isolation —
  live and archived lists must not share entries).
- Dashboard: one `SHOW ARCHIVED` toggle per section (sites + gates),
  `canWrite`-gated like the Archive buttons (readers never need the
  graveyard). Archived rows render dimmed with an `ARCHIVED` pill and
  the existing Restore button (no new affordance — the flip buttons
  already branch on `archived_at`).
- Selecting an archived site still works (detail + restore flow); gates
  of an archived site list normally under the toggle.
- No backend change (API already serves both shapes).

## Out
Archive timestamps in row text ("archived Oct 14"); bulk restore;
separate graveyard route.

## Acceptance
- tsc + oxlint clean.
- Live UI proof as superadmin: archive a gate → vanishes from default
  list → toggle shows it dimmed with ARCHIVED + Restore → restore →
  toggle off shows it live again. Same for a site (gates archived first).
