# Incident Triage Filters — Scope Note (t91, sprint s31)

## Gap
`GET .../incidents` loads every case at the site with limit/offset only —
no status filter, no assignee filter. At 100+ cases the bench drowns:
an analyst working THEIR queue scrolls past everyone else's closed cases.
ReviewDesk solved this exact problem with status tabs; the bench never got
them. The live-refresh subscription (s21) also reloads unfiltered, so the
noise refreshes itself.

## Design
- Backend: `IncidentFilter` gains `status: Option<String>` (validated
  against the four workflow states → 400 on garbage, mirroring
  `list_kyc`'s status validation) and `assignee: Option<Uuid>`
  (`?assignee=me` resolves to the caller — the triage default; explicit
  UUIDs allowed for commanders peeking at someone's queue).
- SQL: `AND ($3 OR status = $4)`-style optional predicates (NULL-safe,
  index-friendly enough at this scale; existing site+created index leads).
- Bench: status tab row (All/Open/Investigating/Resolved/Closed) + MINE
  toggle, mirroring ReviewDesk tab styling. `loadIncidents` threads the
  active filters; the s21 live-refresh path reuses the same loader (no
  fork — filtered views stay filtered on events).
- Audit: none (reads, like all other list endpoints).

## Out
Full-text search over titles/descriptions; SLA-sort (oldest-open-first);
cross-site "all my cases" view.

## Acceptance
- `?status=resolved` returns only resolved; `?status=bogus` → 400;
  `?assignee=me` returns only caller's; combined filters AND.
- Bench tabs filter without reload; live event keeps the active filter.
- Suite green; clippy/tsc clean; live curl + UI proof.
