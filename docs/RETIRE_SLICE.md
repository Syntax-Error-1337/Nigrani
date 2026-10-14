# Topology Retirement — Scope Note (t67, sprint s23)

## Gap
Sites and gates are create-only: no archive, no delete, no restore. A
typo'd gate ("Gtae 1") collects crossings forever; a one-off protest site
pollutes every list and heatmap scope forever. Hard DELETE is unsafe
(gates CASCADE entry_logs — history would vaporize; sites SET NULL
incidents — cases would orphan). Operators need retirement that preserves
history.

## Design
- Flags: `sites.archived_at TIMESTAMPTZ NULL`, `gates.archived_at
  TIMESTAMPTZ NULL` (migration `0013`). Timestamp (not bool) records WHEN
  for audit narrative; NULL = live.
- `POST /sites/:id/archive` + `/restore` (needs `sites:write`);
  `POST /sites/:sid/gates/:gid/archive` + `/restore` (needs
  `gates:write`). Archive sets `archived_at = now()`; restore clears it.
  Both audit-logged (`site.archived/restored`, `gate.archived/restored`)
  and publish `Topology` (dashboards re-list).
- Guard rails:
  - Archiving a SITE with live gates → 409 ("archive N gate(s) first").
    Explicit over cascading surprise; restore has no such guard.
  - `record_event` on an archived gate → 410 Gone ("gate archived").
    Crossings must fail loudly, not vanish. 410 (not 404): the gate
    EXISTS but is retired — clients distinguish misroute from retirement.
  - `create_gate` under an archived site → 410. `create_incident` on an
    archived site → 410 (same EXISTS-check site, extended).
  - lists: `list_sites` / `list_gates` hide archived by default; `?include=
    archived` shows all (archived rows carry the timestamp). Export keeps
    serving archived sites (history must stay portable).
- Domain `Site`/`Gate` gain `archived_at: Option<DateTime<Utc>>`
  (serde default → old cached JSON still parses).

## Out
Hard-delete with history reassignment; merge-sites; auto-archive by
retention policy.

## Acceptance
- Archive gate → record_event 410; archive site with live gate → 409;
  archive gate then site → 200; lists hide both; ?include=archived shows;
  restore revives; audit rows per transition.
- Suite green; clippy clean; live curl proof.
