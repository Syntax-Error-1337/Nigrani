# Incident Lifecycle — Scope Note (t52, sprint s18)

## Gap
Incidents are write-once blobs: no status, no assignment, no evidence
links beyond one suspect id. A forensic bench that can't track "who is
working this, is it closed" is a notepad, not a case system.

## Design
- Migration `0009_incidents`: `status TEXT (open|investigating|resolved|
  closed) DEFAULT open`, `assigned_to UUID→users NULL`,
  `resolved_at TIMESTAMPTZ NULL`; new `incident_links` table
  (incident_id, kind entry|embedding|snapshot, ref_id UUID, note,
  added_by, added_at) for evidence attachments.
- `POST /sites/:id/incidents/:iid/status` (needs `incidents:write`):
  `{status, note?}` — legal transitions open→investigating→resolved→
  closed (+ reopen closed→investigating); sets resolved_at on resolve;
  illegal → `409`. Each transition audit-logged.
- `POST /sites/:id/incidents/:iid/assign` `{user_id}` — must hold
  `incidents:write` themselves (no dumping cases on gate staff).
- `POST /sites/:id/incidents/:iid/links` `{kind, ref_id, note?}` +
  `GET .../links` — evidence attachments (entry logs, embeddings,
  snapshot keys as TEXT ref for snapshots).
- ForensicBench: status pill + transition buttons, assignee select
  (users list), evidence section (add entry-log link by pasting log id,
  snapshot key, or embedding id), all behind existing role gates.

## Out
SLA timers/escalation, duplicate-case merging, courtroom export packs.

## Acceptance
- Full transition chain + illegal jump 409; assign to analyst OK, to
  gate role 400; link round-trips; audit rows per transition.
- Suite green; clippy clean; UI flow screenshotted.
