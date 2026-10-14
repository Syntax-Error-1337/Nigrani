# Assignee Directory — Scope Note (t121, sprint s41)

## Gap
Analysts hold `incidents:write` (file, transition, assign) but NOT
`users:read`, so `GET /users` 403s for them. The bench assign box demands
a pasted user UUID — which analysts cannot discover without a SuperAdmin
reading IDs aloud. Assignment is operator-dead for its primary users.
Granting analysts full `users:read` over-exposes (usernames + roles +
liveness of EVERY account incl. superadmins — enumeration for later
password-guessing, precisely what lockout defends).

## Design
- `GET /users/assignable` — requires `incidents:write` (caller must be
  able to assign at all). Returns `[{id, username, role}]` for ACTIVE
  users holding `incidents:write`, ordered by username. Minimal fields:
  no liveness counters, no lock state, no emails (none exist anyway).
  Inactive users excluded (assign refuses them — listing them would be
  a trap).
- Bench: per-case assignee input becomes a `<select>` populated from the
  directory (lazy-load on first expand... simpler: load with incidents,
  tiny roster) + keeps free-text fallback? NO fallback — select-only
  kills the paste-UUID flow entirely (fewer paths, no garbage UUIDs).
  Show `username (role)`.
- RBAC matrix untouched (no seed change — permission derived from the
  existing `incidents:write` grant via require_permission).
- Audit: none (read path).

## Out
Full users:read for analysts; team/role-group assignment; assignment
suggestions by workload.

## Acceptance
- Analyst GETs directory 200 with only eligible actives; gate 403s;
  deactivated analyst vanishes from list; bench assigns via select.
- Suite green; clippy/tsc clean; live curl + UI proof.
