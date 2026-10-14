# Login Lockout — Scope Note (t64, sprint s22)

## Gap
Login has per-IP rate limits but no per-account guard: a guessing attack
spread across IPs (or under quota) tries one account forever. `login.failed`
audit rows record every attempt but nothing reads them — detection without
response.

## Design
- State on `users`: `failed_logins INT DEFAULT 0`, `locked_until TIMESTAMPTZ
  NULL`. No new table — the counter lives with the credential it protects;
  reset_demo TRUNCATEs users wholesale (no reseed list to update).
- Login flow (after resolving the user row, before password verify):
  if `locked_until > now()` → audit `login.locked`, return 401
  indistinguishable from bad credentials (no oracle — same
  "invalid credentials" body; the lock is visible to the OWNER via a
  separate signal, see below).
- On verify failure: `failed_logins + 1`; when it reaches 5 →
  `locked_until = now() + 15 minutes`, audit `login.locked`. Window: none
  (straight counter; success resets to 0 — a slow-drip attacker who never
  hits 5 consecutive failures without a success is by definition guessing
  at <20% hit rate… actually success means they GOT IN. Consecutive-count
  is the right shape: any success resets).
- On success: reset `failed_logins = 0` (leave `locked_until` stale-past;
  harmless, and avoids a second write path).
- Unlock: SuperAdmin-only `POST /users/:id/unlock` (needs `users:write`,
  same guard as set_active; cannot unlock self — mirrors the
  cannot-change-own-status rule). Clears counter + lock, audit
  `user.unlocked`. OperatorsPanel gets an UNLOCK button next to
  DEACTIVATE/REACTIVATE for locked accounts (list view carries the new
  fields).
- Owner-visible signal: `GET /auth/me` includes `locked_until` (own row
  only — authenticated self, no oracle for others). Login response body
  stays identical locked-or-not.

## Out
Progressive backoff, IP+account composite throttle, CAPTCHA, notify-owner
channel (no messaging infra exists).

## Acceptance
- 5th bad password → locked (6th attempt 401 even with RIGHT password);
  unlock → login works; success resets counter (4 bad + 1 good + 5 bad =
  lock, proving the reset).
- Non-SuperAdmin unlock → 403; self-unlock → 400.
- Suite green; clippy clean; live curl proof incl. `me.locked_until`.
