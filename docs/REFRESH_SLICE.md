# Silent Session Refresh — Scope Note (t118, sprint s40)

## Gap
Access JWTs die at 15 minutes and the client NEVER rotates: `apiFetch`
treats any 401 as "log out now". Every operator gets kicked to the login
screen mid-shift, mid-kiosk-rush, losing form state (payload textarea,
staged snapshot, half-written incident). The server built full rotation
semantics (refresh endpoint, reuse-burn, lockout gating in s37) that the
UI leaves on the floor.

## Design
- `session.ts`: add `refreshNow()` — POSTs the stored refresh token to
  `/auth/refresh`, persists the new pair (same STORAGE_KEY shape), returns
  bool. Single-flight guard (module-level promise) so 10 concurrent 401s
  trigger ONE rotation (reuse-burn makes parallel rotations FATAL — the
  second rotation would present an already-revoked token and nuke the
  family; this is the critical correctness point).
- `apiFetch`: on 401 (and a refresh token exists, and not already a
  `/auth/refresh` call itself), attempt ONE rotation then retry the
  original request once with the new access token. Only logout when
  rotation fails (revoked/locked/expired family — the true logged-out
  states). Recursion guard via an explicit `retried` flag, not URL
  sniffing... actually URL sniffing for `/auth/refresh` IS the clean
  guard (the refresh call itself must never self-retry).
- Proactive: `LiveUpdates` (already mounted app-wide in App.tsx) starts a
  5-minute interval calling refreshNow when a session exists (rotates
  ahead of the 15-min cliff; each rotation resets the window, so steady
  use never sees a 401 at all). Interval cleared on logout (effect dep on
  accessToken null-ness... simpler: check getState() inside the tick,
  skip when logged out).
- No backend change. No new deps.

## Out
JWT expiry countdown UI; "session expiring" toasts; multi-tab rotation
coordination (storage events — two tabs racing rotations burn each
other; accepted: single-kiosk-profile assumption, documented).

## Acceptance
- Expired-access request succeeds after one silent rotation (prove by
  backdating... can't backdate JWTs — prove via: login, revoke ONLY the
  access side? Can't selectively expire. Proof: call /auth/refresh flow
  indirectly — use a short-lived... Alternative honest proof: login,
  manually corrupt accessToken in localStorage (retains refresh), next
  apiFetch 401s → rotates → retries → 200, no login screen. Plus: logout
  path still works when refresh is also dead (revoke family → next call
  logs out).
- tsc + oxlint clean; live UI proof.
