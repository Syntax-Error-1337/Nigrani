# Lockout Session Enforcement — Scope Note (t109, sprint s37)

## Gap
s22 lockout is login-theater while sessions live: (a) `POST /auth/refresh`
checks `active` but NOT `locked_until` — a locked user with a live refresh
token rotates fresh access JWTs for the full 15-minute lock (and beyond,
since each rotation extends the family); (b) the lock transition itself
revokes nothing, unlike `deactivate` which kills sibling sessions
immediately. An attacker mid-session when the 5th strike lands keeps full
API access. The audit even logs `login.locked` while the same identity
keeps calling.

## Design
- Refresh gate: after loading the user row, refuse with 401 when
  `locked_until` is in the future (same indistinguishable body as the
  inactive branch — "refresh token expired"). No new variant.
- Kill at lock: in the login-failure branch where strikes hit
  LOCKOUT_STRIKES, revoke all live refresh tokens for the user in the
  same UPDATE batch as setting the lock (mirrors set_active's kill).
  Outstanding access JWTs still run to their ≤15-min expiry (documented
  limit — allowlist is out of scope, README already says so).
- Unlock path unchanged (operator clears; user re-logins; family
  rebuilds from zero — no stale revocations linger since rotation
  re-issues).
- No migration. No frontend change (401 on refresh already forces the
  session hook back to login — verify the session.ts behavior in t111).

## Out
Access-token allowlist / immediate JWT invalidation; lockout push
notification to active sessions (WS `auth.revoked` event — future).

## Acceptance
- Lock a user WITH a live refresh token: refresh → 401; family rows all
  revoked; unlock → fresh login works, old refresh stays dead.
- Suite green; clippy clean; live curl proof.
