# Operator Provisioning — Scope Note (t49, sprint s17)

## Gap
Operators are provisioned by hand in SQL: no create/deactivate endpoints,
no password change. A SuperAdmin cannot onboard a gate officer from the
console, and a compromised account cannot be locked without DB access.

## Design
- Migration `0008_users`: `users.active BOOL NOT NULL DEFAULT TRUE`;
  login + refresh reject inactive accounts (`401`, indistinguishable
  from bad credentials); grant cache keyed by role is unaffected
  (per-user liveness checked at login/refresh, not per request — a
  deactivated session's access JWT lives ≤15 min, documented).
- `POST /users` (needs `users:write` — NEW permission, SuperAdmin-only
  via grants): `{username, password≥12, role}` → created user.
  Usernames: 3–32 chars, `[a-z0-9_]`.
- `POST /users/:id/deactivate` / `/users/:id/reactivate` (same perm):
  flips flag + revokes live refresh tokens (immediate session kill).
- `POST /auth/password` (self, authed): `{current, new≥12}` → rehash,
  revoke all other sessions (keep current).
- `users:write` grant: SuperAdmin only (role_permissions insert in the
  migration for the new permission).
- Frontend: SuperAdmin "Operators" panel — list, create form, deactivate
  toggle; account menu "Change password" dialog for every role.

## Out
Password-reset-via-email (no mailer), MFA/TOTP (recorded), last-login
tracking.

## Acceptance
- Provision → login works; deactivate → login 401 + refresh dead;
  reactivate → login works; weak password → 400.
- Password change with wrong current → 401; correct → new works, old
  refresh dead.
- Non-SuperAdmin create → 403; suite green; clippy clean.
