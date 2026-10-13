# Ops Readiness — Scope Note (t22, sprint s8)

## Items (ranked)
1. **Logout with server-side revocation** — `POST /auth/logout`
   `{refresh_token}` revokes that token; `POST /auth/logout/all` revokes
   the caller's whole family. Access JWTs stay valid until their 15-min
   expiry (documented; short TTL is the mitigation, no allowlist).
2. **Request-id tracing** — `x-request-id` echo via `tower-http`
   `RequestId` layer + include the id in error responses (`AppError`)
   so client reports map to server logs.
3. **Seed guard** — `seed_users` refuses to run when `APP_ENV=production`
   unless `SEED_BOOTSTRAP=true`; logs loudly in dev. Prevents the
   `password`-for-everyone footgun on a prod database.

## Out (recorded)
- Access-token allowlist (cost per request outweighs 15-min window).
- Structured JSON log format (env-filter text is fine at this scale).
- Password rotation policy UI.

## Acceptance
- Login → logout → refresh with same token → `401`; logout/all kills
  sibling sessions (test).
- Every error body carries `request_id`; response header echoes it.
- `APP_ENV=production cargo run` without flag → boot refuses seed step
  with a clear error; dev boot unchanged.
- Full suite green; clippy/tsc/oxlint clean.
