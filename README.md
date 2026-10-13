# Nigrani

Protest-site access management: RBAC API (Rust/axum) + operations console
(Vite/React). Phase 1 core slice.

## Quick start

Requires Docker (Postgres), Rust toolchain, Node 18+.

```sh
docker compose up -d db
cd backend && cp .env.example .env && cargo run     # :8080
cd frontend && npm install && npm run dev           # :5173
```

Seeded logins (password `password`): `superadmin`, `commander`,
`gate`, `verifier`, `analyst`.

## API

- `GET /health` → `ok`
- `POST /auth/login` `{username, password}` → access JWT + rotating refresh
- `POST /auth/refresh` `{refresh_token}` → fresh pair, old token revoked
- `GET /auth/me`, `GET /users` (needs `users:read`)
- `GET/POST /sites`, `GET/POST /sites/:site_id/gates`

Roles: SuperAdmin, SiteCommander, GateOperator, VerificationOfficer,
ForensicAnalyst. Permissions checked per request; SuperAdmin bypasses.

## Layout

- `backend/src/{api,core,domain,infrastructure}` + `backend/migrations`
- `frontend/src` — `App.tsx` routes, `Login.tsx`, `Dashboard.tsx`,
  `session.ts` (zustand), `api.ts` (tanstack-query)
- `docs/SCOPE.md` — slice scope and manual verification steps
