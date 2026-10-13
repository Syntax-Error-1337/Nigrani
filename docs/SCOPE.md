# Nigrani — Scope Note (t1, sprint s1 Foundations)

## First usable slice
Phase 1 core: authenticated RBAC API + role-based dashboard shell.

Backend (`backend/`, Rust axum + tokio + sqlx):
- `GET /health` (no auth), `POST /auth/login` (seeded users, JWT access +
  rotating refresh), `GET /auth/me`.
- RBAC middleware enforcing the five roles: `SuperAdmin`, `SiteCommander`,
  `GateOperator`, `VerificationOfficer`, `ForensicAnalyst`.
- CRUD for protest sites and entry/exit gates (SuperAdmin/SiteCommander
  write, all authenticated roles read).
- Postgres migrations via sqlx (`users`, `roles`, `permissions`, `sites`,
  `gates`). Local dev DB runs in Docker (`docker compose`); no `psql`
  client on this host, so verification uses `cargo sqlx` / API calls.

Frontend (`frontend/`, Vite + React + TS + Tailwind):
- Login view issuing JWT, role-aware route guards, one dashboard view per
  role (shell cards backed by live `/sites`, `/gates`, `/auth/me`).
- State via zustand, data via tanstack-query.

## Out of scope for this slice
Phase 2 press KYC + QR press cards, Phase 3 hardware/RTSP ingestion,
Phase 4 pgvector forensic search. No pgvector/PostGIS in the first
migrations; schema must leave room (extension + embedding columns land
with Phase 4).

## Manual verification
1. `docker compose up -d db && cd backend && cargo run` → `curl
   localhost:8080/health` → `{"status":"ok"}`.
2. Login as each seeded role, call a forbidden endpoint → `403`; allowed
   endpoint → `200`.
3. `cd frontend && npm run dev` → log in per role → correct dashboard
   renders, gates list loads from the API.

## Toolchain on this host (2026-10-13)
rustc/cargo 1.99, node v26.8.2, npm 12.2.0, Docker 29.8.0, git 2.54.0.
No `psql` client — use Dockerized Postgres.
