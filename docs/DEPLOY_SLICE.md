# Deployment Packaging — Scope Note (t25, sprint s9)

## Gaps (ground truth)
1. `.env.example` lacks S3/AWS vars; storage defaults still point at
   MinIO `:9000` while compose runs LocalStack on `:4566`.
2. Compose services use baked-in env; no `env_file` wiring.
3. No backup/restore notes for Postgres + S3 snapshots.

## Items
1. **Env template**: full `.env.example` (DATABASE_URL, JWT_SECRET,
   BIND_ADDR, APP_ENV, S3_ENDPOINT/BUCKET, AWS_REGION/ACCESS_KEY_ID/
   SECRET_ACCESS_KEY); storage defaults updated to LocalStack `:4566`
   with matching dev creds.
2. **Compose profiles**: `db` + `s3` env via `env_file` (optional,
   defaults intact); add an `api` service (builds backend, needs the DB
   + S3 + secrets) so `docker compose up` boots the whole stack.
3. **Backup notes**: README section — `pg_dump` + S3 bucket export
   commands against the compose services.

## Out
Kubernetes manifests, TLS termination, CI pipelines (recorded).

## Acceptance
- `cp backend/.env.example backend/.env && cargo run` boots with S3 live
  (no manual env exports).
- `docker compose up --build -d` brings up db + s3 + api; health 200.
- Suite green; clippy clean.
