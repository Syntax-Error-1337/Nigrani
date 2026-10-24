#!/bin/sh
# Nigrani backup (s-I7): Postgres dump + S3 snapshot sync.
# Run from cron/k8s CronJob; keeps 7 daily dumps in ./backups.
set -eu
DB_CONTAINER="${DB_CONTAINER:-protest-db-1}"
DB_USER="${DB_USER:-nigrani}"
DB_NAME="${DB_NAME:-nigrani}"
S3_ENDPOINT="${S3_ENDPOINT:-http://127.0.0.1:4566}"
BUCKET="${BUCKET:-nigrani-snapshots}"

mkdir -p backups
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="backups/nigrani-${STAMP}.sql"

echo "== pg_dump ${DB_NAME} -> ${OUT}"
docker exec "${DB_CONTAINER}" pg_dump -U "${DB_USER}" --no-owner --no-privileges "${DB_NAME}" > "${OUT}"

echo "== s3 sync ${BUCKET} -> backups/snapshots"
aws --endpoint-url "${S3_ENDPOINT}" s3 sync "s3://${BUCKET}" backups/snapshots || \
  echo "WARN: s3 sync failed (bucket may be empty/unreachable); SQL dump is still valid"

# Prune dumps older than 7 days.
find backups -name 'nigrani-*.sql' -mtime +7 -delete
echo "backup complete: ${OUT}"
