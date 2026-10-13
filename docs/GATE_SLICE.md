# Phase 3 Gate Slice — Scope Note (t13, sprint s5)

## Constraint (ground truth)
No physical hardware on this host: no CCTV/RTSP feeds, no fingerprint
scanners, no dual-camera rigs. Real frame parsing (`opencv`, RTSP workers)
is therefore OUT. The backend exposes the seam a future edge agent plugs
into: it accepts JPEG frames + events over HTTPS and does everything
downstream (verify → store → log).

## Shipped in this slice
Backend (`backend/`):
- Migration `0004_gate.sql`: `entry_logs` table (id, gate_id, application_id
  NULL, direction entry/exit, method press_card/manual, snapshot_key NULL,
  recorded_by, recorded_at) + new `entries:write` permission granted to
  `GateOperator` and `SiteCommander` (SuperAdmin bypasses; other roles 403).
- `POST /sites/:site_id/gates/:gate_id/events`
  `{direction, method, application_id?, press_card?}` → verifies card payload
  when given (`401`-family on bad card → `409`? no: invalid card = `403`
  with clear error), writes entry log. Needs `entries:write`.
- `POST /snapshots` (multipart JPEG ≤ 5MB) → MinIO bucket
  `nigrani-snapshots`, returns key. `GET /snapshots/:key` proxies download.
- `GET /sites/:site_id/gates/:gate_id/log?limit=` → recent entries.
  Needs `gates:read` (all roles).
- S3 via `aws-sdk-s3` against MinIO (compose service, backend auto-creates
  bucket idempotently on boot). Config: `S3_ENDPOINT`, `S3_ACCESS_KEY`,
  `S3_SECRET_KEY`, `S3_BUCKET` with dev defaults.

Frontend (`frontend/`):
- Kiosk panel in Dashboard for `GateOperator` (+ `SuperAdmin`): card payload
  field → verify → holder display → Entry/Exit log buttons → snapshot file
  picker → recent log list. Reuses ReviewDesk visual language.

Infra:
- `docker-compose.yml`: `s3` service (LocalStack 3.6.0 S3 on :4566; MinIO
  image unpullable from this host, `latest` LocalStack needs a license).

## Explicitly out
RTSP/opencv workers, fingerprint matching, 180° rig stitching, QR image
rendering (unchanged), shared rate-limit quota (unchanged).

## Manual verification
1. `docker compose up -d db minio`, `cargo run` → boot creates bucket.
2. Submit KYC → approve → press card (s2 flow), then kiosk: verify card,
   log entry with snapshot upload, entry appears in log list.
3. `curl` event with tampered card → `403`; as `analyst` → `403` (no
   `entries:write`); snapshot > 5MB → `413` (axum body limit, before handler).
4. `cargo test`, clippy, browser pass on kiosk panel.
