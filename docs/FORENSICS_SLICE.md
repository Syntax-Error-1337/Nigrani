# Phase 4 Forensics Slice — Scope Note (t16, sprint s6)

## Constraint (ground truth)
No face-embedding model on this host (no GPU, no ONNX weights, no camera
feeds). Real extraction (`opencv` + model inference) is OUT. The backend
accepts caller-supplied 512-d vectors (edge agents / future pipeline fill
them) and owns storage, similarity search, incidents, and heatmap.

## Shipped in this slice
Infra:
- `db` image → `pgvector/pgvector:pg16`; migration `0005_forensics.sql`:
  `CREATE EXTENSION vector`, `face_embeddings` table
  (id, entry_log_id NULL, application_id NULL, embedding vector(512),
  captured_at), HNSW cosine index, `incidents` table
  (id, site_id NULL, title, description, suspect_application_id NULL,
  created_by, created_at).

Backend:
- `POST /forensics/embeddings` (needs `forensics:search`)
  `{entry_log_id?, application_id?, embedding: [512 floats]}` → stored.
  Rejects wrong-length vectors (`400`).
- `POST /forensics/search` (needs `forensics:search`)
  `{embedding: [512], threshold?, limit?, site_id?}` → ranked matches
  `[{id, application_id, entry_log_id, distance}]` by cosine distance
  (`<=>`), optional site scoping via entry-log gate join.
- `GET/POST /sites/:site_id/incidents` (needs `incidents:write` for POST,
  `gates:read` for GET) → suspect tagging against KYC applications.
- `GET /sites/:site_id/heatmap` (needs `gates:read`) → per-gate
  entry/exit counts, bucketed hourly for the last 24h (from `entry_logs`).

Frontend:
- Forensic bench in Dashboard for `ForensicAnalyst` (+ `SuperAdmin`):
  paste-vector search panel (comma-separated 512 floats), results list,
  incident composer + list, heatmap table (gates × in/out totals).

## Explicitly out
Model inference, image→vector extraction, PostGIS gate mapping (gates
already site-scoped; GIS adds nothing at this scale).

## Manual verification
1. `docker compose up -d db` (pgvector image), `cargo run` → extension live.
2. Enroll two vectors (near-duplicates + distant), search → near one ranks
   first with small distance; wrong-length → `400`; as `gate` → `403`.
3. Log incident with suspect app, heatmap shows seeded gate crossings.
4. `cargo test`, clippy, browser pass on forensic bench.
