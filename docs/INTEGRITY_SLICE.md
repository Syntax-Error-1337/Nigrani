# Forensic Reference Integrity — Scope Note (t82, sprint s28)

## Gap
Three write paths accept foreign UUIDs and let Postgres FK violations
surface as `500 database error`:
1. `POST /forensics/embeddings` — `entry_log_id` / `application_id`
   reference entry_logs / kyc_applications (both `ON DELETE SET NULL` FKs).
   A typo'd or GC'd id → raw 500.
2. `POST /sites/:id/incidents` — `suspect_application_id` references
   kyc_applications. Same 500.
3. `POST .../incidents/:iid/links` — `entry`/`embedding` kinds store raw
   TEXT UUIDs with NO existence check at all: silent dangling evidence
   (worse than a 500 — a case citing a crossing that doesn't exist).

Entry-log links also skip site-scoping: an analyst can link a crossing
from site B onto a site-A case (evidence confusion across protest sites).

## Design
- Pre-insert EXISTS checks (cheap indexed point-lookups, same connection):
  - enroll: each Some(id) verified → `404 entry log not found` /
    `404 application not found`.
  - create_incident: Some(suspect) verified → `404 suspect application
    not found`.
  - add link `entry`: row must exist AND its gate's site must equal the
    case's site → `404` / `400 cross-site link refused`. `embedding`:
    existence only (embeddings are site-ambiguous by design — the search
    itself is optionally site-scoped).
- No schema change. No new error variants (`NotFound`/`BadRequest` exist).
- Audit: keep as-is (failed validations return before mutation, like all
  other 4xx paths — no audit rows for rejected writes).

## Out
Snapshotted evidence immutability (links rot when purge deletes rows —
  accepted: links are investigative pointers, export freezes them);
backfill validation of existing dangling links.

## Acceptance
- Enroll with bogus entry_log + application → 404s; incident with bogus
  suspect → 404; entry-link to other-site crossing → 400; good links
  still 200 with audit row.
- Suite green; clippy clean; live curl proof.
