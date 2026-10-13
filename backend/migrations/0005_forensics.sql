-- Forensic search: face embeddings (pgvector), incidents.
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE face_embeddings (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entry_log_id   UUID REFERENCES entry_logs (id) ON DELETE SET NULL,
    application_id UUID REFERENCES kyc_applications (id) ON DELETE SET NULL,
    embedding      vector(512) NOT NULL,
    captured_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX face_embeddings_hnsw_idx ON face_embeddings
    USING hnsw (embedding vector_cosine_ops);

CREATE TABLE incidents (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    site_id                UUID REFERENCES sites (id) ON DELETE SET NULL,
    title                  TEXT NOT NULL,
    description            TEXT NOT NULL DEFAULT '',
    suspect_application_id UUID REFERENCES kyc_applications (id) ON DELETE SET NULL,
    created_by             UUID NOT NULL REFERENCES users (id),
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX incidents_site_idx ON incidents (site_id, created_at DESC);
