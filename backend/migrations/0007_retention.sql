-- Retention policies: per-entity keep windows (days). 0 = keep forever.
CREATE TABLE retention_policies (
    entity      TEXT PRIMARY KEY,
    retain_days INTEGER NOT NULL DEFAULT 365 CHECK (retain_days >= 0)
);

INSERT INTO retention_policies (entity, retain_days) VALUES
    ('kyc_applications', 365),
    ('face_embeddings', 180),
    ('entry_logs', 365),
    ('refresh_tokens', 30),
    ('audit_log', 0)
ON CONFLICT (entity) DO NOTHING;
