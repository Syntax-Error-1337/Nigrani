-- Append-only, hash-chained audit trail.
CREATE TABLE audit_log (
    seq       BIGSERIAL PRIMARY KEY,
    at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor     UUID REFERENCES users (id) ON DELETE SET NULL,
    action    TEXT NOT NULL,
    entity    TEXT NOT NULL,
    entity_id UUID,
    detail    JSONB NOT NULL DEFAULT '{}',
    prev_hash TEXT NOT NULL DEFAULT '',
    hash      TEXT NOT NULL DEFAULT ''
);

CREATE INDEX audit_log_entity_idx ON audit_log (entity, entity_id, seq DESC);
CREATE INDEX audit_log_at_idx ON audit_log (at DESC);

-- No UPDATE/DELETE grants are managed here (all roles share one DB user);
-- append-only is enforced by convention + the hash chain, verified via
-- GET /audit/verify. A dedicated read-only DB role is recorded out of scope.
