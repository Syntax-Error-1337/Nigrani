-- Topology retirement: archive timestamps (NULL = live).
-- History is preserved: entry_logs CASCADE only on hard delete (never
-- issued by the API); incidents SET NULL only then too.
ALTER TABLE sites ADD COLUMN archived_at TIMESTAMPTZ;
ALTER TABLE gates ADD COLUMN archived_at TIMESTAMPTZ;

CREATE INDEX sites_archived_idx ON sites (archived_at) WHERE archived_at IS NULL;
CREATE INDEX gates_archived_idx ON gates (site_id, archived_at) WHERE archived_at IS NULL;
