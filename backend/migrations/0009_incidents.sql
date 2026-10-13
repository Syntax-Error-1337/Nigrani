-- Incident lifecycle: status workflow, assignment, evidence links.
ALTER TABLE incidents
    ADD COLUMN status TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'investigating', 'resolved', 'closed')),
    ADD COLUMN assigned_to UUID REFERENCES users (id) ON DELETE SET NULL,
    ADD COLUMN resolved_at TIMESTAMPTZ;

CREATE TABLE incident_links (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('entry', 'embedding', 'snapshot', 'note')),
    ref_id      TEXT NOT NULL DEFAULT '',
    note        TEXT NOT NULL DEFAULT '',
    added_by    UUID NOT NULL REFERENCES users (id),
    added_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX incident_links_incident_idx ON incident_links (incident_id, added_at);
