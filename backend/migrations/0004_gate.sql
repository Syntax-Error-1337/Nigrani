-- Gate screening: entry/exit event log.
CREATE TABLE entry_logs (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gate_id        UUID NOT NULL REFERENCES gates (id) ON DELETE CASCADE,
    application_id UUID REFERENCES kyc_applications (id),
    direction      TEXT NOT NULL CHECK (direction IN ('entry', 'exit')),
    method         TEXT NOT NULL CHECK (method IN ('press_card', 'manual')),
    snapshot_key   TEXT NOT NULL DEFAULT '',
    recorded_by    UUID NOT NULL REFERENCES users (id),
    recorded_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX entry_logs_gate_idx ON entry_logs (gate_id, recorded_at DESC);

INSERT INTO permissions (name, description) VALUES
    ('entries:write', 'Record gate entry/exit screening events')
ON CONFLICT (name) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.name = 'entries:write'
WHERE r.name IN ('SiteCommander', 'GateOperator')
ON CONFLICT DO NOTHING;
