-- Canonical roles, permission set, role grants, seeded users (password: password).
-- Password hash below is argon2 for "password"; replaced by seed code at runtime.
INSERT INTO roles (name, description) VALUES
    ('SuperAdmin', 'System configuration'),
    ('SiteCommander', 'Site chief, e.g. Jantar Mantar chief'),
    ('GateOperator', 'Kiosk verification officer at physical gates'),
    ('VerificationOfficer', 'Press and media KYC reviewer'),
    ('ForensicAnalyst', 'Police incident and face-search analyst')
ON CONFLICT (name) DO NOTHING;

INSERT INTO permissions (name, description) VALUES
    ('sites:read', 'List and view protest sites'),
    ('sites:write', 'Create and update protest sites'),
    ('gates:read', 'List and view entry/exit gates'),
    ('gates:write', 'Create and update entry/exit gates'),
    ('users:read', 'List users'),
    ('kyc:review', 'Inspect, approve, or reject media access requests'),
    ('forensics:search', 'Run facial-embedding similarity search'),
    ('incidents:write', 'Log incidents and tag suspects')
ON CONFLICT (name) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON
    (r.name = 'SuperAdmin') OR
    (r.name = 'SiteCommander' AND p.name IN ('sites:read', 'sites:write', 'gates:read', 'gates:write', 'incidents:write')) OR
    (r.name = 'GateOperator' AND p.name IN ('sites:read', 'gates:read')) OR
    (r.name = 'VerificationOfficer' AND p.name IN ('sites:read', 'gates:read', 'kyc:review')) OR
    (r.name = 'ForensicAnalyst' AND p.name IN ('sites:read', 'gates:read', 'forensics:search', 'incidents:write'))
ON CONFLICT DO NOTHING;

INSERT INTO sites (name, location) VALUES
    ('Jantar Mantar', 'New Delhi')
ON CONFLICT (name) DO NOTHING;
