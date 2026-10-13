-- Operator provisioning: liveness flag + management permission.
ALTER TABLE users ADD COLUMN active BOOLEAN NOT NULL DEFAULT TRUE;

INSERT INTO permissions (name, description) VALUES
    ('users:write', 'Create, deactivate, and reactivate operator accounts')
ON CONFLICT (name) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.name = 'users:write'
WHERE r.name = 'SuperAdmin'
ON CONFLICT DO NOTHING;
