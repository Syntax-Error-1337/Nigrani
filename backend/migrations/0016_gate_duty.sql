-- Gate duty: the VerificationOfficer (or other entries:write holder)
-- assigned to staff a gate. Officer learns the assignment, commander sets it.
ALTER TABLE gates
    ADD COLUMN duty_officer UUID REFERENCES users (id) ON DELETE SET NULL;

-- Verifiers staff gates and record crossings: grant the write permission.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'VerificationOfficer' AND p.name = 'entries:write';
