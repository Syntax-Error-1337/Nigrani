-- Retention coverage for the incident lifecycle tables.
INSERT INTO retention_policies (entity, retain_days) VALUES
    ('incidents', 365),
    ('incident_links', 365)
ON CONFLICT (entity) DO NOTHING;
