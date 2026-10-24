-- Machine-recorded crossings (s-I1): hardware ingest records with no
-- operator — recorded_by becomes nullable (NULL = machine actor).
ALTER TABLE entry_logs ALTER COLUMN recorded_by DROP NOT NULL;
