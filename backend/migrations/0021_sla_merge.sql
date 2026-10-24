-- Incident SLA timers, escalation, and case merging. Legacy rows keep NULL
-- sla_due_at (created before the policy; they never escalate). Escalation is
-- lazy: the first list/read that sees an overdue, un-escalated case stamps it.
ALTER TABLE incidents
    ADD COLUMN sla_due_at TIMESTAMPTZ,
    ADD COLUMN escalated_at TIMESTAMPTZ,
    ADD COLUMN merged_into UUID REFERENCES incidents (id);
CREATE INDEX incidents_sla_idx ON incidents (site_id, sla_due_at);
