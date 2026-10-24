-- Occupancy trends beyond 24h + surge alerting: hourly buckets come from
-- entry_logs (no new storage); surge = per-site entries/hour threshold with
-- one deduplicated alert per gate-hour.
ALTER TABLE sites ADD COLUMN surge_threshold INT;

CREATE TABLE surge_alerts (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    site_id      UUID NOT NULL REFERENCES sites (id) ON DELETE CASCADE,
    gate_id      UUID NOT NULL REFERENCES gates (id) ON DELETE CASCADE,
    window_start TIMESTAMPTZ NOT NULL,
    count        INT NOT NULL,
    threshold    INT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (gate_id, window_start)
);
CREATE INDEX surge_alerts_site_idx ON surge_alerts (site_id, created_at DESC);
