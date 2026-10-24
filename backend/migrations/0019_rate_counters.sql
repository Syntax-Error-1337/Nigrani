-- Cluster-wide rate-limit quota: counters live in Postgres, so every
-- replica shares one fixed-window budget per (limiter, ip). The old
-- per-instance HashMap made a second replica double each quota.
CREATE TABLE rate_counters (
    limiter TEXT NOT NULL,
    ip TEXT NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    count INT NOT NULL,
    PRIMARY KEY (limiter, ip, window_start)
);
CREATE INDEX rate_counters_prune_idx ON rate_counters (window_start);
