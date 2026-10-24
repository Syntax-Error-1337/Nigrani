-- External audit-chain anchors (s-H1): a checkpoint of the chain head that
-- lives OUTSIDE the chain. An attacker who rewrites history and re-chains
-- (recomputing every hash) passes the linear verifier; these stored copies
-- of past heads no longer match, exposing the rewrite.
CREATE TABLE audit_anchors (
    seq      BIGINT      NOT NULL,             -- head seq at anchor time
    hash     TEXT        NOT NULL,             -- head hash at anchor time
    at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor    UUID REFERENCES users (id),
    note     TEXT        NOT NULL DEFAULT ''
);
