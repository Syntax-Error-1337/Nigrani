-- Fuzzy duplicate matching (reviewer flags) + photo-hash duplicates.
-- Flags store only ids + score/reason — no PII — computed in memory at
-- submit time while the plaintext is available.
ALTER TABLE kyc_applications ADD COLUMN photo_hash TEXT;
CREATE TABLE kyc_duplicates (
    application_id UUID NOT NULL REFERENCES kyc_applications (id) ON DELETE CASCADE,
    similar_id     UUID NOT NULL REFERENCES kyc_applications (id) ON DELETE CASCADE,
    score          REAL NOT NULL,
    reason         TEXT NOT NULL CHECK (reason IN ('name', 'document', 'photo')),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (application_id, similar_id)
);
CREATE INDEX kyc_duplicates_similar_idx ON kyc_duplicates (similar_id);
