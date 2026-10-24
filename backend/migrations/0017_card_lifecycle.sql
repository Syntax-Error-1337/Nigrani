-- Card lifecycle: per-print serials, 90-day validity, re-issuance.
-- Legacy rows (issued before this migration) keep NULL serial/expiry:
-- issuance/reissue fills them lazily; no fake backfill.
ALTER TABLE kyc_applications
    ADD COLUMN card_serial TEXT UNIQUE,
    ADD COLUMN card_expires_at TIMESTAMPTZ,
    ADD COLUMN card_print_count INT NOT NULL DEFAULT 0,
    ADD COLUMN prior_serials TEXT[] NOT NULL DEFAULT '{}';
