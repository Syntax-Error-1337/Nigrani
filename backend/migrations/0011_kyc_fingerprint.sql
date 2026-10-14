-- KYC duplicate blind index: HMAC-SHA256 over normalized
-- `document_type|DOCUMENT_NUMBER` (see TemplateCrypto::fingerprint).
-- Legacy rows keep '' (fail-open); new submits always fingerprinted.
ALTER TABLE kyc_applications
    ADD COLUMN doc_fingerprint TEXT NOT NULL DEFAULT '';

CREATE INDEX kyc_applications_fingerprint_idx
    ON kyc_applications (doc_fingerprint, status);
