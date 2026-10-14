-- Press-card revocation: per-application kill timestamp (NULL = valid).
-- Revocation taints the application, not one QR printout (re-issuance
-- re-signs freely; re-vetting means a fresh application).
ALTER TABLE kyc_applications ADD COLUMN card_revoked_at TIMESTAMPTZ;
