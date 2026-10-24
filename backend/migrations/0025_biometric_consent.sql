-- Biometric processing consent (s-H3): the applicant opts in on the public
-- form; embedding enrollment refuses without it (DPDP-style lawful basis).
ALTER TABLE kyc_applications ADD COLUMN photo_consent BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE face_embeddings ADD COLUMN consent BOOLEAN NOT NULL DEFAULT false;
