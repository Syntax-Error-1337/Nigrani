-- Press/media KYC applications and review decisions.
CREATE TABLE kyc_applications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    full_name       TEXT NOT NULL,
    organization    TEXT NOT NULL DEFAULT '',
    document_type   TEXT NOT NULL CHECK (document_type IN ('aadhaar', 'pan', 'press_id')),
    document_number TEXT NOT NULL,
    photo_url       TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'approved', 'rejected')),
    submitted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at      TIMESTAMPTZ,
    decided_by      UUID REFERENCES users (id),
    decision_note   TEXT NOT NULL DEFAULT ''
);

CREATE INDEX kyc_applications_status_idx ON kyc_applications (status, submitted_at);
