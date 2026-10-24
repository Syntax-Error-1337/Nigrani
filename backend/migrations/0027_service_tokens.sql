-- Hardware ingest (s-I1): turnstile/QR-scanner/NFC devices POST crossings
-- with a service token (hashed at rest; raw shown once at creation).
CREATE TABLE service_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT        NOT NULL UNIQUE,
    token_hash   TEXT        NOT NULL UNIQUE,
    permissions  TEXT        NOT NULL DEFAULT 'entries:write',
    created_by   UUID REFERENCES users (id),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);
