-- TOTP 2FA + session identity (s-H2).
ALTER TABLE users
    ADD COLUMN totp_secret TEXT,
    ADD COLUMN totp_enabled_at TIMESTAMPTZ;

-- Session identity: each login mints a session_id; rotations inherit it so
-- the console can list and revoke per-device session families.
ALTER TABLE refresh_tokens ADD COLUMN session_id UUID;
ALTER TABLE access_tokens ADD COLUMN session_id UUID;
CREATE INDEX refresh_tokens_session_idx ON refresh_tokens (session_id);
