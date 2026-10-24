-- Access-token allowlist: a JWT is only valid while its jti row is alive.
-- Login/refresh mint rows; self-revocation and deactivate/lockout delete
-- revocation, so a stolen access token dies mid-TTL (not at 15-min expiry).
CREATE TABLE access_tokens (
    jti UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX access_tokens_user_idx ON access_tokens (user_id);
