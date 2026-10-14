-- Login lockout: per-account guessing guard (counter resets on success).
ALTER TABLE users
    ADD COLUMN failed_logins INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN locked_until TIMESTAMPTZ;
