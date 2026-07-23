-- V11__create_password_reset_token.sql
-- Part IV §password_reset_token (V11)
-- ON DELETE CASCADE on user_id: CASCADE per Part II §F and Part IV §ON DELETE Cascade Policy.

CREATE TABLE password_reset_token (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES secbret_user(id) ON DELETE CASCADE,
    token_hash  VARCHAR(64) NOT NULL UNIQUE,
    expires_at  TIMESTAMP NOT NULL,
    used_at     TIMESTAMP,
    created_at  TIMESTAMP NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_reset_expiry CHECK (expires_at > created_at)
);

CREATE INDEX idx_password_reset_user    ON password_reset_token (user_id);
CREATE INDEX idx_password_reset_expires ON password_reset_token (expires_at);
