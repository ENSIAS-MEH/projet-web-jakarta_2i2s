-- V19__create_api_token.sql
-- Part IV §api_token (v2 pre-positioning)
-- v2 pre-positioning: no application code references this table in v1.
-- ON DELETE CASCADE on user_id per Part II §F and Part IV §ON DELETE Cascade Policy.

CREATE TABLE api_token (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES secbret_user(id) ON DELETE CASCADE,
    token_hash   VARCHAR(64) NOT NULL UNIQUE,
    label        VARCHAR(100),
    created_at   TIMESTAMP NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMP,
    expires_at   TIMESTAMP
);

CREATE INDEX idx_api_token_user ON api_token (user_id);
