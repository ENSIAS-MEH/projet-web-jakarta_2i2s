-- V13__create_idempotency_key.sql
-- Part IV §idempotency_key (V13)
-- ON DELETE CASCADE on user_id per Part II §F and Part IV §ON DELETE Cascade Policy.

CREATE TABLE idempotency_key (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES secbret_user(id) ON DELETE CASCADE,
    idem_key        VARCHAR(255) NOT NULL,
    endpoint        VARCHAR(100) NOT NULL,
    request_hash    VARCHAR(64)  NOT NULL,
    response_status INTEGER,
    response_body   TEXT,
    expires_at      TIMESTAMP    NOT NULL,
    created_at      TIMESTAMP    NOT NULL DEFAULT NOW(),

    UNIQUE (user_id, endpoint, idem_key),
    CONSTRAINT chk_idem_response CHECK (response_status IS NULL
        OR response_status BETWEEN 200 AND 599)
);

CREATE INDEX idx_idempotency_expires ON idempotency_key (expires_at);
