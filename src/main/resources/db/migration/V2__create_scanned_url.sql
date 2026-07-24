-- V2__create_scanned_url.sql
-- Part IV §scanned_url
-- NOTE: deleted_at column is NOT added here; it is added in V14.
-- NOTE: The unique index on normalized_hash is non-partial here; V14 replaces it
--       with a partial index (WHERE deleted_at IS NULL) after adding the column.

CREATE TABLE scanned_url (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    original_url        VARCHAR(2048) NOT NULL,
    normalized_hash     VARCHAR(64)   NOT NULL,
    last_scanned_at     TIMESTAMP,
    community_verdict   VARCHAR(30),
    created_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMP NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_community_verdict
        CHECK (community_verdict IS NULL
            OR community_verdict IN ('UNKNOWN', 'BENIGN', 'SUSPICIOUS', 'MALICIOUS'))
);

-- Base DDL: hard (non-partial) unique; V14 drops and replaces with partial.
-- Do NOT add the partial index here or V14 will fail with "relation already exists".
CREATE UNIQUE INDEX uq_scanned_url_normalized_hash ON scanned_url (normalized_hash);

CREATE INDEX idx_scanned_url_verdict      ON scanned_url (community_verdict);
CREATE INDEX idx_scanned_url_last_scanned ON scanned_url (last_scanned_at DESC);
