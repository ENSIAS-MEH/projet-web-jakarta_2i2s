-- V9__create_share_link.sql
-- Part IV §share_link
-- Composite index (idx_share_link_active) is added in V16.
-- uuid_token UNIQUE constraint on the column creates the underlying B-tree index;
-- no redundant CREATE UNIQUE INDEX per spec.

CREATE TABLE share_link (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_job_id    UUID        NOT NULL REFERENCES report_job(id) ON DELETE CASCADE,
    created_by       UUID        REFERENCES secbret_user(id) ON DELETE SET NULL,
    uuid_token       VARCHAR(36) NOT NULL UNIQUE,
    expires_at       TIMESTAMP   NOT NULL,
    is_revoked       BOOLEAN     NOT NULL DEFAULT FALSE,
    access_count     INTEGER     NOT NULL DEFAULT 0,
    created_at       TIMESTAMP   NOT NULL DEFAULT NOW(),
    last_accessed_at TIMESTAMP
);

CREATE INDEX idx_share_link_expires    ON share_link (expires_at);
CREATE INDEX idx_share_link_created_by ON share_link (created_by);
