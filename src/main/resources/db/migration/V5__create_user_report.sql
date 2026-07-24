-- V5__create_user_report.sql
-- Part IV §user_report
-- version and deleted_at are declared inline here per the spec note:
--   "version and deleted_at are declared inline in CREATE TABLE above (same
--    convention as scan_job); V14's ADD COLUMN IF NOT EXISTS for them is an
--    idempotent no-op safety net."
-- Composite/partial indexes (idx_user_report_status_created, idx_user_report_pending_created,
-- idx_user_report_reported_by_created, idx_evidence_urls_gin, idx_user_report_live)
-- are added in V16.

CREATE TABLE user_report (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url_id                UUID        NOT NULL REFERENCES scanned_url(id) ON DELETE CASCADE,
    reported_by           UUID        REFERENCES secbret_user(id) ON DELETE SET NULL,
    evidence_description  TEXT        NOT NULL,
    evidence_urls         JSONB,
    status                VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    verdict               VARCHAR(30),
    error_message         TEXT,
    version               BIGINT      NOT NULL DEFAULT 0,
    deleted_at            TIMESTAMP,
    created_at            TIMESTAMP   NOT NULL DEFAULT NOW(),
    resolved_at           TIMESTAMP,

    CONSTRAINT chk_report_status CHECK (status IN ('PENDING', 'PENDING_REVIEW', 'VERIFIED', 'REJECTED', 'FAILED')),
    CONSTRAINT chk_report_verdict CHECK (
        verdict IS NULL
        OR (
            verdict IN ('VERIFIED_MALICIOUS', 'VERIFIED_BENIGN', 'REJECTED')
            AND verdict NOT IN ('BENIGN', 'SUSPICIOUS')
        )
    ),
    CONSTRAINT chk_evidence_length CHECK (char_length(evidence_description) >= 10 AND char_length(evidence_description) <= 2000)
);

CREATE INDEX idx_user_report_url         ON user_report (url_id);
CREATE INDEX idx_user_report_reported_by ON user_report (reported_by);
CREATE INDEX idx_user_report_created     ON user_report (created_at DESC);
