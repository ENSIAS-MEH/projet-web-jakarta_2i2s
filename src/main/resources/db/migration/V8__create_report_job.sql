-- V8__create_report_job.sql
-- Part IV §report_job
-- error_message is included in the base DDL per V17 note:
--   "CR-2: report_job.error_message — present in base DDL (V8); IF NOT EXISTS guard
--    prevents failure on fresh schemas."
-- Composite index (idx_report_job_status_created) is added in V16.

CREATE TABLE report_job (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url_id          UUID        NOT NULL REFERENCES scanned_url(id) ON DELETE CASCADE,
    requested_by    UUID        REFERENCES secbret_user(id) ON DELETE SET NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    file_data       BYTEA,
    file_size_bytes BIGINT,
    error_message   TEXT,
    created_at      TIMESTAMP   NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMP,

    CONSTRAINT chk_report_job_status CHECK (status IN ('PENDING', 'GENERATING', 'COMPLETED', 'FAILED'))
);

CREATE INDEX idx_report_job_url          ON report_job (url_id);
CREATE INDEX idx_report_job_requested_by ON report_job (requested_by);

-- At most one active (PENDING or GENERATING) report job per URL at a time.
CREATE UNIQUE INDEX uq_report_job_active_per_url
    ON report_job (url_id)
    WHERE status IN ('PENDING', 'GENERATING');
