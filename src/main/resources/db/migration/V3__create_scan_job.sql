-- V3__create_scan_job.sql
-- Part IV §scan_job
-- superseded_by and error_message are included in the base DDL per Part IV V17 note.
-- V17 adds them with IF NOT EXISTS as an idempotent guard for older deployments.
-- version column (optimistic locking) is included here per the spec comment
--   "version column is in the CREATE TABLE block above (JPA @Version)".

CREATE TABLE scan_job (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url_id          UUID        NOT NULL REFERENCES scanned_url(id) ON DELETE CASCADE,
    submitted_by    UUID        REFERENCES secbret_user(id) ON DELETE SET NULL,
    superseded_by   UUID        REFERENCES scan_job(id) ON DELETE SET NULL,
    scan_depth      VARCHAR(10) NOT NULL DEFAULT 'QUICK',
    status          VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    version         BIGINT      NOT NULL DEFAULT 0,
    error_message   TEXT,
    created_at      TIMESTAMP   NOT NULL DEFAULT NOW(),
    started_at      TIMESTAMP,
    completed_at    TIMESTAMP,

    CONSTRAINT chk_scan_depth CHECK (scan_depth IN ('QUICK', 'DEEP')),
    CONSTRAINT chk_scan_job_status CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'SUPERSEDED', 'FAILED'))
);

CREATE INDEX idx_scan_job_url          ON scan_job (url_id);
CREATE INDEX idx_scan_job_submitted_by ON scan_job (submitted_by);

-- One active scan job per URL. Enforces overwrite semantics at the DB level.
-- Terminal statuses and tombstoned rows are excluded per Part IV.
CREATE UNIQUE INDEX uq_scan_job_active_per_url
    ON scan_job (url_id)
    WHERE status IN ('PENDING', 'RUNNING');
