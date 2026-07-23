-- V17__add_report_job_error_message_and_scan_job_superseded_by.sql
-- Part IV §V17: scan_job.superseded_by constraint and verdict extension
-- error_message and superseded_by are already present in base DDL (V3/V8).
-- IF NOT EXISTS guards make these idempotent no-ops on fresh schemas.
-- Constraint rewrites are retained for older deployments that lacked REJECTED.

-- CR-2: report_job.error_message — present in base DDL (V8); IF NOT EXISTS guard.
ALTER TABLE report_job ADD COLUMN IF NOT EXISTS error_message TEXT;

-- LO-3: scan_job.superseded_by — present in base DDL (V3); IF NOT EXISTS guard.
ALTER TABLE scan_job ADD COLUMN IF NOT EXISTS
    superseded_by UUID REFERENCES scan_job(id) ON DELETE SET NULL;

-- CR-1: Expand chk_review_status to include REJECTED.
-- Base DDL already contains REJECTED; no-op on fresh schemas.
ALTER TABLE security_team_review DROP CONSTRAINT IF EXISTS chk_review_status;
ALTER TABLE security_team_review ADD CONSTRAINT chk_review_status
    CHECK (status IN ('APPROVED', 'REJECTED', 'MODIFIED'));

-- C1 FIX: Symmetric dual-layer guard on user_report.verdict.
-- Re-applied here so existing installations get the strengthened constraint.
ALTER TABLE user_report DROP CONSTRAINT IF EXISTS chk_report_verdict;
ALTER TABLE user_report ADD CONSTRAINT chk_report_verdict CHECK (
    verdict IS NULL
    OR (
        verdict IN ('VERIFIED_MALICIOUS', 'VERIFIED_BENIGN', 'REJECTED')
        AND verdict NOT IN ('BENIGN', 'SUSPICIOUS')
    )
);
