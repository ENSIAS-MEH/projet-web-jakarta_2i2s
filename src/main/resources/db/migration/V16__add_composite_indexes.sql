-- V16__add_composite_indexes.sql
-- Part IV §Composite and JSONB Indexes (V16)

-- Pending review dashboard score-sorted.
CREATE INDEX idx_user_report_pending_created
    ON user_report (status, created_at DESC)
    WHERE status = 'PENDING_REVIEW';

-- Job queue for operator dashboards.
CREATE INDEX idx_scan_job_status_created   ON scan_job   (status, created_at DESC);
CREATE INDEX idx_report_job_status_created ON report_job (status, created_at DESC);

-- "My incident reports" listing: filter by submitter, sort by recency.
CREATE INDEX idx_user_report_reported_by_created
    ON user_report (reported_by, created_at DESC);

-- JSONB containment queries against scan findings.
CREATE INDEX idx_scan_result_tier1_gin ON scan_result USING GIN (tier1_findings jsonb_path_ops);
CREATE INDEX idx_scan_result_tier2_gin ON scan_result USING GIN (tier2_findings jsonb_path_ops);
CREATE INDEX idx_scan_result_tier3_gin ON scan_result USING GIN (tier3_findings jsonb_path_ops);
CREATE INDEX idx_evidence_urls_gin     ON user_report  USING GIN (evidence_urls   jsonb_path_ops);

-- Active share-link lookup is hot. Composite standard index (not partial with volatile
-- predicate) so expired rows are not silently omitted from the index.
CREATE INDEX idx_share_link_active
    ON share_link (uuid_token, is_revoked, expires_at);

-- Live scanned_url rows only.
CREATE INDEX idx_scanned_url_live
    ON scanned_url (last_scanned_at DESC)
    WHERE deleted_at IS NULL;

-- Soft-delete: user_report operational queries always filter deleted_at IS NULL.
CREATE INDEX idx_user_report_live
    ON user_report (created_at DESC)
    WHERE deleted_at IS NULL;
