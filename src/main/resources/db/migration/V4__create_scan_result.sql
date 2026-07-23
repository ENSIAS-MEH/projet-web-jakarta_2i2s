-- V4__create_scan_result.sql
-- Part IV §scan_result
-- GIN indexes on tier findings are added in V16 (composite/JSONB indexes migration).

CREATE TABLE scan_result (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url_id          UUID        NOT NULL REFERENCES scanned_url(id) ON DELETE CASCADE,
    scan_job_id     UUID        NOT NULL UNIQUE REFERENCES scan_job(id) ON DELETE CASCADE,
    tier1_findings  JSONB,
    tier2_findings  JSONB,
    tier3_findings  JSONB,
    overall_score   DECIMAL(3,2),
    created_at      TIMESTAMP   NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_overall_score CHECK (overall_score IS NULL OR (overall_score >= 0.00 AND overall_score <= 1.00))
);

CREATE INDEX idx_scan_result_url   ON scan_result (url_id);
CREATE INDEX idx_scan_result_score ON scan_result (overall_score DESC);
