-- V6__create_secbret_analysis.sql
-- Part IV §secbret_analysis
-- model_version is included here per V18 note:
--   "LO-4: model_version was originally added here in V18, but has been folded
--    into the base secbret_analysis table definition (V6) in this specification
--    to avoid a duplicate-column migration error."

CREATE TABLE secbret_analysis (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url_id              UUID         NOT NULL REFERENCES scanned_url(id) ON DELETE CASCADE,
    scan_result_id      UUID         REFERENCES scan_result(id) ON DELETE SET NULL,
    user_report_id      UUID         REFERENCES user_report(id) ON DELETE SET NULL,
    threat_score        DECIMAL(3,2) NOT NULL,
    verdict             VARCHAR(30)  NOT NULL,
    reasoning_chain     TEXT         NOT NULL,
    ml_consulted        BOOLEAN      NOT NULL DEFAULT FALSE,
    ml_score            DECIMAL(3,2),
    model_version       VARCHAR(50),
    created_at          TIMESTAMP    NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_threat_score     CHECK (threat_score >= 0.00 AND threat_score <= 1.00),
    CONSTRAINT chk_ml_score         CHECK (ml_score IS NULL OR (ml_score >= 0.00 AND ml_score <= 1.00)),
    CONSTRAINT chk_analysis_verdict CHECK (verdict IN ('BENIGN', 'SUSPICIOUS'))
);

CREATE INDEX idx_secbret_analysis_url    ON secbret_analysis (url_id);
CREATE INDEX idx_secbret_analysis_report ON secbret_analysis (user_report_id);
CREATE INDEX idx_secbret_analysis_score  ON secbret_analysis (threat_score DESC);

-- Prevents duplicate analysis records if the async CDI event fires more than once.
CREATE UNIQUE INDEX uq_secbret_analysis_report
    ON secbret_analysis (user_report_id)
    WHERE user_report_id IS NOT NULL;
