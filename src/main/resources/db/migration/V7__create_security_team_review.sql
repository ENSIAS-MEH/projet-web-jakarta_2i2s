-- V7__create_security_team_review.sql
-- Part IV §security_team_review

CREATE TABLE security_team_review (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_report_id      UUID        UNIQUE NOT NULL REFERENCES user_report(id) ON DELETE CASCADE,
    secbret_analysis_id UUID        NOT NULL REFERENCES secbret_analysis(id) ON DELETE CASCADE,
    reviewed_by         UUID        REFERENCES secbret_user(id) ON DELETE SET NULL,
    status              VARCHAR(20) NOT NULL,
    reviewer_notes      TEXT,
    final_verdict       VARCHAR(30) NOT NULL,
    created_at          TIMESTAMP   NOT NULL DEFAULT NOW(),
    reviewed_at         TIMESTAMP,

    CONSTRAINT chk_review_status  CHECK (status IN ('APPROVED', 'REJECTED', 'MODIFIED')),
    CONSTRAINT chk_review_verdict CHECK (final_verdict IN ('VERIFIED_MALICIOUS', 'VERIFIED_BENIGN', 'REJECTED'))
);

CREATE INDEX idx_review_report      ON security_team_review (user_report_id);
CREATE INDEX idx_review_reviewed_by ON security_team_review (reviewed_by);
CREATE INDEX idx_review_status      ON security_team_review (status);
