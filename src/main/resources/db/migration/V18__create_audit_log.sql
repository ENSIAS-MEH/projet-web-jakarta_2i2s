-- V18__create_audit_log.sql
-- Part IV §V18: audit_log and ML model_version
-- actor_id ON DELETE SET NULL per Part II §F and Part IV §ON DELETE Cascade Policy.
-- model_version has been folded into secbret_analysis base DDL (V6); the standalone
-- ALTER TABLE is commented out here as noted in Part IV to avoid duplicate-column error.

CREATE TABLE audit_log (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id               UUID REFERENCES secbret_user(id) ON DELETE SET NULL,
    actor_username         VARCHAR(50),
    action                 VARCHAR(100) NOT NULL,
    target_type            VARCHAR(50),
    target_id              UUID,
    detail                 JSONB,
    internal_error_details TEXT,
    created_at             TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_log_actor          ON audit_log (actor_id);
CREATE INDEX idx_audit_log_actor_username ON audit_log (actor_username);
CREATE INDEX idx_audit_log_created        ON audit_log (created_at DESC);
CREATE INDEX idx_audit_log_target         ON audit_log (target_type, target_id);

-- LO-4: model_version already added in base DDL (V6). Do NOT execute:
-- ALTER TABLE secbret_analysis ADD COLUMN model_version VARCHAR(50);
