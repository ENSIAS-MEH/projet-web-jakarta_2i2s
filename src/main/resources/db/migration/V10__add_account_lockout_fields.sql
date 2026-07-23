-- V10__add_account_lockout_fields.sql
-- Part IV §secbret_user — account lockout fields.
-- failed_login_attempts and locked_until are already present in the base DDL (V1).
-- This migration is an idempotent no-op safety net for older deployments that
-- may have been created before these columns were folded into V1.
-- Interpretation: spec names V10 "add_account_lockout_fields", so we use
-- ADD COLUMN IF NOT EXISTS guards so V10 is safe to apply against both
-- old schemas (pre-V10 columns) and the current base DDL.

ALTER TABLE secbret_user ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE secbret_user ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP;

-- The partial index on locked_until was created in V1 for fresh schemas.
-- Create it here only if it doesn't already exist (idempotent via DO block).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE tablename = 'secbret_user' AND indexname = 'idx_user_locked_until'
    ) THEN
        CREATE INDEX idx_user_locked_until ON secbret_user (locked_until) WHERE locked_until IS NOT NULL;
    END IF;
END;
$$;
