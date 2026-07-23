-- V14__add_soft_delete_and_version_columns.sql
-- Part IV §Soft-delete and Optimistic-locking Columns (V14)
-- user_report.deleted_at and user_report.version are declared inline in V5 CREATE TABLE,
-- so the ADD COLUMN IF NOT EXISTS statements below are idempotent no-op safety nets.
-- scan_job.version is declared inline in V3 CREATE TABLE; same idempotent guard.
-- scanned_url.deleted_at is NOT in V2; it is first added here.
-- The partial unique index on normalized_hash replaces the non-partial one from V2.

ALTER TABLE user_report ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
ALTER TABLE user_report ADD COLUMN IF NOT EXISTS version BIGINT NOT NULL DEFAULT 0;
ALTER TABLE scan_job    ADD COLUMN IF NOT EXISTS version BIGINT NOT NULL DEFAULT 0;
ALTER TABLE scanned_url ADD COLUMN deleted_at TIMESTAMP;

-- Replace non-partial unique index with a partial one so that soft-deleted URLs
-- can be re-scanned without constraint violations.
-- NOTE: The base DDL uses CREATE UNIQUE INDEX (standalone), so DROP INDEX is correct.
DROP INDEX IF EXISTS uq_scanned_url_normalized_hash;
CREATE UNIQUE INDEX uq_scanned_url_normalized_hash
    ON scanned_url (normalized_hash)
    WHERE deleted_at IS NULL;
