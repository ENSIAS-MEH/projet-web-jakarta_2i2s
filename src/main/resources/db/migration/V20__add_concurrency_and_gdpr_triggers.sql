-- V20__add_concurrency_and_gdpr_triggers.sql
-- Part IV §V20: DB-enforced concurrency and GDPR triggers
-- C2 FIX (part 2): link_superseded_scan_job — AFTER INSERT trigger that atomically
--   sets superseded_by on the SUPERSEDED job when a new PENDING scan_job is inserted.
--   ScanPersistence.createJob() MUST NOT contain an explicit step-4 UPDATE; this trigger
--   is the canonical implementation.
-- C3 FIX: tombstone_audit_before_delete — BEFORE DELETE trigger on secbret_user that
--   writes actor_username = 'deleted_{uuid}' before the ON DELETE SET NULL cascade
--   nullifies actor_id. UserService.deleteAccount() MUST NOT contain an explicit tombstone
--   UPDATE. See V18 Historical Note for the superseded application-level implementation.

-- ── C2 FIX (part 2): Atomic superseded_by back-pointer ───────────────────────

CREATE OR REPLACE FUNCTION trg_link_superseded_scan_job()
RETURNS trigger AS $$
BEGIN
    -- When a new PENDING scan_job is inserted, find any SUPERSEDED job for the same
    -- URL that has not yet been linked (superseded_by IS NULL) and link it.
    -- The FOR UPDATE lock from step 1 ensures at most one SUPERSEDED job exists here.
    UPDATE scan_job
    SET    superseded_by = NEW.id
    WHERE  url_id        = NEW.url_id
      AND  status        = 'SUPERSEDED'
      AND  superseded_by IS NULL
      AND  id           <> NEW.id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Fires only for PENDING inserts (new scan submissions), not RUNNING/COMPLETED updates.
CREATE TRIGGER link_superseded_scan_job
    AFTER INSERT ON scan_job
    FOR EACH ROW
    WHEN (NEW.status = 'PENDING')
    EXECUTE FUNCTION trg_link_superseded_scan_job();


-- ── C3 FIX: DDL-enforced audit_log tombstoning before user hard-delete ────────

CREATE OR REPLACE FUNCTION trg_tombstone_audit_before_user_delete()
RETURNS trigger AS $$
BEGIN
    UPDATE audit_log
    SET    actor_username = 'deleted_' || OLD.id::text
    WHERE  actor_id = OLD.id;
    -- If no audit_log rows exist for this user, this UPDATE is a safe no-op.
    RETURN OLD;  -- Must return OLD (not NEW/NULL) for BEFORE DELETE triggers.
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER tombstone_audit_before_delete
    BEFORE DELETE ON secbret_user
    FOR EACH ROW
    EXECUTE FUNCTION trg_tombstone_audit_before_user_delete();
