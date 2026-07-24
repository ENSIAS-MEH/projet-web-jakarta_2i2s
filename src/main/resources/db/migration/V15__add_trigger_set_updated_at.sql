-- V15__add_trigger_set_updated_at.sql
-- Part IV §updated_at Trigger (shared function, applied per-table)
-- Applies only to tables with an updated_at column: secbret_user and scanned_url.
-- Tables without updated_at (scan_job, webhook_subscription, scan_result, user_report,
-- secbret_analysis, report_job, share_link) must NOT have this trigger.

CREATE OR REPLACE FUNCTION trg_set_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER set_scanned_url_updated_at
    BEFORE UPDATE ON scanned_url
    FOR EACH ROW EXECUTE FUNCTION trg_set_updated_at();

CREATE TRIGGER set_secbret_user_updated_at
    BEFORE UPDATE ON secbret_user
    FOR EACH ROW EXECUTE FUNCTION trg_set_updated_at();
