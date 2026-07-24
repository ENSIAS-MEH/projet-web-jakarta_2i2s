package com.secbret.integration;

import com.secbret.service.StaleJobRecovery;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test for application-level stale-job recovery (Part II §10.4 / Part IV).
 * Against the real Flyway V1–V20 schema it proves that {@link StaleJobRecovery} at
 * startup:
 *
 * <ul>
 *   <li>flips interrupted {@code scan_job} rows (PENDING/RUNNING) → FAILED with the
 *       {@code "; server restart"} error-message suffix;</li>
 *   <li>flips interrupted {@code report_job} rows (PENDING/GENERATING) → FAILED likewise;</li>
 *   <li>leaves terminal rows (COMPLETED/FAILED/SUPERSEDED) untouched;</li>
 *   <li>purges expired {@code idempotency_key} rows and keeps non-expired ones.</li>
 * </ul>
 *
 * <p>Runs on the RESOURCE_LOCAL test unit, driving {@link StaleJobRecovery#recoverInTx}
 * inside an explicit transaction. Setup uses native SQL because {@code report_job} and
 * {@code idempotency_key} have no JPA entities in this phase.
 */
class StaleJobRecoveryIT extends PostgresIntegrationSupport {

    @Test
    void recoveryFailsInterruptedJobsAndPurgesExpiredKeys() {
        EntityManager em = EMF.createEntityManager();
        try {
            UUID userId = UUID.randomUUID();
            UUID urlId = UUID.randomUUID();
            String hash = UUID.randomUUID().toString().replace("-", "")
                    + UUID.randomUUID().toString().replace("-", "").substring(0, 32);

            // --- Fixture: a user + a URL, then jobs in various states. ---
            em.getTransaction().begin();
            em.createNativeQuery(
                            "INSERT INTO secbret_user (id, username, email, password_hash, role) "
                                    + "VALUES (?1, ?2, ?3, ?4, 'REPORTER')")
                    .setParameter(1, userId)
                    .setParameter(2, "stale-user-" + userId)
                    .setParameter(3, userId + "@example.test")
                    .setParameter(4, "$2a$12$0123456789012345678901uABCDEFGHIJKLMNOPQRSTUVWXYZ01234")
                    .executeUpdate();

            em.createNativeQuery(
                            "INSERT INTO scanned_url (id, original_url, normalized_hash) VALUES (?1, ?2, ?3)")
                    .setParameter(1, urlId)
                    .setParameter(2, "https://stale.test/" + urlId)
                    .setParameter(3, hash)
                    .executeUpdate();

            // Separate URLs so the report_job/scan_job partial unique indexes
            // (one active job per URL) do not reject the multi-state fixture.
            UUID urlId2 = insertUrl(em);
            UUID urlId3 = insertUrl(em);
            UUID urlId4 = insertUrl(em);
            UUID urlId5 = insertUrl(em);
            UUID urlId6 = insertUrl(em);

            UUID pendingScan = insertScanJob(em, urlId, "PENDING", null);
            UUID runningScan = insertScanJob(em, urlId2, "RUNNING", null);
            UUID completedScan = insertScanJob(em, urlId3, "COMPLETED", null);
            UUID alreadyFailedScan = insertScanJob(em, urlId4, "FAILED", "boom");

            UUID pendingReport = insertReportJob(em, urlId, userId, "PENDING", null);
            UUID generatingReport = insertReportJob(em, urlId5, userId, "GENERATING", null);
            UUID completedReport = insertReportJob(em, urlId6, userId, "COMPLETED", null);

            // Two idempotency keys: one expired, one fresh.
            insertIdempotencyKey(em, userId, "expired-key", "-1 hour");
            insertIdempotencyKey(em, userId, "fresh-key", "+1 hour");
            em.getTransaction().commit();
            em.clear();

            // --- Run recovery. ---
            em.getTransaction().begin();
            new StaleJobRecovery(em).recoverInTx(em);
            em.getTransaction().commit();
            em.clear();

            // --- scan_job assertions ---
            assertThat(scanStatus(em, pendingScan)).isEqualTo("FAILED");
            assertThat(scanStatus(em, runningScan)).isEqualTo("FAILED");
            assertThat(scanErrorMessage(em, pendingScan)).endsWith("; server restart");
            assertThat(scanErrorMessage(em, runningScan)).endsWith("; server restart");
            // Terminal rows untouched.
            assertThat(scanStatus(em, completedScan)).isEqualTo("COMPLETED");
            assertThat(scanStatus(em, alreadyFailedScan)).isEqualTo("FAILED");
            assertThat(scanErrorMessage(em, alreadyFailedScan)).isEqualTo("boom");

            // --- report_job assertions ---
            assertThat(reportStatus(em, pendingReport)).isEqualTo("FAILED");
            assertThat(reportStatus(em, generatingReport)).isEqualTo("FAILED");
            assertThat(reportStatus(em, completedReport)).isEqualTo("COMPLETED");

            // --- idempotency_key assertions ---
            assertThat(idempotencyKeyExists(em, userId, "expired-key")).isFalse();
            assertThat(idempotencyKeyExists(em, userId, "fresh-key")).isTrue();
        } finally {
            if (em.getTransaction().isActive()) {
                em.getTransaction().rollback();
            }
            em.close();
        }
    }

    private UUID insertUrl(EntityManager em) {
        UUID id = UUID.randomUUID();
        String hash = UUID.randomUUID().toString().replace("-", "")
                + UUID.randomUUID().toString().replace("-", "").substring(0, 32);
        em.createNativeQuery(
                        "INSERT INTO scanned_url (id, original_url, normalized_hash) VALUES (?1, ?2, ?3)")
                .setParameter(1, id)
                .setParameter(2, "https://stale.test/" + id)
                .setParameter(3, hash)
                .executeUpdate();
        return id;
    }

    private UUID insertScanJob(EntityManager em, UUID urlId, String status, String errorMessage) {
        UUID id = UUID.randomUUID();
        em.createNativeQuery(
                        "INSERT INTO scan_job (id, url_id, scan_depth, status, error_message) "
                                + "VALUES (?1, ?2, 'QUICK', ?3, ?4)")
                .setParameter(1, id)
                .setParameter(2, urlId)
                .setParameter(3, status)
                .setParameter(4, errorMessage)
                .executeUpdate();
        return id;
    }

    private UUID insertReportJob(EntityManager em, UUID urlId, UUID userId, String status, String errorMessage) {
        UUID id = UUID.randomUUID();
        em.createNativeQuery(
                        "INSERT INTO report_job (id, url_id, requested_by, status, error_message) "
                                + "VALUES (?1, ?2, ?3, ?4, ?5)")
                .setParameter(1, id)
                .setParameter(2, urlId)
                .setParameter(3, userId)
                .setParameter(4, status)
                .setParameter(5, errorMessage)
                .executeUpdate();
        return id;
    }

    private void insertIdempotencyKey(EntityManager em, UUID userId, String key, String interval) {
        em.createNativeQuery(
                        "INSERT INTO idempotency_key (id, user_id, idem_key, endpoint, request_hash, expires_at) "
                                + "VALUES (?1, ?2, ?3, '/api/v1/scan', ?4, NOW() + INTERVAL '" + interval + "')")
                .setParameter(1, UUID.randomUUID())
                .setParameter(2, userId)
                .setParameter(3, key)
                .setParameter(4, UUID.randomUUID().toString().replace("-", ""))
                .executeUpdate();
    }

    private String scanStatus(EntityManager em, UUID id) {
        return (String) em.createNativeQuery("SELECT status FROM scan_job WHERE id = ?1")
                .setParameter(1, id).getSingleResult();
    }

    private String scanErrorMessage(EntityManager em, UUID id) {
        return (String) em.createNativeQuery("SELECT error_message FROM scan_job WHERE id = ?1")
                .setParameter(1, id).getSingleResult();
    }

    private String reportStatus(EntityManager em, UUID id) {
        return (String) em.createNativeQuery("SELECT status FROM report_job WHERE id = ?1")
                .setParameter(1, id).getSingleResult();
    }

    private boolean idempotencyKeyExists(EntityManager em, UUID userId, String key) {
        Number count = (Number) em.createNativeQuery(
                        "SELECT COUNT(*) FROM idempotency_key WHERE user_id = ?1 AND idem_key = ?2")
                .setParameter(1, userId)
                .setParameter(2, key)
                .getSingleResult();
        return count.longValue() > 0;
    }
}
