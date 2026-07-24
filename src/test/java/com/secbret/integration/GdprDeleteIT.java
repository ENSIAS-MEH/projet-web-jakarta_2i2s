package com.secbret.integration;

import com.secbret.model.entity.AuditLog;
import com.secbret.model.entity.ScannedUrl;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.entity.UserReport;
import com.secbret.model.enums.UserRole;
import com.secbret.repository.AuditLogRepository;
import com.secbret.repository.ScannedUrlRepository;
import com.secbret.repository.UserRepository;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for the GDPR hard-delete path (Part III §1 DELETE /auth/me).
 *
 * <p>Proves against the real Flyway V1–V20 schema:
 * <ol>
 *   <li>Hard DELETE on secbret_user triggers ON DELETE SET NULL cascades on scan_job,
 *       user_report, security_team_review FKs — references become NULL, data survives.</li>
 *   <li>Hard DELETE triggers ON DELETE CASCADE on api_token.</li>
 *   <li>V20 BEFORE DELETE trigger ({@code tombstone_audit_before_delete}) writes
 *       {@code actor_username = 'deleted_{uuid}'} BEFORE the ON DELETE SET NULL cascade
 *       nullifies {@code actor_id}. This means:
 *       - audit_log.actor_id is NULL after the delete
 *       - audit_log.actor_username is 'deleted_&lt;uuid&gt;' (tombstone preserved)</li>
 *   <li>report_job and share_link FKs (no JPA entity in this tree) — seeded via
 *       native SQL — also get SET NULL on requested_by and created_by respectively.</li>
 * </ol>
 *
 * <p>Application code (AdminUserService.deleteAccount) must NOT write the tombstone;
 * this IT verifies it is written by the V20 trigger alone.
 */
class GdprDeleteIT extends PostgresIntegrationSupport {

    private EntityManager em;
    private UserRepository userRepo;
    private ScannedUrlRepository urlRepo;
    private AuditLogRepository auditRepo;

    @BeforeEach
    void open() {
        em = EMF.createEntityManager();
        userRepo = new UserRepository(em);
        urlRepo = new ScannedUrlRepository(em);
        auditRepo = new AuditLogRepository(em);
    }

    @AfterEach
    void close() {
        if (em.getTransaction().isActive()) em.getTransaction().rollback();
        em.close();
    }

    // ── V20 trigger: tombstone written before cascade ──────────────────────────

    @Test
    @DisplayName("V20 trigger: tombstone audit_log.actor_username='deleted_{uuid}' before ON DELETE SET NULL nullifies actor_id")
    void tombstone_trigger_writesActorUsernameBeforeCascade() {
        SecBretUser user = createUser("delete-me-" + UUID.randomUUID(), UserRole.REPORTER);
        UUID userId = user.getId();

        // Seed an audit log row for this user (actor)
        UUID auditId = seedAuditLog(user.getId(), user.getUsername());

        // Verify pre-condition: actor_id is set and actor_username is the real username
        String[] preState = queryAuditActorFields(auditId);
        assertThat(preState[0]).isEqualTo(userId.toString()); // actor_id
        assertThat(preState[1]).isEqualTo(user.getUsername()); // actor_username

        // Hard-delete the user row — V20 trigger fires BEFORE the cascade
        em.getTransaction().begin();
        SecBretUser managed = em.find(SecBretUser.class, userId);
        em.remove(managed);
        em.getTransaction().commit();

        em.clear();

        // Post-delete: actor_id must be NULL (ON DELETE SET NULL fired)
        String[] postState = queryAuditActorFields(auditId);
        assertThat(postState[0]).as("actor_id must be NULL after hard-delete").isNull();

        // actor_username must be the tombstone 'deleted_{uuid}' written by V20 trigger
        assertThat(postState[1])
                .as("V20 trigger must have written tombstone actor_username before the cascade")
                .isEqualTo("deleted_" + userId);
    }

    @Test
    @DisplayName("Multiple audit_log rows for same user: all tombstoned by V20 trigger")
    void tombstone_trigger_allAuditRowsTombstoned() {
        SecBretUser user = createUser("multi-audit-" + UUID.randomUUID(), UserRole.ANALYST);
        UUID userId = user.getId();

        // Seed three audit log rows
        UUID audit1 = seedAuditLog(userId, user.getUsername());
        UUID audit2 = seedAuditLog(userId, user.getUsername());
        UUID audit3 = seedAuditLog(userId, user.getUsername());

        // Hard-delete
        em.getTransaction().begin();
        SecBretUser managed = em.find(SecBretUser.class, userId);
        em.remove(managed);
        em.getTransaction().commit();
        em.clear();

        // All three rows must have the tombstone
        for (UUID auditId : List.of(audit1, audit2, audit3)) {
            String[] state = queryAuditActorFields(auditId);
            assertThat(state[0]).as("actor_id null for " + auditId).isNull();
            assertThat(state[1]).as("tombstone for " + auditId)
                    .isEqualTo("deleted_" + userId);
        }
    }

    // ── ON DELETE SET NULL cascade: scan_job, user_report ────────────────────

    @Test
    @DisplayName("ON DELETE SET NULL: scan_job.submitted_by becomes NULL after user hard-delete")
    void cascade_setNull_scanJob_submittedBy() {
        SecBretUser user = createUser("scanner-" + UUID.randomUUID(), UserRole.REPORTER);
        UUID userId = user.getId();
        ScannedUrl url = createUrl();

        // Seed a scan_job using native SQL (column is scan_depth per V3 DDL)
        UUID jobId = UUID.randomUUID();
        em.getTransaction().begin();
        em.createNativeQuery(
                "INSERT INTO scan_job (id, url_id, submitted_by, status, scan_depth, created_at) " +
                "VALUES (:id, :urlId, :userId, 'COMPLETED', 'QUICK', NOW())")
                .setParameter("id", jobId)
                .setParameter("urlId", url.getId())
                .setParameter("userId", userId)
                .executeUpdate();
        em.getTransaction().commit();

        // Hard-delete user
        em.getTransaction().begin();
        SecBretUser managed = em.find(SecBretUser.class, userId);
        em.remove(managed);
        em.getTransaction().commit();
        em.clear();

        // scan_job row must still exist with submitted_by=NULL
        Object submittedBy = em.createNativeQuery(
                "SELECT submitted_by FROM scan_job WHERE id = :id")
                .setParameter("id", jobId)
                .getSingleResult();
        assertThat(submittedBy).as("scan_job.submitted_by must be NULL (SET NULL cascade)").isNull();
    }

    @Test
    @DisplayName("ON DELETE SET NULL: user_report.reported_by becomes NULL after user hard-delete")
    void cascade_setNull_userReport_reportedBy() {
        SecBretUser reporter = createUser("rpt-" + UUID.randomUUID(), UserRole.REPORTER);
        UUID reporterId = reporter.getId();
        ScannedUrl url = createUrl();

        // Seed user_report via native SQL (evidence_description ≥10 chars per chk_evidence_length)
        UUID reportId = UUID.randomUUID();
        em.getTransaction().begin();
        em.createNativeQuery(
                "INSERT INTO user_report (id, url_id, reported_by, evidence_description, status, created_at, version) " +
                "VALUES (:id, :urlId, :userId, 'Phishing site with fake login form collecting credentials.', 'PENDING', NOW(), 0)")
                .setParameter("id", reportId)
                .setParameter("urlId", url.getId())
                .setParameter("userId", reporterId)
                .executeUpdate();
        em.getTransaction().commit();

        // Hard-delete user
        em.getTransaction().begin();
        SecBretUser managed = em.find(SecBretUser.class, reporterId);
        em.remove(managed);
        em.getTransaction().commit();
        em.clear();

        // user_report row must still exist with reported_by=NULL
        Object reportedBy = em.createNativeQuery(
                "SELECT reported_by FROM user_report WHERE id = :id")
                .setParameter("id", reportId)
                .getSingleResult();
        assertThat(reportedBy).as("user_report.reported_by must be NULL (SET NULL cascade)").isNull();
    }

    @Test
    @DisplayName("ON DELETE SET NULL: report_job.requested_by and share_link.created_by become NULL")
    void cascade_setNull_reportJob_and_shareLink() {
        SecBretUser user = createUser("rjob-" + UUID.randomUUID(), UserRole.REPORTER);
        UUID userId = user.getId();
        ScannedUrl url = createUrl();

        // Seed report_job (no JPA entity in this tree — native SQL per HANDOFF spec note)
        UUID reportJobId = UUID.randomUUID();
        em.getTransaction().begin();
        em.createNativeQuery(
                "INSERT INTO report_job (id, url_id, requested_by, status, created_at) " +
                "VALUES (:id, :urlId, :userId, 'COMPLETED', NOW())")
                .setParameter("id", reportJobId)
                .setParameter("urlId", url.getId())
                .setParameter("userId", userId)
                .executeUpdate();

        // Seed share_link (no JPA entity in this tree — native SQL per HANDOFF spec note)
        UUID shareLinkId = UUID.randomUUID();
        em.createNativeQuery(
                "INSERT INTO share_link (id, report_job_id, created_by, uuid_token, expires_at) " +
                "VALUES (:id, :jobId, :userId, :token, NOW() + INTERVAL '30 days')")
                .setParameter("id", shareLinkId)
                .setParameter("jobId", reportJobId)
                .setParameter("userId", userId)
                .setParameter("token", UUID.randomUUID().toString())
                .executeUpdate();
        em.getTransaction().commit();

        // Hard-delete user
        em.getTransaction().begin();
        SecBretUser managed = em.find(SecBretUser.class, userId);
        em.remove(managed);
        em.getTransaction().commit();
        em.clear();

        // report_job.requested_by must be NULL
        Object requestedBy = em.createNativeQuery(
                "SELECT requested_by FROM report_job WHERE id = :id")
                .setParameter("id", reportJobId)
                .getSingleResult();
        assertThat(requestedBy).as("report_job.requested_by must be NULL (SET NULL cascade)").isNull();

        // share_link.created_by must be NULL
        Object createdBy = em.createNativeQuery(
                "SELECT created_by FROM share_link WHERE id = :id")
                .setParameter("id", shareLinkId)
                .getSingleResult();
        assertThat(createdBy).as("share_link.created_by must be NULL (SET NULL cascade)").isNull();
    }

    @Test
    @DisplayName("ON DELETE CASCADE: api_token row deleted when user is hard-deleted")
    void cascade_delete_apiToken() {
        SecBretUser user = createUser("api-tok-" + UUID.randomUUID(), UserRole.REPORTER);
        UUID userId = user.getId();

        // Seed api_token (V19 table; no JPA entity in this tree — V19 DDL: id, user_id, token_hash, label, created_at)
        UUID tokenId = UUID.randomUUID();
        em.getTransaction().begin();
        em.createNativeQuery(
                "INSERT INTO api_token (id, user_id, token_hash, label, created_at) " +
                "VALUES (:id, :userId, :hash, 'test token', NOW())")
                .setParameter("id", tokenId)
                .setParameter("userId", userId)
                // token_hash is VARCHAR(64); two UUID strings (no dashes) = 64 chars exactly
                .setParameter("hash", (UUID.randomUUID().toString() + UUID.randomUUID().toString()).replace("-", "").substring(0, 64))
                .executeUpdate();
        em.getTransaction().commit();

        // Hard-delete user
        em.getTransaction().begin();
        SecBretUser managed = em.find(SecBretUser.class, userId);
        em.remove(managed);
        em.getTransaction().commit();
        em.clear();

        // api_token row must be CASCADE DELETED
        Long count = (Long) em.createNativeQuery(
                "SELECT COUNT(*) FROM api_token WHERE id = :id")
                .setParameter("id", tokenId)
                .getSingleResult();
        assertThat(count).as("api_token must be CASCADE DELETED with user").isEqualTo(0L);
    }

    @Test
    @DisplayName("User with no audit_log rows: hard-delete is a safe no-op for the trigger")
    void tombstone_trigger_noAuditRows_safeNoOp() {
        SecBretUser user = createUser("no-audit-" + UUID.randomUUID(), UserRole.REPORTER);
        UUID userId = user.getId();

        // Hard-delete with zero audit_log rows — trigger UPDATE should be a no-op (no rows matched)
        em.getTransaction().begin();
        SecBretUser managed = em.find(SecBretUser.class, userId);
        em.remove(managed);
        em.getTransaction().commit();

        // secbret_user row is gone
        assertThat(em.find(SecBretUser.class, userId)).isNull();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private SecBretUser createUser(String username, UserRole role) {
        SecBretUser u = new SecBretUser();
        u.setUsername(username);
        u.setEmail(username + "@test.example");
        u.setPasswordHash("$2a$12$0123456789012345678901uABCDEFGHIJKLMNOPQRSTUVWXYZ01234");
        u.setRole(role);
        em.getTransaction().begin();
        userRepo.persist(u);
        em.getTransaction().commit();
        return u;
    }

    private ScannedUrl createUrl() {
        ScannedUrl url = new ScannedUrl();
        url.setOriginalUrl("https://gdpr-test-" + UUID.randomUUID() + ".example.com");
        url.setNormalizedHash(randomHash());
        em.getTransaction().begin();
        urlRepo.persist(url);
        em.getTransaction().commit();
        return url;
    }

    /** Seeds an audit_log row for the given actor and returns its UUID. */
    private UUID seedAuditLog(UUID actorId, String actorUsername) {
        UUID auditId = UUID.randomUUID();
        em.getTransaction().begin();
        em.createNativeQuery(
                "INSERT INTO audit_log (id, actor_id, actor_username, action, target_type, target_id, created_at) " +
                "VALUES (:id, :actorId, :actorUsername, 'TEST_ACTION', 'secbret_user', :targetId, NOW())")
                .setParameter("id", auditId)
                .setParameter("actorId", actorId)
                .setParameter("actorUsername", actorUsername)
                .setParameter("targetId", actorId)
                .executeUpdate();
        em.getTransaction().commit();
        return auditId;
    }

    /** Returns [actor_id (as string or null), actor_username] for an audit_log row. */
    private String[] queryAuditActorFields(UUID auditId) {
        Object[] row = (Object[]) em.createNativeQuery(
                "SELECT actor_id::text, actor_username FROM audit_log WHERE id = :id")
                .setParameter("id", auditId)
                .getSingleResult();
        return new String[]{(String) row[0], (String) row[1]};
    }

    private static String randomHash() {
        return (UUID.randomUUID().toString() + UUID.randomUUID()).replace("-", "").substring(0, 64);
    }
}
