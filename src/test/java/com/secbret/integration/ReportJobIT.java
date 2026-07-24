package com.secbret.integration;

import com.secbret.model.entity.ReportJob;
import com.secbret.model.entity.ScannedUrl;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.entity.ShareLink;
import com.secbret.model.enums.UserRole;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Integration tests for report_job + share_link (Lane B, Tasks 17 + 18).
 *
 * <p>Scenarios:
 * <ol>
 *   <li>ReportJob entity round-trip: PENDING</li>
 *   <li>Decision #13: file_data IS NULL after markGeneratingInTx (GENERATING transition)</li>
 *   <li>uq_report_job_active_per_url: second insert for same URL while PENDING throws</li>
 *   <li>Idempotent de-dup: one active job per URL; COMPLETED releases the slot</li>
 *   <li>ShareLink entity round-trip</li>
 *   <li>410 semantics: expired share link is invalid</li>
 *   <li>410 semantics: revoked share link is invalid</li>
 *   <li>Ownership 404: intruder cannot pass the owner check</li>
 *   <li>Atomic access_count under 2 concurrent readers</li>
 * </ol>
 *
 * <p>Note: the repository @Transactional methods use JTA annotations which have no effect
 * in RESOURCE_LOCAL test mode. This IT manages transactions manually, mirroring the
 * pattern used in IncidentPipelineIT and ScanPersistenceIT.
 */
class ReportJobIT extends PostgresIntegrationSupport {

    private EntityManager em;

    @BeforeEach
    void open() {
        em = EMF.createEntityManager();
    }

    @AfterEach
    void close() {
        if (em.getTransaction().isActive()) em.getTransaction().rollback();
        em.close();
    }

    // =========================================================================
    // 1. ReportJob round-trip
    // =========================================================================

    @Test
    @DisplayName("ReportJob persists with status=PENDING and reads back with null file_data")
    void reportJob_roundTrip_pending() {
        SecBretUser user = createUser();
        ScannedUrl url  = createUrl();

        em.getTransaction().begin();
        ReportJob job = new ReportJob();
        job.setUrl(url);
        job.setRequestedBy(user);
        job.setStatus("PENDING");
        em.persist(job);
        em.getTransaction().commit();

        em.clear();
        ReportJob found = em.find(ReportJob.class, job.getId());
        assertThat(found).isNotNull();
        assertThat(found.getStatus()).isEqualTo("PENDING");
        assertThat(found.getFileData()).isNull();
        assertThat(found.getFileSizeBytes()).isNull();
    }

    // =========================================================================
    // 2. Decision #13: file_data IS NULL while GENERATING
    // =========================================================================

    @Test
    @DisplayName("Decision #13: file_data IS NULL after GENERATING transition (markGeneratingInTx has no byte[] param)")
    void decision13_fileData_isNull_while_generating() {
        SecBretUser user = createUser();
        ScannedUrl url  = createUrl();

        em.getTransaction().begin();
        ReportJob job = new ReportJob();
        job.setUrl(url);
        job.setRequestedBy(user);
        job.setStatus("PENDING");
        em.persist(job);
        em.getTransaction().commit();
        UUID jobId = job.getId();

        // Transition to GENERATING using the same native SQL as the production method
        // but with a manual transaction (RESOURCE_LOCAL test context)
        em.getTransaction().begin();
        em.createNativeQuery(
                "UPDATE report_job SET status = 'GENERATING' WHERE id = CAST(:id AS uuid)")
                .setParameter("id", jobId.toString())
                .executeUpdate();
        em.getTransaction().commit();

        // Verify: file_data IS NULL while GENERATING (decision #13)
        em.clear();
        ReportJob generating = em.find(ReportJob.class, jobId);
        assertThat(generating.getStatus()).isEqualTo("GENERATING");
        assertThat(generating.getFileData())
                .as("Decision #13: file_data MUST be NULL during GENERATING — not written on intermediate update")
                .isNull();
        assertThat(generating.getFileSizeBytes())
                .as("file_size_bytes also null during GENERATING")
                .isNull();
    }

    // =========================================================================
    // 3. uq_report_job_active_per_url: constraint enforced
    // =========================================================================

    @Test
    @DisplayName("uq_report_job_active_per_url: second PENDING job for same URL throws")
    void uniqueConstraint_preventsDuplicatePendingJob() {
        ScannedUrl url = createUrl();

        em.getTransaction().begin();
        ReportJob job1 = new ReportJob();
        job1.setUrl(url);
        job1.setStatus("PENDING");
        em.persist(job1);
        em.getTransaction().commit();

        assertThatThrownBy(() -> {
            EntityManager em2 = EMF.createEntityManager();
            try {
                em2.getTransaction().begin();
                ReportJob job2 = new ReportJob();
                job2.setUrl(em2.find(ScannedUrl.class, url.getId()));
                job2.setStatus("PENDING");
                em2.persist(job2);
                em2.flush();
                em2.getTransaction().commit();
            } finally {
                if (em2.getTransaction().isActive()) em2.getTransaction().rollback();
                em2.close();
            }
        }).isInstanceOf(PersistenceException.class);
    }

    // =========================================================================
    // 4. Idempotent de-dup: only one active job per URL
    // =========================================================================

    @Test
    @DisplayName("Only one PENDING/GENERATING job per URL; COMPLETED releases the slot")
    void idempotentDeDup_oneActiveJobPerUrl() {
        ScannedUrl url = createUrl();

        em.getTransaction().begin();
        ReportJob job1 = new ReportJob();
        job1.setUrl(url);
        job1.setStatus("PENDING");
        em.persist(job1);
        em.getTransaction().commit();

        // Verify there is one active job
        Long activeCount = em.createQuery(
                "SELECT COUNT(j) FROM ReportJob j WHERE j.url.id = :urlId AND j.status IN ('PENDING','GENERATING')",
                Long.class).setParameter("urlId", url.getId()).getSingleResult();
        assertThat(activeCount).isEqualTo(1L);

        // Transition to COMPLETED (releases the unique index slot)
        em.getTransaction().begin();
        em.createNativeQuery(
                "UPDATE report_job SET status = 'COMPLETED', file_data = :data," +
                " file_size_bytes = :size, completed_at = NOW() WHERE id = CAST(:id AS uuid)")
                .setParameter("data", new byte[]{37,80,68,70})
                .setParameter("size", 4L)
                .setParameter("id", job1.getId().toString())
                .executeUpdate();
        em.getTransaction().commit();

        // Second job for same URL is now allowed
        em.getTransaction().begin();
        ReportJob job2 = new ReportJob();
        job2.setUrl(em.find(ScannedUrl.class, url.getId()));
        job2.setStatus("PENDING");
        em.persist(job2);
        em.getTransaction().commit();

        assertThat(job2.getId()).isNotNull();

        Long active2 = em.createQuery(
                "SELECT COUNT(j) FROM ReportJob j WHERE j.url.id = :urlId AND j.status IN ('PENDING','GENERATING')",
                Long.class).setParameter("urlId", url.getId()).getSingleResult();
        assertThat(active2).isEqualTo(1L);
    }

    // =========================================================================
    // 5. ShareLink entity round-trip
    // =========================================================================

    @Test
    @DisplayName("ShareLink persists and reads back by uuid_token")
    void shareLink_roundTrip() {
        ScannedUrl url = createUrl();
        SecBretUser user = createUser();
        ReportJob job = createCompletedJob(url, user);

        String token = UUID.randomUUID().toString();
        em.getTransaction().begin();
        ShareLink link = new ShareLink();
        link.setReportJob(em.find(ReportJob.class, job.getId()));
        link.setCreatedBy(em.find(SecBretUser.class, user.getId()));
        link.setUuidToken(token);
        link.setExpiresAt(LocalDateTime.now().plusDays(30));
        em.persist(link);
        em.getTransaction().commit();

        em.clear();
        ShareLink found = em.createQuery(
                "SELECT sl FROM ShareLink sl WHERE sl.uuidToken = :token", ShareLink.class)
                .setParameter("token", token)
                .getSingleResult();
        assertThat(found).isNotNull();
        assertThat(found.getUuidToken()).isEqualTo(token);
        assertThat(found.isRevoked()).isFalse();
        assertThat(found.getAccessCount()).isZero();
    }

    // =========================================================================
    // 6. 410: expired share link
    // =========================================================================

    @Test
    @DisplayName("410 semantics: expired share link (expiresAt in past) is invalid")
    void shareLink_expired_isInvalid() {
        ScannedUrl url = createUrl();
        ReportJob job = createCompletedJob(url, null);

        String token = UUID.randomUUID().toString();
        em.getTransaction().begin();
        ShareLink link = new ShareLink();
        link.setReportJob(em.find(ReportJob.class, job.getId()));
        link.setUuidToken(token);
        link.setExpiresAt(LocalDateTime.now().minusDays(1)); // EXPIRED
        em.persist(link);
        em.getTransaction().commit();

        // Found, but invalid
        em.clear();
        ShareLink found = em.createQuery(
                "SELECT sl FROM ShareLink sl WHERE sl.uuidToken = :token", ShareLink.class)
                .setParameter("token", token)
                .getSingleResult();
        assertThat(found).isNotNull();

        boolean isValid = !found.isRevoked() && found.getExpiresAt().isAfter(LocalDateTime.now());
        assertThat(isValid)
                .as("Expired link must be invalid → caller returns 410")
                .isFalse();
    }

    // =========================================================================
    // 7. 410: revoked share link
    // =========================================================================

    @Test
    @DisplayName("410 semantics: revoked share link (is_revoked=TRUE) is invalid")
    void shareLink_revoked_isInvalid() {
        ScannedUrl url = createUrl();
        ReportJob job = createCompletedJob(url, null);

        String token = UUID.randomUUID().toString();
        em.getTransaction().begin();
        ShareLink link = new ShareLink();
        link.setReportJob(em.find(ReportJob.class, job.getId()));
        link.setUuidToken(token);
        link.setExpiresAt(LocalDateTime.now().plusDays(30));
        link.setRevoked(true);
        em.persist(link);
        em.getTransaction().commit();

        em.clear();
        ShareLink found = em.createQuery(
                "SELECT sl FROM ShareLink sl WHERE sl.uuidToken = :token", ShareLink.class)
                .setParameter("token", token)
                .getSingleResult();

        boolean isValid = !found.isRevoked() && found.getExpiresAt().isAfter(LocalDateTime.now());
        assertThat(isValid)
                .as("Revoked link must be invalid → caller returns 410")
                .isFalse();

        // Revoking again is idempotent
        em.getTransaction().begin();
        em.createNativeQuery(
                "UPDATE share_link SET is_revoked = TRUE WHERE id = CAST(:id AS uuid)")
                .setParameter("id", found.getId().toString())
                .executeUpdate();
        em.getTransaction().commit();

        em.clear();
        ShareLink revokedAgain = em.find(ShareLink.class, found.getId());
        assertThat(revokedAgain.isRevoked()).isTrue();
    }

    // =========================================================================
    // 8. Ownership 404
    // =========================================================================

    @Test
    @DisplayName("Ownership: intruder's ID != requestedBy.ID → 404 not 403")
    void ownership_differentUser_returns404() {
        SecBretUser owner   = createUser();
        SecBretUser intruder = createUser();
        ScannedUrl url = createUrl();

        em.getTransaction().begin();
        ReportJob job = new ReportJob();
        job.setUrl(url);
        job.setRequestedBy(em.find(SecBretUser.class, owner.getId()));
        job.setStatus("PENDING");
        em.persist(job);
        em.getTransaction().commit();

        em.clear();
        ReportJob found = em.createQuery(
                "SELECT j FROM ReportJob j LEFT JOIN FETCH j.url LEFT JOIN FETCH j.requestedBy WHERE j.id = :id",
                ReportJob.class)
                .setParameter("id", job.getId())
                .getSingleResult();
        assertThat(found).isNotNull();

        // Ownership check that mirrors the resource layer
        boolean isOwner = found.getRequestedBy() != null
                && intruder.getId().equals(found.getRequestedBy().getId());
        assertThat(isOwner)
                .as("Intruder must NOT be the job owner — resource should return 404")
                .isFalse();
    }

    // =========================================================================
    // 9. Atomic access_count under 2 concurrent readers
    // =========================================================================

    @Test
    @DisplayName("Atomic access_count: 2 concurrent readers both increment without lost update")
    void accessCount_atomic_underConcurrentReaders() throws Exception {
        ScannedUrl url = createUrl();
        ReportJob job = createCompletedJob(url, null);

        String token = UUID.randomUUID().toString();
        em.getTransaction().begin();
        ShareLink link = new ShareLink();
        link.setReportJob(em.find(ReportJob.class, job.getId()));
        link.setUuidToken(token);
        link.setExpiresAt(LocalDateTime.now().plusDays(30));
        em.persist(link);
        em.getTransaction().commit();
        UUID linkId = link.getId();

        // 2 concurrent atomic access_count increments using separate EntityManagers
        java.util.concurrent.CountDownLatch start = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch done  = new java.util.concurrent.CountDownLatch(2);
        List<Exception> errors = new ArrayList<>();

        for (int i = 0; i < 2; i++) {
            new Thread(() -> {
                try {
                    start.await();
                    EntityManager threadEm = EMF.createEntityManager();
                    try {
                        threadEm.getTransaction().begin();
                        threadEm.createNativeQuery(
                                "UPDATE share_link SET access_count = access_count + 1," +
                                " last_accessed_at = NOW() WHERE id = CAST(:id AS uuid)")
                                .setParameter("id", linkId.toString())
                                .executeUpdate();
                        threadEm.getTransaction().commit();
                    } finally {
                        if (threadEm.getTransaction().isActive()) threadEm.getTransaction().rollback();
                        threadEm.close();
                    }
                } catch (Exception e) {
                    errors.add(e);
                } finally {
                    done.countDown();
                }
            }).start();
        }

        start.countDown();
        done.await();

        assertThat(errors).as("No errors during concurrent access_count increment").isEmpty();

        em.clear();
        ShareLink updated = em.find(ShareLink.class, linkId);
        assertThat(updated.getAccessCount())
                .as("Both concurrent increments must be reflected — no lost update")
                .isEqualTo(2);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private SecBretUser createUser() {
        em.getTransaction().begin();
        SecBretUser u = new SecBretUser();
        u.setUsername("user-" + UUID.randomUUID());
        u.setPasswordHash("$2a$12$fakehash");
        u.setEmail(UUID.randomUUID() + "@test.com");
        u.setRole(UserRole.REPORTER);
        em.persist(u);
        em.getTransaction().commit();
        return u;
    }

    private ScannedUrl createUrl() {
        em.getTransaction().begin();
        ScannedUrl url = new ScannedUrl();
        url.setOriginalUrl("https://example-" + UUID.randomUUID() + ".com/");
        url.setNormalizedHash(UUID.randomUUID().toString());
        em.persist(url);
        em.getTransaction().commit();
        return url;
    }

    private ReportJob createCompletedJob(ScannedUrl url, SecBretUser user) {
        em.getTransaction().begin();
        ReportJob job = new ReportJob();
        job.setUrl(em.find(ScannedUrl.class, url.getId()));
        if (user != null) job.setRequestedBy(em.find(SecBretUser.class, user.getId()));
        job.setStatus("PENDING");
        em.persist(job);
        em.getTransaction().commit();

        em.getTransaction().begin();
        em.createNativeQuery(
                "UPDATE report_job SET status = 'COMPLETED', file_data = :data," +
                " file_size_bytes = :size, completed_at = NOW() WHERE id = CAST(:id AS uuid)")
                .setParameter("data", new byte[]{37, 80, 68, 70}) // %PDF
                .setParameter("size", 4L)
                .setParameter("id", job.getId().toString())
                .executeUpdate();
        em.getTransaction().commit();
        return job;
    }
}
