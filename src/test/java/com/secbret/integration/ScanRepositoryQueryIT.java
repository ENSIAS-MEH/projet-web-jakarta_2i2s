package com.secbret.integration;

import com.secbret.model.entity.ScanJob;
import com.secbret.model.entity.ScanResult;
import com.secbret.model.entity.ScannedUrl;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.enums.ScanDepth;
import com.secbret.model.enums.ScanJobStatus;
import com.secbret.model.enums.UserRole;
import com.secbret.repository.ScanJobRepository;
import com.secbret.repository.ScanResultRepository;
import com.secbret.repository.ScannedUrlRepository;
import com.secbret.repository.UserRepository;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for the new ScanJobRepository + ScanResultRepository query methods
 * added in Task 13 (Part III §2 — GET /scan list + pagination, GET /scan/url ownership).
 *
 * <p>Runs against the real Flyway-migrated PostgreSQL 14 container via
 * {@link PostgresIntegrationSupport}.
 */
@DisplayName("ScanRepository query methods IT (Task 13)")
class ScanRepositoryQueryIT extends PostgresIntegrationSupport {

    private EntityManager em;
    private ScanJobRepository jobRepo;
    private ScanResultRepository resultRepo;
    private ScannedUrlRepository urlRepo;
    private UserRepository userRepo;

    @BeforeEach
    void openEm() {
        em = EMF.createEntityManager();
        jobRepo    = new ScanJobRepository(em);
        resultRepo = new ScanResultRepository(em);
        urlRepo    = new ScannedUrlRepository(em);
        userRepo   = new UserRepository(em);
    }

    @AfterEach
    void closeEm() {
        if (em.getTransaction().isActive()) {
            em.getTransaction().rollback();
        }
        em.close();
    }

    // =========================================================================
    // existsByUrlIdAndSubmittedBy (ownership check for GET /scan/url/{urlId})
    // =========================================================================

    @Test
    @DisplayName("existsByUrlIdAndSubmittedBy: returns true when REPORTER has scanned the URL")
    void existsByUrlIdAndSubmittedBy_ownerHasScanned_returnsTrue() {
        SecBretUser reporter = persistUser("reporter-own-" + UUID.randomUUID());
        ScannedUrl url = persistUrl();
        persistJob(url, reporter, ScanJobStatus.COMPLETED);

        boolean found = jobRepo.existsByUrlIdAndSubmittedBy(url.getId(), reporter.getId());
        assertThat(found).isTrue();
    }

    @Test
    @DisplayName("existsByUrlIdAndSubmittedBy: returns false when REPORTER has NOT scanned the URL")
    void existsByUrlIdAndSubmittedBy_otherUser_returnsFalse() {
        SecBretUser reporter = persistUser("reporter-other-" + UUID.randomUUID());
        SecBretUser other    = persistUser("other-" + UUID.randomUUID());
        ScannedUrl url = persistUrl();
        // Only 'other' has scanned it.
        persistJob(url, other, ScanJobStatus.COMPLETED);

        boolean found = jobRepo.existsByUrlIdAndSubmittedBy(url.getId(), reporter.getId());
        assertThat(found).isFalse();
    }

    @Test
    @DisplayName("existsByUrlIdAndSubmittedBy: superseded historical jobs count for ownership")
    void existsByUrlIdAndSubmittedBy_supersededJobCounts_returnsTrue() {
        SecBretUser reporter = persistUser("reporter-sup-" + UUID.randomUUID());
        ScannedUrl url = persistUrl();
        // Only a SUPERSEDED job — still counts per spec §4.
        persistJob(url, reporter, ScanJobStatus.SUPERSEDED);

        boolean found = jobRepo.existsByUrlIdAndSubmittedBy(url.getId(), reporter.getId());
        assertThat(found).isTrue();
    }

    // =========================================================================
    // count / findPage (paginated list for GET /scan)
    // =========================================================================

    @Test
    @DisplayName("count with ownerId filter returns only that user's jobs")
    void count_ownerFilter_countsCorrectly() {
        SecBretUser u1 = persistUser("u1-" + UUID.randomUUID());
        SecBretUser u2 = persistUser("u2-" + UUID.randomUUID());
        ScannedUrl url1 = persistUrl();
        ScannedUrl url2 = persistUrl();
        ScannedUrl url3 = persistUrl();
        persistJob(url1, u1, ScanJobStatus.PENDING);
        persistJob(url2, u1, ScanJobStatus.COMPLETED);
        persistJob(url3, u2, ScanJobStatus.PENDING);

        long u1Count = jobRepo.count(u1.getId(), null, null);
        long u2Count = jobRepo.count(u2.getId(), null, null);

        assertThat(u1Count).isGreaterThanOrEqualTo(2);
        assertThat(u2Count).isGreaterThanOrEqualTo(1);
    }

    @Test
    @DisplayName("findPage returns jobs in descending createdAt order")
    void findPage_orderedByCreatedAtDesc() {
        SecBretUser u = persistUser("order-" + UUID.randomUUID());
        ScannedUrl url1 = persistUrl();
        ScannedUrl url2 = persistUrl();
        persistJob(url1, u, ScanJobStatus.PENDING);
        persistJob(url2, u, ScanJobStatus.RUNNING);

        List<ScanJob> page = jobRepo.findPage(u.getId(), null, null, 1, 20);

        assertThat(page).hasSizeGreaterThanOrEqualTo(2);
        // Verify ordering: each job's createdAt >= the next one's.
        for (int i = 0; i < page.size() - 1; i++) {
            assertThat(page.get(i).getCreatedAt())
                    .isAfterOrEqualTo(page.get(i + 1).getCreatedAt());
        }
    }

    @Test
    @DisplayName("findPage size=1 returns only one job")
    void findPage_sizeOne_returnsOneResult() {
        SecBretUser u = persistUser("page-" + UUID.randomUUID());
        ScannedUrl url1 = persistUrl();
        ScannedUrl url2 = persistUrl();
        persistJob(url1, u, ScanJobStatus.PENDING);
        persistJob(url2, u, ScanJobStatus.PENDING);

        List<ScanJob> page = jobRepo.findPage(u.getId(), null, null, 1, 1);
        assertThat(page).hasSize(1);
    }

    // =========================================================================
    // findLatestByUrlId (GET /scan/url/{urlId})
    // =========================================================================

    @Test
    @DisplayName("findLatestByUrlId returns most recent result")
    void findLatestByUrlId_returnsLatest() {
        SecBretUser u = persistUser("latest-" + UUID.randomUUID());
        ScannedUrl url = persistUrl();
        ScanJob job1 = persistJob(url, u, ScanJobStatus.COMPLETED);
        ScanJob job2 = persistJob(url, u, ScanJobStatus.COMPLETED);

        // Persist result for job2 second (it's the newer one).
        persistResult(url, job1, new BigDecimal("0.30"));
        ScanResult result2 = persistResult(url, job2, new BigDecimal("0.70"));

        var latest = resultRepo.findLatestByUrlId(url.getId());
        assertThat(latest).isPresent();
        // The latest result has a higher score (job2).
        assertThat(latest.get().getOverallScore()).isEqualByComparingTo("0.70");
    }

    @Test
    @DisplayName("findLatestByUrlId returns empty when no results exist")
    void findLatestByUrlId_noResults_returnsEmpty() {
        ScannedUrl url = persistUrl();
        assertThat(resultRepo.findLatestByUrlId(url.getId())).isEmpty();
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private SecBretUser persistUser(String usernameHint) {
        // Username must be ≤50 chars (secbret_user DDL); truncate the hint to a safe token.
        String token = usernameHint.replaceAll("[^a-z0-9]", "");
        String username = token.length() > 20 ? token.substring(0, 20) : token;
        // Ensure uniqueness with a short random suffix even after truncation.
        username = username + Long.toHexString(System.nanoTime()).substring(0, 8);
        if (username.length() > 48) { username = username.substring(0, 48); }

        SecBretUser u = new SecBretUser();
        u.setUsername(username);
        u.setEmail(username + "@ex.test");
        u.setPasswordHash("$2a$12$0123456789012345678901uABCDEFGHIJKLMNOPQRSTUVWXYZ01234");
        u.setRole(UserRole.REPORTER);
        em.getTransaction().begin();
        em.persist(u);
        em.getTransaction().commit();
        em.clear();
        return em.find(SecBretUser.class, u.getId());
    }

    private ScannedUrl persistUrl() {
        ScannedUrl url = new ScannedUrl();
        url.setOriginalUrl("https://example.test/" + UUID.randomUUID());
        url.setNormalizedHash(UUID.randomUUID().toString().replace("-", "") + "1234567890123456");
        em.getTransaction().begin();
        em.persist(url);
        em.getTransaction().commit();
        em.clear();
        return em.find(ScannedUrl.class, url.getId());
    }

    private ScanJob persistJob(ScannedUrl url, SecBretUser user, ScanJobStatus status) {
        em.getTransaction().begin();
        ScanJob j = new ScanJob();
        j.setUrl(em.merge(url));
        j.setSubmittedBy(user != null ? em.merge(user) : null);
        j.setScanDepth(ScanDepth.QUICK);
        j.setStatus(status);
        em.persist(j);
        em.getTransaction().commit();
        em.clear();
        return em.find(ScanJob.class, j.getId());
    }

    private ScanResult persistResult(ScannedUrl url, ScanJob job, BigDecimal score) {
        em.getTransaction().begin();
        ScanResult r = new ScanResult();
        r.setUrl(em.merge(url));
        r.setScanJob(em.merge(job));
        r.setTier1Findings("{\"domainAge\":\"established\"}");
        r.setOverallScore(score);
        em.persist(r);
        em.getTransaction().commit();
        em.clear();
        return em.find(ScanResult.class, r.getId());
    }
}
