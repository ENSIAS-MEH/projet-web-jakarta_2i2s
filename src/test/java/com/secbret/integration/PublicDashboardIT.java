package com.secbret.integration;

import com.secbret.model.entity.ScanJob;
import com.secbret.model.entity.ScanResult;
import com.secbret.model.entity.ScannedUrl;
import com.secbret.model.enums.CommunityVerdict;
import com.secbret.model.enums.ScanDepth;
import com.secbret.model.enums.ScanJobStatus;
import com.secbret.repository.ScannedUrlRepository;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for ScannedUrlRepository public dashboard queries (Part III §7 / Task 14).
 *
 * <p>Seeds several scanned_url rows:
 * <ul>
 *   <li>urlMalicious — community_verdict=MALICIOUS, not deleted</li>
 *   <li>urlBenign    — community_verdict=BENIGN, not deleted</li>
 *   <li>urlUnknown   — community_verdict=UNKNOWN, not deleted (excluded from dashboard)</li>
 *   <li>urlDeleted   — community_verdict=MALICIOUS but deleted_at set (excluded)</li>
 *   <li>urlNull      — community_verdict=NULL (excluded)</li>
 * </ul>
 *
 * Asserts that:
 * - countPublicDashboard returns only the MALICIOUS+BENIGN non-deleted rows
 * - findPublicDashboardPage returns them newest-first by last_scanned_at
 * - verdict filter (MALICIOUS / BENIGN) works correctly
 * - findPublicDashboardByHash works and excludes deleted/unknown rows
 */
@DisplayName("PublicDashboard repository queries IT (Task 14)")
class PublicDashboardIT extends PostgresIntegrationSupport {

    private EntityManager em;
    private ScannedUrlRepository repo;

    @BeforeEach
    void openEm() {
        em = EMF.createEntityManager();
        repo = new ScannedUrlRepository(em);
    }

    @AfterEach
    void closeEm() {
        if (em.getTransaction().isActive()) {
            em.getTransaction().rollback();
        }
        em.close();
    }

    // =========================================================================
    // count
    // =========================================================================

    @Test
    @DisplayName("countPublicDashboard excludes NULL, UNKNOWN, and deleted rows")
    void count_excludesNullUnknownAndDeleted() {
        Fixture f = seed();

        long all = repo.countPublicDashboard(null);
        // Must include MALICIOUS + BENIGN (non-deleted) but not UNKNOWN, NULL, or deleted.
        assertThat(all).isGreaterThanOrEqualTo(2);
        // The two clearly-excluded rows (deleted MALICIOUS + UNKNOWN) should not bump the count.
        long malicious = repo.countPublicDashboard(CommunityVerdict.MALICIOUS);
        long benign    = repo.countPublicDashboard(CommunityVerdict.BENIGN);
        assertThat(malicious).isGreaterThanOrEqualTo(1);
        assertThat(benign).isGreaterThanOrEqualTo(1);
        assertThat(malicious + benign).isEqualTo(all);
    }

    @Test
    @DisplayName("countPublicDashboard with MALICIOUS filter excludes BENIGN")
    void count_maliciousFilter_excludesBenign() {
        Fixture f = seed();

        long maliciousOnly = repo.countPublicDashboard(CommunityVerdict.MALICIOUS);
        long benignOnly    = repo.countPublicDashboard(CommunityVerdict.BENIGN);
        assertThat(maliciousOnly).isGreaterThanOrEqualTo(1);
        assertThat(benignOnly).isGreaterThanOrEqualTo(1);
        // They must be disjoint sets.
        assertThat(repo.countPublicDashboard(null)).isEqualTo(maliciousOnly + benignOnly);
    }

    // =========================================================================
    // findPublicDashboardPage ordering
    // =========================================================================

    @Test
    @DisplayName("findPublicDashboardPage returns newest last_scanned_at first, excludes deleted/UNKNOWN/NULL")
    void findPage_orderingAndFiltering() {
        Fixture f = seed();

        List<ScannedUrl> page = repo.findPublicDashboardPage(null, 1, 50);

        // Should contain MALICIOUS (non-deleted) and BENIGN — not deleted, not UNKNOWN, not null.
        List<UUID> ids = page.stream().map(ScannedUrl::getId).toList();
        assertThat(ids).contains(f.maliciousId, f.benignId);
        assertThat(ids).doesNotContain(f.deletedId, f.unknownId, f.nullVerdictId);

        // Ordering: last_scanned_at DESC NULLS LAST.
        for (int i = 0; i < page.size() - 1; i++) {
            LocalDateTime a = page.get(i).getLastScannedAt();
            LocalDateTime b = page.get(i + 1).getLastScannedAt();
            if (a != null && b != null) {
                assertThat(a).isAfterOrEqualTo(b);
            } else if (a == null) {
                // null sorts after non-null (NULLS LAST).
                assertThat(b).isNull();
            }
        }
    }

    @Test
    @DisplayName("findPublicDashboardPage with MALICIOUS filter excludes BENIGN")
    void findPage_maliciousFilter_excludesBenign() {
        Fixture f = seed();

        List<ScannedUrl> page = repo.findPublicDashboardPage(CommunityVerdict.MALICIOUS, 1, 50);

        assertThat(page).extracting(ScannedUrl::getId).contains(f.maliciousId);
        assertThat(page).extracting(ScannedUrl::getId).doesNotContain(f.benignId);
        assertThat(page).allMatch(su -> su.getCommunityVerdict() == CommunityVerdict.MALICIOUS);
    }

    @Test
    @DisplayName("findPublicDashboardPage with BENIGN filter excludes MALICIOUS")
    void findPage_benignFilter_excludesMalicious() {
        Fixture f = seed();

        List<ScannedUrl> page = repo.findPublicDashboardPage(CommunityVerdict.BENIGN, 1, 50);

        assertThat(page).extracting(ScannedUrl::getId).contains(f.benignId);
        assertThat(page).extracting(ScannedUrl::getId).doesNotContain(f.maliciousId);
        assertThat(page).allMatch(su -> su.getCommunityVerdict() == CommunityVerdict.BENIGN);
    }

    @Test
    @DisplayName("findPublicDashboardPage pagination: size=1 returns exactly one row")
    void findPage_pagination_sizeOne() {
        seed();

        List<ScannedUrl> page1 = repo.findPublicDashboardPage(null, 1, 1);
        List<ScannedUrl> page2 = repo.findPublicDashboardPage(null, 2, 1);

        assertThat(page1).hasSize(1);
        assertThat(page2).hasSize(1);
        // Different rows.
        assertThat(page1.get(0).getId()).isNotEqualTo(page2.get(0).getId());
    }

    // =========================================================================
    // findPublicDashboardByHash
    // =========================================================================

    @Test
    @DisplayName("findPublicDashboardByHash returns MALICIOUS URL by hash")
    void findByHash_maliciousUrl_found() {
        Fixture f = seed();

        var result = repo.findPublicDashboardByHash(f.maliciousHash);
        assertThat(result).isPresent();
        assertThat(result.get().getId()).isEqualTo(f.maliciousId);
    }

    @Test
    @DisplayName("findPublicDashboardByHash excludes deleted URL")
    void findByHash_deletedUrl_notFound() {
        Fixture f = seed();

        var result = repo.findPublicDashboardByHash(f.deletedHash);
        assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("findPublicDashboardByHash excludes UNKNOWN URL")
    void findByHash_unknownUrl_notFound() {
        Fixture f = seed();

        var result = repo.findPublicDashboardByHash(f.unknownHash);
        assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("findPublicDashboardByHash returns empty for non-existent hash")
    void findByHash_nonExistent_empty() {
        var result = repo.findPublicDashboardByHash("deadbeef00000000000000000000000000000000000000000000000000000000");
        assertThat(result).isEmpty();
    }

    // =========================================================================
    // Fixture
    // =========================================================================

    /** IDs of rows seeded for the current test. */
    private static class Fixture {
        UUID maliciousId;
        String maliciousHash;
        UUID benignId;
        UUID deletedId;
        String deletedHash;
        UUID unknownId;
        String unknownHash;
        UUID nullVerdictId;
    }

    /**
     * Seeds 5 rows covering the filtering matrix:
     * <ol>
     *   <li>MALICIOUS, not deleted, lastScannedAt = T+2 (newest)</li>
     *   <li>BENIGN, not deleted, lastScannedAt = T+1 (second)</li>
     *   <li>MALICIOUS, deleted_at set (excluded)</li>
     *   <li>UNKNOWN verdict, not deleted (excluded)</li>
     *   <li>NULL verdict, not deleted (excluded)</li>
     * </ol>
     * Uses native SQL for the deleted_at write (no v1 Java write path per §16).
     */
    private Fixture seed() {
        Fixture f = new Fixture();
        LocalDateTime baseTime = LocalDateTime.now().minusDays(1);

        // Row 1: MALICIOUS, not deleted, lastScannedAt = baseTime + 2h (newest)
        f.maliciousHash = uniqueHash();
        ScannedUrl malicious = makeUrl("https://malicious.test/" + UUID.randomUUID(),
                f.maliciousHash, CommunityVerdict.MALICIOUS, baseTime.plusHours(2));
        f.maliciousId = malicious.getId();

        // Row 2: BENIGN, not deleted, lastScannedAt = baseTime + 1h
        String benignHash = uniqueHash();
        ScannedUrl benign = makeUrl("https://benign.test/" + UUID.randomUUID(),
                benignHash, CommunityVerdict.BENIGN, baseTime.plusHours(1));
        f.benignId = benign.getId();

        // Row 3: MALICIOUS but deleted_at is set — excluded from dashboard
        f.deletedHash = uniqueHash();
        ScannedUrl deletedRow = makeUrl("https://deleted.test/" + UUID.randomUUID(),
                f.deletedHash, CommunityVerdict.MALICIOUS, baseTime);
        f.deletedId = deletedRow.getId();
        // Write deleted_at via native SQL (no v1 Java write path per Part II §16).
        em.getTransaction().begin();
        em.createNativeQuery(
                "UPDATE scanned_url SET deleted_at = NOW() WHERE id = :id")
                .setParameter("id", deletedRow.getId())
                .executeUpdate();
        em.getTransaction().commit();
        em.clear();

        // Row 4: UNKNOWN verdict — excluded from dashboard
        f.unknownHash = uniqueHash();
        ScannedUrl unknown = makeUrl("https://unknown.test/" + UUID.randomUUID(),
                f.unknownHash, CommunityVerdict.UNKNOWN, baseTime.minusHours(1));
        f.unknownId = unknown.getId();

        // Row 5: NULL verdict — excluded from dashboard
        ScannedUrl nullVerdict = makeUrl("https://noVerdict.test/" + UUID.randomUUID(),
                uniqueHash(), null, null);
        f.nullVerdictId = nullVerdict.getId();

        return f;
    }

    private ScannedUrl makeUrl(String originalUrl, String hash,
                               CommunityVerdict verdict, LocalDateTime lastScannedAt) {
        ScannedUrl url = new ScannedUrl();
        url.setOriginalUrl(originalUrl);
        url.setNormalizedHash(hash);
        url.setCommunityVerdict(verdict);
        url.setLastScannedAt(lastScannedAt);
        em.getTransaction().begin();
        em.persist(url);
        em.getTransaction().commit();
        em.clear();
        return em.find(ScannedUrl.class, url.getId());
    }

    /** Generates a unique 64-hex-char hash for test data. */
    private static String uniqueHash() {
        String raw = UUID.randomUUID().toString().replace("-", "")
                   + UUID.randomUUID().toString().replace("-", "");
        return raw.substring(0, 64);
    }
}
