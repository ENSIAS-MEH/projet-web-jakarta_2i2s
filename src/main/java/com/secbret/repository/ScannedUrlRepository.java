package com.secbret.repository;

import com.secbret.model.entity.ScannedUrl;
import com.secbret.model.enums.CommunityVerdict;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@ApplicationScoped
public class ScannedUrlRepository {

    /**
     * Base JPQL WHERE clause for the public dashboard:
     * only MALICIOUS or BENIGN verdicts, soft-delete excluded (deleted_at IS NULL).
     * SUSPICIOUS and UNKNOWN/NULL are deliberately not surfaced (Part III §7).
     * No @Where on the entity (Part II §16) — filter is applied at query level.
     */
    private static final String PUBLIC_DASHBOARD_WHERE =
            "s.communityVerdict IN (com.secbret.model.enums.CommunityVerdict.MALICIOUS,"
            + " com.secbret.model.enums.CommunityVerdict.BENIGN)"
            + " AND s.deletedAt IS NULL";

    @PersistenceContext(unitName = "SecBretPU")
    EntityManager em;

    public ScannedUrlRepository() {
    }

    /** Test constructor — production uses container-injected @PersistenceContext. */
    public ScannedUrlRepository(EntityManager em) {
        this.em = em;
    }

    @Transactional
    public ScannedUrl persist(ScannedUrl url) {
        em.persist(url);
        return url;
    }

    public Optional<ScannedUrl> findById(UUID id) {
        return Optional.ofNullable(em.find(ScannedUrl.class, id));
    }

    /** Dedup lookup per Part II §C — dedup MUST use normalized_hash, never original_url. */
    public Optional<ScannedUrl> findByNormalizedHash(String normalizedHash) {
        return em.createQuery(
                        "SELECT s FROM ScannedUrl s WHERE s.normalizedHash = :hash", ScannedUrl.class)
                .setParameter("hash", normalizedHash)
                .getResultStream()
                .findFirst();
    }

    // =========================================================================
    // Public dashboard queries (Part III §7) — anonymous, read-only
    // =========================================================================

    /**
     * Count rows with an established community verdict (MALICIOUS or BENIGN),
     * excluding soft-deleted rows.
     *
     * @param verdictFilter optional; null means both MALICIOUS and BENIGN
     */
    public long countPublicDashboard(CommunityVerdict verdictFilter) {
        String jpql = "SELECT COUNT(s) FROM ScannedUrl s WHERE " + PUBLIC_DASHBOARD_WHERE
                + (verdictFilter != null ? " AND s.communityVerdict = :verdict" : "");
        var q = em.createQuery(jpql, Long.class);
        if (verdictFilter != null) {
            q.setParameter("verdict", verdictFilter);
        }
        return q.getSingleResult();
    }

    /**
     * Fetch a page of URLs with an established community verdict, newest
     * last_scanned_at first (nulls sort last), excluding soft-deleted rows.
     *
     * @param verdictFilter optional; null returns both MALICIOUS and BENIGN
     * @param page          1-based page number
     * @param size          page size (max 50 per spec)
     */
    public List<ScannedUrl> findPublicDashboardPage(CommunityVerdict verdictFilter,
                                                     int page, int size) {
        String jpql = "SELECT s FROM ScannedUrl s WHERE " + PUBLIC_DASHBOARD_WHERE
                + (verdictFilter != null ? " AND s.communityVerdict = :verdict" : "")
                + " ORDER BY s.lastScannedAt DESC NULLS LAST, s.createdAt DESC";
        var q = em.createQuery(jpql, ScannedUrl.class);
        if (verdictFilter != null) {
            q.setParameter("verdict", verdictFilter);
        }
        q.setFirstResult((page - 1) * size);
        q.setMaxResults(size);
        return q.getResultList();
    }

    /**
     * Lookup a URL by its normalized hash for the public dashboard single-URL endpoint.
     * Returns empty if the URL does not exist, is soft-deleted, or has no established verdict.
     */
    public Optional<ScannedUrl> findPublicDashboardByHash(String normalizedHash) {
        return em.createQuery(
                        "SELECT s FROM ScannedUrl s WHERE s.normalizedHash = :hash"
                        + " AND " + PUBLIC_DASHBOARD_WHERE,
                        ScannedUrl.class)
                .setParameter("hash", normalizedHash)
                .getResultStream()
                .findFirst();
    }
}
