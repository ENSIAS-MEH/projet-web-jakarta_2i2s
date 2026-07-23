package com.secbret.repository;

import com.secbret.model.entity.ScanResult;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

import java.util.Optional;
import java.util.UUID;

@ApplicationScoped
public class ScanResultRepository {

    @PersistenceContext(unitName = "SecBretPU")
    EntityManager em;

    public ScanResultRepository() {
    }

    /** Test constructor — production uses container-injected @PersistenceContext. */
    public ScanResultRepository(EntityManager em) {
        this.em = em;
    }

    @Transactional
    public ScanResult persist(ScanResult result) {
        em.persist(result);
        return result;
    }

    public Optional<ScanResult> findById(UUID id) {
        return Optional.ofNullable(em.find(ScanResult.class, id));
    }

    public Optional<ScanResult> findByScanJobId(UUID scanJobId) {
        return em.createQuery(
                        "SELECT r FROM ScanResult r WHERE r.scanJob.id = :jobId", ScanResult.class)
                .setParameter("jobId", scanJobId)
                .getResultStream()
                .findFirst();
    }

    /**
     * Find the latest scan result for a given URL, ordered by createdAt DESC.
     * Used by GET /api/v1/scan/url/{urlId} (Part III §2).
     */
    @Transactional
    public Optional<ScanResult> findLatestByUrlId(UUID urlId) {
        return em.createQuery(
                        "SELECT r FROM ScanResult r WHERE r.url.id = :urlId "
                                + "ORDER BY r.createdAt DESC",
                        ScanResult.class)
                .setParameter("urlId", urlId)
                .setMaxResults(1)
                .getResultStream()
                .findFirst();
    }
}
