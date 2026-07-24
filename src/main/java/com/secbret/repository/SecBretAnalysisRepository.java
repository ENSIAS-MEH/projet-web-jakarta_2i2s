package com.secbret.repository;

import com.secbret.model.entity.SecBretAnalysis;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

import java.util.Optional;
import java.util.UUID;

@ApplicationScoped
public class SecBretAnalysisRepository {

    @PersistenceContext(unitName = "SecBretPU")
    EntityManager em;

    public SecBretAnalysisRepository() {}

    /** Test constructor. */
    public SecBretAnalysisRepository(EntityManager em) { this.em = em; }

    @Transactional
    public SecBretAnalysis persist(SecBretAnalysis analysis) {
        em.persist(analysis);
        return analysis;
    }

    /**
     * Resolves the report/url references and persists the analysis in ONE
     * repository-owned transaction. Used by IncidentService's async worker:
     * a self-invoked @Transactional on the service is bypassed by Weld, which
     * left the worker's em.find calls untransacted — under concurrent bursts
     * this raced HTTP-thread cleanup ("This statement has been closed" → 500s).
     */
    @Transactional
    public SecBretAnalysis persistForReport(UUID reportId, UUID urlId, SecBretAnalysis analysis) {
        com.secbret.model.entity.UserReport report = em.find(com.secbret.model.entity.UserReport.class, reportId);
        com.secbret.model.entity.ScannedUrl url = em.find(com.secbret.model.entity.ScannedUrl.class, urlId);
        if (report == null || url == null) {
            throw new IllegalStateException("report or url disappeared: " + reportId);
        }
        analysis.setUserReport(report);
        analysis.setUrl(url);
        em.persist(analysis);
        return analysis;
    }

    /** Latest analysis for a URL — used by the async PDF worker (must go through CDI proxy, not self-call). */
    @Transactional
    public Optional<SecBretAnalysis> findLatestByUrlId(UUID urlId) {
        return em.createQuery(
                        "SELECT a FROM SecBretAnalysis a WHERE a.url.id = :uid ORDER BY a.createdAt DESC",
                        SecBretAnalysis.class)
                .setParameter("uid", urlId)
                .setMaxResults(1)
                .getResultStream()
                .findFirst();
    }

    public Optional<SecBretAnalysis> findByUserReportId(UUID userReportId) {
        return em.createQuery(
                        "SELECT a FROM SecBretAnalysis a WHERE a.userReport.id = :rid",
                        SecBretAnalysis.class)
                .setParameter("rid", userReportId)
                .getResultStream()
                .findFirst();
    }

    public Optional<SecBretAnalysis> findById(UUID id) {
        return Optional.ofNullable(em.find(SecBretAnalysis.class, id));
    }
}
