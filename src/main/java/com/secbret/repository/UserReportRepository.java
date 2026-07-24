package com.secbret.repository;

import com.secbret.model.entity.ScannedUrl;
import com.secbret.model.entity.UserReport;
import com.secbret.model.enums.CommunityVerdict;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@ApplicationScoped
public class UserReportRepository {

    @PersistenceContext(unitName = "SecBretPU")
    EntityManager em;

    public UserReportRepository() {}

    /** Test constructor. */
    public UserReportRepository(EntityManager em) { this.em = em; }

    @Transactional
    public UserReport persist(UserReport report) {
        em.persist(report);
        return report;
    }

    /**
     * Auto-resolution write, in a real transaction that flushes. Called from the async
     * IncidentService thread — must own its @Transactional here (not on the service) because
     * a self-invoked @Transactional on the @ApplicationScoped service is bypassed by Weld.
     *
     * @param communityVerdict the verdict to set on scanned_url, or null to leave unchanged (REJECT/PENDING_REVIEW)
     */
    @Transactional
    public void resolveInTx(UUID reportId, UUID urlId, String status, String finalVerdict,
                            CommunityVerdict communityVerdict) {
        UserReport report = em.find(UserReport.class, reportId);
        if (report == null) return;
        report.setStatus(status);
        if (finalVerdict != null) {
            report.setVerdict(finalVerdict);
            report.setResolvedAt(LocalDateTime.now());
        }
        if (communityVerdict != null && urlId != null) {
            ScannedUrl url = em.find(ScannedUrl.class, urlId);
            if (url != null) url.setCommunityVerdict(communityVerdict);
        }
    }

    /** Mark a report FAILED (§16.5) in a real transaction. */
    @Transactional
    public void markFailedInTx(UUID reportId, String errorMessage) {
        UserReport report = em.find(UserReport.class, reportId);
        if (report == null) return;
        report.setStatus("FAILED");
        report.setErrorMessage(errorMessage);
    }

    public Optional<UserReport> findById(UUID id) {
        return Optional.ofNullable(em.find(UserReport.class, id));
    }

    /** Eager-load url and reportedBy to avoid LazyInitializationException outside tx. */
    public Optional<UserReport> findByIdEager(UUID id) {
        return em.createQuery(
                        "SELECT r FROM UserReport r "
                                + "LEFT JOIN FETCH r.url "
                                + "LEFT JOIN FETCH r.reportedBy "
                                + "WHERE r.id = :id",
                        UserReport.class)
                .setParameter("id", id)
                .getResultStream()
                .findFirst();
    }

    /** Own reports for a specific user (REPORTER view). Ordered by created_at DESC. */
    public List<UserReport> findByReportedByIdPage(UUID userId, String statusFilter, int page, int size) {
        String jpql = "SELECT r FROM UserReport r LEFT JOIN FETCH r.url LEFT JOIN FETCH r.reportedBy"
                + " WHERE r.reportedBy.id = :uid"
                + (statusFilter != null ? " AND r.status = :st" : "")
                + " ORDER BY r.createdAt DESC";
        var q = em.createQuery(jpql, UserReport.class).setParameter("uid", userId);
        if (statusFilter != null) q.setParameter("st", statusFilter);
        return q.setFirstResult((page - 1) * size).setMaxResults(size).getResultList();
    }

    public long countByReportedById(UUID userId, String statusFilter) {
        String jpql = "SELECT COUNT(r) FROM UserReport r WHERE r.reportedBy.id = :uid"
                + (statusFilter != null ? " AND r.status = :st" : "");
        var q = em.createQuery(jpql, Long.class).setParameter("uid", userId);
        if (statusFilter != null) q.setParameter("st", statusFilter);
        return q.getSingleResult();
    }

    /** All reports for ANALYST/ADMIN view. Ordered by created_at DESC. */
    public List<UserReport> findAllPage(String statusFilter, int page, int size) {
        String jpql = "SELECT r FROM UserReport r LEFT JOIN FETCH r.url LEFT JOIN FETCH r.reportedBy"
                + (statusFilter != null ? " WHERE r.status = :st" : "")
                + " ORDER BY r.createdAt DESC";
        var q = em.createQuery(jpql, UserReport.class);
        if (statusFilter != null) q.setParameter("st", statusFilter);
        return q.setFirstResult((page - 1) * size).setMaxResults(size).getResultList();
    }

    public long countAll(String statusFilter) {
        String jpql = "SELECT COUNT(r) FROM UserReport r"
                + (statusFilter != null ? " WHERE r.status = :st" : "");
        var q = em.createQuery(jpql, Long.class);
        if (statusFilter != null) q.setParameter("st", statusFilter);
        return q.getSingleResult();
    }

    /** PENDING_REVIEW reports for the analyst queue, sorted by createdAt ASC (oldest first). */
    public List<UserReport> findPendingReviewPage(int page, int size) {
        return em.createQuery(
                        "SELECT r FROM UserReport r LEFT JOIN FETCH r.url LEFT JOIN FETCH r.reportedBy"
                                + " WHERE r.status = 'PENDING_REVIEW' ORDER BY r.createdAt ASC",
                        UserReport.class)
                .setFirstResult((page - 1) * size)
                .setMaxResults(size)
                .getResultList();
    }

    public long countPendingReview() {
        return em.createQuery(
                "SELECT COUNT(r) FROM UserReport r WHERE r.status = 'PENDING_REVIEW'", Long.class)
                .getSingleResult();
    }
}
