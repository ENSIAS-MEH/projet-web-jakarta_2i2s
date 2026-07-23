package com.secbret.repository;

import com.secbret.model.entity.ScanJob;
import com.secbret.model.enums.ScanDepth;
import com.secbret.model.enums.ScanJobStatus;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@ApplicationScoped
public class ScanJobRepository {

    @PersistenceContext(unitName = "SecBretPU")
    EntityManager em;

    public ScanJobRepository() {
    }

    /** Test constructor — production uses container-injected @PersistenceContext. */
    public ScanJobRepository(EntityManager em) {
        this.em = em;
    }

    @Transactional
    public ScanJob persist(ScanJob job) {
        em.persist(job);
        return job;
    }

    public Optional<ScanJob> findById(UUID id) {
        return Optional.ofNullable(em.find(ScanJob.class, id));
    }

    /**
     * Find a scan job by id with the URL and submittedBy associations eagerly loaded
     * via JOIN FETCH, avoiding LazyInitializationException when the entity is read
     * outside a transaction context (as in JAX-RS request scoped beans).
     */
    public Optional<ScanJob> findByIdEager(UUID id) {
        return em.createQuery(
                        "SELECT j FROM ScanJob j "
                                + "LEFT JOIN FETCH j.url "
                                + "LEFT JOIN FETCH j.submittedBy "
                                + "WHERE j.id = :id",
                        ScanJob.class)
                .setParameter("id", id)
                .getResultStream()
                .findFirst();
    }

    /**
     * Count scan jobs with optional filters. Used for pagination.
     * When {@code ownerId} is non-null, results are restricted to that user.
     */
    public long count(UUID ownerId, ScanJobStatus status, ScanDepth depth) {
        StringBuilder jpql = new StringBuilder("SELECT COUNT(j) FROM ScanJob j WHERE 1=1");
        List<Object[]> params = new ArrayList<>();
        if (ownerId != null) {
            jpql.append(" AND j.submittedBy.id = :ownerId");
            params.add(new Object[]{"ownerId", ownerId});
        }
        if (status != null) {
            jpql.append(" AND j.status = :status");
            params.add(new Object[]{"status", status});
        }
        if (depth != null) {
            jpql.append(" AND j.scanDepth = :depth");
            params.add(new Object[]{"depth", depth});
        }
        var q = em.createQuery(jpql.toString(), Long.class);
        for (Object[] p : params) {
            q.setParameter((String) p[0], p[1]);
        }
        return q.getSingleResult();
    }

    /**
     * Paginated scan job list with optional filters, ordered by createdAt DESC.
     * When {@code ownerId} is non-null, results are restricted to that user.
     */
    public List<ScanJob> findPage(UUID ownerId, ScanJobStatus status, ScanDepth depth,
                                   int page, int size) {
        StringBuilder jpql = new StringBuilder(
                "SELECT j FROM ScanJob j LEFT JOIN FETCH j.url WHERE 1=1");
        List<Object[]> params = new ArrayList<>();
        if (ownerId != null) {
            jpql.append(" AND j.submittedBy.id = :ownerId");
            params.add(new Object[]{"ownerId", ownerId});
        }
        if (status != null) {
            jpql.append(" AND j.status = :status");
            params.add(new Object[]{"status", status});
        }
        if (depth != null) {
            jpql.append(" AND j.scanDepth = :depth");
            params.add(new Object[]{"depth", depth});
        }
        jpql.append(" ORDER BY j.createdAt DESC");
        var q = em.createQuery(jpql.toString(), ScanJob.class);
        for (Object[] p : params) {
            q.setParameter((String) p[0], p[1]);
        }
        int offset = (page - 1) * size;
        q.setFirstResult(offset);
        q.setMaxResults(size);
        return q.getResultList();
    }

    /**
     * Returns true when the given user has ever submitted a scan job for the given URL.
     * Used for REPORTER ownership check on GET /scan/url/{urlId} (anti-enumeration 404).
     */
    public boolean existsByUrlIdAndSubmittedBy(UUID urlId, UUID userId) {
        Long count = em.createQuery(
                        "SELECT COUNT(j) FROM ScanJob j "
                                + "WHERE j.url.id = :urlId AND j.submittedBy.id = :userId",
                        Long.class)
                .setParameter("urlId", urlId)
                .setParameter("userId", userId)
                .getSingleResult();
        return count > 0;
    }
}
