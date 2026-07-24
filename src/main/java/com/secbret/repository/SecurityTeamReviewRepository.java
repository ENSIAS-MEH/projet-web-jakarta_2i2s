package com.secbret.repository;

import com.secbret.model.entity.SecurityTeamReview;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

import java.util.Optional;
import java.util.UUID;

@ApplicationScoped
public class SecurityTeamReviewRepository {

    @PersistenceContext(unitName = "SecBretPU")
    EntityManager em;

    public SecurityTeamReviewRepository() {}

    /** Test constructor. */
    public SecurityTeamReviewRepository(EntityManager em) { this.em = em; }

    @Transactional
    public SecurityTeamReview persist(SecurityTeamReview review) {
        em.persist(review);
        return review;
    }

    /** Latest review for any report on a URL — used by the async PDF worker. */
    @Transactional
    public Optional<SecurityTeamReview> findLatestByUrlId(UUID urlId) {
        return em.createQuery(
                        "SELECT str FROM SecurityTeamReview str"
                        + " JOIN str.userReport ur"
                        + " WHERE ur.url.id = :uid"
                        + " ORDER BY str.reviewedAt DESC",
                        SecurityTeamReview.class)
                .setParameter("uid", urlId)
                .setMaxResults(1)
                .getResultStream()
                .findFirst();
    }

    public Optional<SecurityTeamReview> findByUserReportId(UUID userReportId) {
        return em.createQuery(
                        "SELECT r FROM SecurityTeamReview r LEFT JOIN FETCH r.reviewedBy"
                                + " WHERE r.userReport.id = :rid",
                        SecurityTeamReview.class)
                .setParameter("rid", userReportId)
                .getResultStream()
                .findFirst();
    }

    public Optional<SecurityTeamReview> findById(UUID id) {
        return Optional.ofNullable(em.find(SecurityTeamReview.class, id));
    }
}
