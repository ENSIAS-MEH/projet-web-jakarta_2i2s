package com.secbret.repository;

import com.secbret.model.entity.ShareLink;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for {@link ShareLink}.
 *
 * <h2>access_count (Part IV)</h2>
 * Incremented atomically via native SQL UPDATE — never via ORM read-modify-write,
 * which causes lost updates under concurrent readers. See {@link #incrementAccessCountInTx(UUID)}.
 */
@ApplicationScoped
public class ShareLinkRepository {

    @PersistenceContext(unitName = "SecBretPU")
    EntityManager em;

    public ShareLinkRepository() {}

    /** Test constructor. */
    public ShareLinkRepository(EntityManager em) { this.em = em; }

    // -----------------------------------------------------------------------
    // Write
    // -----------------------------------------------------------------------

    @Transactional
    public ShareLink persist(ShareLink link) {
        em.persist(link);
        return link;
    }

    /**
     * Atomic access_count increment per spec (Part IV §share_link):
     *   UPDATE share_link SET access_count = access_count + 1, last_accessed_at = NOW() WHERE id = :id
     * Must NOT use ORM read-modify-write (concurrent readers produce lost updates).
     */
    @Transactional
    public void incrementAccessCountInTx(UUID linkId) {
        em.createNativeQuery(
                "UPDATE share_link SET access_count = access_count + 1, last_accessed_at = NOW()" +
                " WHERE id = CAST(:id AS uuid)")
                .setParameter("id", linkId.toString())
                .executeUpdate();
    }

    /**
     * Revoke a share link. Owns its @Transactional.
     */
    @Transactional
    public void revokeInTx(UUID linkId) {
        em.createNativeQuery(
                "UPDATE share_link SET is_revoked = TRUE WHERE id = CAST(:id AS uuid)")
                .setParameter("id", linkId.toString())
                .executeUpdate();
    }

    // -----------------------------------------------------------------------
    // Read
    // -----------------------------------------------------------------------

    public Optional<ShareLink> findById(UUID id) {
        return Optional.ofNullable(em.find(ShareLink.class, id));
    }

    public Optional<ShareLink> findByIdEager(UUID id) {
        return em.createQuery(
                        "SELECT sl FROM ShareLink sl"
                                + " LEFT JOIN FETCH sl.reportJob rj"
                                + " LEFT JOIN FETCH rj.url"
                                + " LEFT JOIN FETCH sl.createdBy"
                                + " WHERE sl.id = :id",
                        ShareLink.class)
                .setParameter("id", id)
                .getResultStream()
                .findFirst();
    }

    /**
     * Find by uuid_token, checking validity (not revoked, not expired) per spec SQL (Part IV §share_link check).
     * Returns empty if not found, revoked, or expired → caller returns 404 for not-found,
     * 410 for expired/revoked (see check below).
     */
    public Optional<ShareLink> findByToken(String uuidToken) {
        return em.createQuery(
                        "SELECT sl FROM ShareLink sl"
                                + " LEFT JOIN FETCH sl.reportJob rj"
                                + " LEFT JOIN FETCH rj.url"
                                + " LEFT JOIN FETCH rj.requestedBy"
                                + " LEFT JOIN FETCH sl.createdBy"
                                + " WHERE sl.uuidToken = :token",
                        ShareLink.class)
                .setParameter("token", uuidToken)
                .getResultStream()
                .findFirst();
    }

    /**
     * Find the most recently created active share link for a report job.
     * Used to embed in COMPLETED poll response.
     */
    public Optional<ShareLink> findFirstByReportJobId(UUID reportJobId) {
        return em.createQuery(
                        "SELECT sl FROM ShareLink sl"
                                + " WHERE sl.reportJob.id = :jobId"
                                + " AND sl.isRevoked = FALSE"
                                + " ORDER BY sl.createdAt DESC",
                        ShareLink.class)
                .setParameter("jobId", reportJobId)
                .setMaxResults(1)
                .getResultStream()
                .findFirst();
    }

    /** Paginated list of own share links (created_by = userId), ordered newest first. */
    public List<ShareLink> findByCreatedByPage(UUID userId, int page, int size) {
        return em.createQuery(
                        "SELECT sl FROM ShareLink sl"
                                + " LEFT JOIN FETCH sl.reportJob rj"
                                + " LEFT JOIN FETCH rj.url"
                                + " WHERE sl.createdBy.id = :uid"
                                + " ORDER BY sl.createdAt DESC",
                        ShareLink.class)
                .setParameter("uid", userId)
                .setFirstResult((page - 1) * size)
                .setMaxResults(size)
                .getResultList();
    }

    public long countByCreatedBy(UUID userId) {
        return em.createQuery(
                        "SELECT COUNT(sl) FROM ShareLink sl WHERE sl.createdBy.id = :uid",
                        Long.class)
                .setParameter("uid", userId)
                .getSingleResult();
    }
}
