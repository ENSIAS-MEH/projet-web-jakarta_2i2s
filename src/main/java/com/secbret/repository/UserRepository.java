package com.secbret.repository;

import com.secbret.model.entity.SecBretUser;
import com.secbret.model.enums.UserRole;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@ApplicationScoped
public class UserRepository {

    @PersistenceContext(unitName = "SecBretPU")
    EntityManager em;

    public UserRepository() {
    }

    /** Test constructor — production uses container-injected @PersistenceContext. */
    public UserRepository(EntityManager em) {
        this.em = em;
    }

    @Transactional
    public SecBretUser persist(SecBretUser user) {
        em.persist(user);
        return user;
    }

    public Optional<SecBretUser> findById(UUID id) {
        return Optional.ofNullable(em.find(SecBretUser.class, id));
    }

    public Optional<SecBretUser> findByUsername(String username) {
        return em.createQuery(
                        "SELECT u FROM SecBretUser u WHERE u.username = :username", SecBretUser.class)
                .setParameter("username", username)
                .getResultStream()
                .findFirst();
    }

    public Optional<SecBretUser> findByEmail(String email) {
        return em.createQuery(
                        "SELECT u FROM SecBretUser u WHERE u.email = :email", SecBretUser.class)
                .setParameter("email", email)
                .getResultStream()
                .findFirst();
    }

    public long count() {
        return em.createQuery("SELECT COUNT(u) FROM SecBretUser u", Long.class).getSingleResult();
    }

    /**
     * Paginated user list for GET /admin/users. Optional role and enabled filters.
     * Offset is 0-based (caller converts 1-based page to offset).
     */
    public List<SecBretUser> findPage(UserRole role, Boolean enabled, int offset, int limit) {
        StringBuilder jpql = new StringBuilder("SELECT u FROM SecBretUser u WHERE 1=1");
        if (role != null)    jpql.append(" AND u.role = :role");
        if (enabled != null) jpql.append(" AND u.enabled = :enabled");
        jpql.append(" ORDER BY u.createdAt DESC");

        var q = em.createQuery(jpql.toString(), SecBretUser.class);
        if (role != null)    q.setParameter("role", role);
        if (enabled != null) q.setParameter("enabled", enabled);
        return q.setFirstResult(offset).setMaxResults(limit).getResultList();
    }

    /** Count for the same filter set (for pagination totalElements). */
    public long countFiltered(UserRole role, Boolean enabled) {
        StringBuilder jpql = new StringBuilder("SELECT COUNT(u) FROM SecBretUser u WHERE 1=1");
        if (role != null)    jpql.append(" AND u.role = :role");
        if (enabled != null) jpql.append(" AND u.enabled = :enabled");

        var q = em.createQuery(jpql.toString(), Long.class);
        if (role != null)    q.setParameter("role", role);
        if (enabled != null) q.setParameter("enabled", enabled);
        return q.getSingleResult();
    }

    @Transactional
    public SecBretUser merge(SecBretUser user) {
        return em.merge(user);
    }

    @Transactional
    public void delete(SecBretUser user) {
        SecBretUser managed = em.contains(user) ? user : em.merge(user);
        em.remove(managed);
    }

    /**
     * Atomically increments failed_login_attempts; if that reaches the threshold,
     * also sets locked_until = NOW() + 15 min. Returns the new attempt count.
     * Uses native SQL so the read-increment-write is one DB round-trip (no stale
     * entity in the 1st-level cache to invalidate).
     */
    @Transactional
    public int incrementFailedLoginAttempts(UUID userId, int threshold) {
        // Increment and conditionally lock in one statement.
        em.createNativeQuery("""
            UPDATE secbret_user
               SET failed_login_attempts = failed_login_attempts + 1,
                   locked_until = CASE
                       WHEN failed_login_attempts + 1 >= :threshold
                       THEN NOW() + INTERVAL '15 minutes'
                       ELSE locked_until
                   END
             WHERE id = :id
            """)
                .setParameter("threshold", threshold)
                .setParameter("id", userId)
                .executeUpdate();

        // Return the new count so callers can decide whether to log.
        Number count = (Number) em.createNativeQuery(
                        "SELECT failed_login_attempts FROM secbret_user WHERE id = :id")
                .setParameter("id", userId)
                .getSingleResult();
        return count.intValue();
    }

    /**
     * Resets failed_login_attempts to 0 and clears locked_until on successful login.
     */
    @Transactional
    public void resetFailedLoginAttempts(UUID userId) {
        em.createNativeQuery("""
            UPDATE secbret_user
               SET failed_login_attempts = 0,
                   locked_until = NULL
             WHERE id = :id
            """)
                .setParameter("id", userId)
                .executeUpdate();
    }

    /**
     * Invalidates all outstanding password reset tokens for a user
     * by marking them as used (used_at = NOW()). Used when password is changed.
     */
    @Transactional
    public void invalidatePasswordResetTokens(UUID userId) {
        em.createNativeQuery("""
            UPDATE password_reset_token
               SET used_at = NOW()
             WHERE user_id = :userId AND used_at IS NULL
            """)
                .setParameter("userId", userId)
                .executeUpdate();
    }
}
