package com.secbret.repository;

import com.secbret.model.entity.PasswordResetToken;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@ApplicationScoped
public class PasswordResetTokenRepository {

    @PersistenceContext(unitName = "SecBretPU")
    EntityManager em;

    public PasswordResetTokenRepository() {
    }

    public PasswordResetTokenRepository(EntityManager em) {
        this.em = em;
    }

    @Transactional
    public PasswordResetToken persist(PasswordResetToken token) {
        em.persist(token);
        return token;
    }

    /**
     * Finds a token by its SHA-256 hash — the only lookup path.
     * Checks not-used AND not-expired.
     */
    public Optional<PasswordResetToken> findValidByHash(String tokenHash) {
        return em.createQuery("""
                SELECT t FROM PasswordResetToken t
                 WHERE t.tokenHash = :hash
                   AND t.usedAt IS NULL
                   AND t.expiresAt > :now
                """, PasswordResetToken.class)
                .setParameter("hash", tokenHash)
                .setParameter("now", LocalDateTime.now())
                .getResultStream()
                .findFirst();
    }

    /**
     * Marks this specific token as used (single-use guarantee).
     */
    @Transactional
    public void markUsed(UUID tokenId) {
        em.createNativeQuery(
                "UPDATE password_reset_token SET used_at = NOW() WHERE id = :id")
                .setParameter("id", tokenId)
                .executeUpdate();
    }

    /**
     * Invalidates ALL outstanding tokens for a user — called after successful
     * password reset and after password change (Part III §POST /reset-password).
     */
    @Transactional
    public void invalidateAllForUser(UUID userId) {
        em.createNativeQuery("""
            UPDATE password_reset_token
               SET used_at = NOW()
             WHERE user_id = :userId AND used_at IS NULL
            """)
                .setParameter("userId", userId)
                .executeUpdate();
    }
}
