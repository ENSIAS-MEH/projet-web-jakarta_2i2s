package com.secbret.integration;

import com.secbret.model.entity.PasswordResetToken;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.enums.UserRole;
import com.secbret.repository.PasswordResetTokenRepository;
import com.secbret.repository.UserRepository;
import com.secbret.security.PasswordHasher;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for password_reset_token flow against a real PostgreSQL container.
 * Covers: create → consume → token single-use; expired token rejected; invalidate-all.
 */
class PasswordResetIT extends PostgresIntegrationSupport {

    private EntityManager em;
    private UserRepository userRepo;
    private PasswordResetTokenRepository tokenRepo;
    private final PasswordHasher hasher = new PasswordHasher(4);

    @BeforeEach
    void setUp() {
        em = EMF.createEntityManager();
        userRepo = new UserRepository(em);
        tokenRepo = new PasswordResetTokenRepository(em);
    }

    @AfterEach
    void tearDown() {
        if (em.isOpen()) {
            if (em.getTransaction().isActive()) em.getTransaction().rollback();
            // Clean up test data
            em.getTransaction().begin();
            em.createNativeQuery("DELETE FROM password_reset_token").executeUpdate();
            em.createNativeQuery("DELETE FROM secbret_user WHERE username LIKE 'prtest%'").executeUpdate();
            em.getTransaction().commit();
            em.close();
        }
    }

    private SecBretUser createUser(String username) {
        em.getTransaction().begin();
        SecBretUser u = new SecBretUser();
        u.setUsername(username);
        u.setEmail(username + "@example.com");
        u.setPasswordHash(hasher.hash("testpassword123"));
        u.setRole(UserRole.REPORTER);
        u.setEnabled(true);
        em.persist(u);
        em.getTransaction().commit();
        return u;
    }

    private PasswordResetToken createToken(SecBretUser user, LocalDateTime expiresAt, boolean used) {
        String tokenHash = "hash_" + System.nanoTime();
        // Use native SQL so we can set created_at explicitly (allowing expires_at in the past)
        // The check constraint is expires_at > created_at, so set created_at well before expires_at.
        em.getTransaction().begin();
        LocalDateTime createdAt = expiresAt.minusHours(2); // always satisfies constraint
        String usedAtSql = used ? "NOW() - INTERVAL '1 minute'" : "NULL";
        em.createNativeQuery("""
            INSERT INTO password_reset_token (id, user_id, token_hash, expires_at, used_at, created_at)
            VALUES (gen_random_uuid(), :userId, :hash, :expiresAt, """ + usedAtSql + ", :createdAt)")
                .setParameter("userId", user.getId())
                .setParameter("hash", tokenHash)
                .setParameter("expiresAt", expiresAt)
                .setParameter("createdAt", createdAt)
                .executeUpdate();
        em.getTransaction().commit();
        em.clear();
        // Return a stub for the hash so tests can look it up
        PasswordResetToken stub = new PasswordResetToken();
        stub.setTokenHash(tokenHash);
        return stub;
    }

    @Test
    @DisplayName("valid token → findValidByHash returns it")
    void validToken_found() {
        SecBretUser user = createUser("prtest_valid");
        PasswordResetToken tok = createToken(user, LocalDateTime.now().plusHours(1), false);

        Optional<PasswordResetToken> found = tokenRepo.findValidByHash(tok.getTokenHash());
        assertThat(found).isPresent();
        assertThat(found.get().getTokenHash()).isEqualTo(tok.getTokenHash());
    }

    @Test
    @DisplayName("expired token → findValidByHash returns empty")
    void expiredToken_notFound() {
        SecBretUser user = createUser("prtest_expired");
        PasswordResetToken tok = createToken(user, LocalDateTime.now().minusMinutes(1), false);

        Optional<PasswordResetToken> found = tokenRepo.findValidByHash(tok.getTokenHash());
        assertThat(found).isEmpty();
    }

    @Test
    @DisplayName("already-used token → findValidByHash returns empty")
    void usedToken_notFound() {
        SecBretUser user = createUser("prtest_used");
        PasswordResetToken tok = createToken(user, LocalDateTime.now().plusHours(1), true);

        Optional<PasswordResetToken> found = tokenRepo.findValidByHash(tok.getTokenHash());
        assertThat(found).isEmpty();
    }

    @Test
    @DisplayName("invalidateAllForUser marks all user tokens as used")
    void invalidateAll_marksAllUsed() {
        SecBretUser user = createUser("prtest_invalidate");
        PasswordResetToken t1 = createToken(user, LocalDateTime.now().plusHours(1), false);
        PasswordResetToken t2 = createToken(user, LocalDateTime.now().plusHours(1), false);

        // RESOURCE_LOCAL: @Transactional doesn't fire in tests; wrap explicitly
        em.getTransaction().begin();
        tokenRepo.invalidateAllForUser(user.getId());
        em.getTransaction().commit();

        em.clear();
        assertThat(tokenRepo.findValidByHash(t1.getTokenHash())).isEmpty();
        assertThat(tokenRepo.findValidByHash(t2.getTokenHash())).isEmpty();
    }
}
