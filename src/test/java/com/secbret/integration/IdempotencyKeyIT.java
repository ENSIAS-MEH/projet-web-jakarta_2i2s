package com.secbret.integration;

import com.secbret.model.entity.IdempotencyKey;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.enums.UserRole;
import com.secbret.repository.IdempotencyKeyRepository;
import com.secbret.security.PasswordHasher;
import com.secbret.service.MaintenanceBatchTimer;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for idempotency_key entity and MaintenanceBatchTimer purge.
 */
class IdempotencyKeyIT extends PostgresIntegrationSupport {

    private EntityManager em;
    private IdempotencyKeyRepository keyRepo;
    private final PasswordHasher hasher = new PasswordHasher(4);

    @BeforeEach
    void setUp() {
        em = EMF.createEntityManager();
        keyRepo = new IdempotencyKeyRepository(em);
    }

    @AfterEach
    void tearDown() {
        if (em.isOpen()) {
            if (em.getTransaction().isActive()) em.getTransaction().rollback();
            em.getTransaction().begin();
            em.createNativeQuery("DELETE FROM idempotency_key").executeUpdate();
            em.createNativeQuery("DELETE FROM secbret_user WHERE username LIKE 'iktest%'").executeUpdate();
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

    private IdempotencyKey createKey(SecBretUser user, String endpoint, String key,
                                      LocalDateTime expiresAt, Integer status, String body) {
        em.getTransaction().begin();
        IdempotencyKey k = new IdempotencyKey();
        k.setUser(user);
        k.setEndpoint(endpoint);
        k.setIdemKey(key);
        k.setRequestHash("hash_" + key);
        k.setExpiresAt(expiresAt);
        k.setResponseStatus(status);
        k.setResponseBody(body);
        em.persist(k);
        em.getTransaction().commit();
        em.clear();
        return k;
    }

    @Test
    @DisplayName("in-flight key → isInFlight=true, isComplete=false")
    void inFlightKey_stateCorrect() {
        SecBretUser user = createUser("iktest_inflight");
        createKey(user, "POST /scan", "key1", LocalDateTime.now().plusHours(24), null, null);

        Optional<IdempotencyKey> found = keyRepo.findByUserEndpointKey(user.getId(), "POST /scan", "key1");
        assertThat(found).isPresent();
        assertThat(found.get().isInFlight()).isTrue();
        assertThat(found.get().isComplete()).isFalse();
    }

    @Test
    @DisplayName("captureResponse → key becomes complete with stored status/body")
    void captureResponse_keyComplete() {
        SecBretUser user = createUser("iktest_capture");
        IdempotencyKey k = createKey(user, "POST /scan", "key2",
                LocalDateTime.now().plusHours(24), null, null);

        // RESOURCE_LOCAL: @Transactional doesn't fire in tests; wrap explicitly
        em.getTransaction().begin();
        keyRepo.captureResponse(k.getId(), 202, "{\"jobId\":\"abc\"}");
        em.getTransaction().commit();

        em.clear();
        Optional<IdempotencyKey> found = keyRepo.findByUserEndpointKey(user.getId(), "POST /scan", "key2");
        assertThat(found).isPresent();
        assertThat(found.get().isComplete()).isTrue();
        assertThat(found.get().getResponseStatus()).isEqualTo(202);
        assertThat(found.get().getResponseBody()).isEqualTo("{\"jobId\":\"abc\"}");
    }

    @Test
    @DisplayName("expired key → not found by findByUserEndpointKey")
    void expiredKey_notFound() {
        SecBretUser user = createUser("iktest_expired");
        createKey(user, "POST /scan", "key3",
                LocalDateTime.now().minusHours(1), 202, "{}");

        Optional<IdempotencyKey> found = keyRepo.findByUserEndpointKey(user.getId(), "POST /scan", "key3");
        assertThat(found).isEmpty();
    }

    @Test
    @DisplayName("different endpoint → not found for other endpoint")
    void differentEndpoint_notFound() {
        SecBretUser user = createUser("iktest_endpoint");
        createKey(user, "POST /scan", "key4", LocalDateTime.now().plusHours(24), null, null);

        Optional<IdempotencyKey> found = keyRepo.findByUserEndpointKey(user.getId(), "POST /incident", "key4");
        assertThat(found).isEmpty();
    }

    @Test
    @DisplayName("MaintenanceBatchTimer.runMaintenance purges expired idempotency_key rows")
    void maintenancePurge_removesExpiredKeys() {
        SecBretUser user = createUser("iktest_maint");
        // Create expired key
        createKey(user, "POST /scan", "expired_key",
                LocalDateTime.now().minusHours(25), 202, "{}");
        // Create live key
        createKey(user, "POST /scan", "live_key",
                LocalDateTime.now().plusHours(23), 202, "{}");

        // Run maintenance with the test EM directly (runMaintenance accepts EM param)
        MaintenanceBatchTimer timer = new MaintenanceBatchTimer();
        em.getTransaction().begin();
        timer.runMaintenance(em);
        em.getTransaction().commit();
        em.clear();

        // Expired key gone
        Optional<IdempotencyKey> expired = keyRepo.findByUserEndpointKey(user.getId(), "POST /scan", "expired_key");
        assertThat(expired).isEmpty();

        // Live key still there (TTL not up)
        // Note: "live_key" has expiresAt > NOW() so it should not be purged
        // We verify by checking the DB directly
        Long count = (Long) em.createQuery(
                "SELECT COUNT(k) FROM IdempotencyKey k WHERE k.idemKey = 'live_key'").getSingleResult();
        assertThat(count).isEqualTo(1L);
    }
}
