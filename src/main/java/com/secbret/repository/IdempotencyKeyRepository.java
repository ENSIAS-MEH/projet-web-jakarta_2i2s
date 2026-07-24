package com.secbret.repository;

import com.secbret.model.entity.IdempotencyKey;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

import java.util.Optional;
import java.util.UUID;

@ApplicationScoped
public class IdempotencyKeyRepository {

    @PersistenceContext(unitName = "SecBretPU")
    EntityManager em;

    public IdempotencyKeyRepository() {
    }

    public IdempotencyKeyRepository(EntityManager em) {
        this.em = em;
    }

    /**
     * Finds an unexpired idempotency key for a specific user+endpoint+key triple.
     * Returns the record regardless of whether it is in-flight or complete.
     */
    public Optional<IdempotencyKey> findByUserEndpointKey(UUID userId, String endpoint, String idemKey) {
        return em.createQuery("""
                SELECT k FROM IdempotencyKey k
                  JOIN FETCH k.user u
                 WHERE u.id = :userId
                   AND k.endpoint = :endpoint
                   AND k.idemKey = :idemKey
                   AND k.expiresAt > CURRENT_TIMESTAMP
                """, IdempotencyKey.class)
                .setParameter("userId", userId)
                .setParameter("endpoint", endpoint)
                .setParameter("idemKey", idemKey)
                .getResultStream()
                .findFirst();
    }

    @Transactional
    public IdempotencyKey persist(IdempotencyKey key) {
        em.persist(key);
        em.flush(); // ensure ID is assigned; caller may need it immediately
        return key;
    }

    /**
     * Captures the response for a completed request. Sets response_status and
     * response_body atomically so in-flight → complete transition is a single UPDATE.
     */
    @Transactional
    public void captureResponse(UUID keyId, int status, String body) {
        em.createNativeQuery("""
            UPDATE idempotency_key
               SET response_status = :status,
                   response_body   = :body
             WHERE id = :id
            """)
                .setParameter("status", status)
                .setParameter("body", body)
                .setParameter("id", keyId)
                .executeUpdate();
    }
}
