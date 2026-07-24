package com.secbret.repository;

import com.secbret.model.entity.AuditLog;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

@ApplicationScoped
public class AuditLogRepository {

    @PersistenceContext(unitName = "SecBretPU")
    EntityManager em;

    public AuditLogRepository() {}

    /** Test constructor. */
    public AuditLogRepository(EntityManager em) { this.em = em; }

    /** Append-only — persist and never update or delete. */
    @Transactional
    public AuditLog append(AuditLog entry) {
        em.persist(entry);
        return entry;
    }
}
