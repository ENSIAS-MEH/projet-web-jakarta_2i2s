package com.secbret.service;

import com.secbret.model.entity.AuditLog;
import com.secbret.model.entity.SecBretUser;
import com.secbret.repository.AuditLogRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.UUID;

/**
 * Append-only audit log writer (Part IV V18 / Part II §8.5 Actions logged).
 *
 * <p>Every call creates a new immutable row. Never updates or deletes rows.
 */
@ApplicationScoped
public class AuditLogService {

    @Inject
    private AuditLogRepository repo;

    protected AuditLogService() {}

    @Inject
    public AuditLogService(AuditLogRepository repo) {
        this.repo = repo;
    }

    /**
     * Append an audit log entry.
     *
     * @param actor      the user performing the action (may be null for system actions)
     * @param action     action string, e.g. "REVIEW_APPROVED" (Part IV V18)
     * @param targetType e.g. "user_report"
     * @param targetId   UUID of the target entity
     * @param detail     optional JSONB-compatible JSON string
     */
    public void log(SecBretUser actor, String action, String targetType, UUID targetId, String detail) {
        AuditLog entry = new AuditLog();
        entry.setActor(actor);
        entry.setActorUsername(actor != null ? actor.getUsername() : null);
        entry.setAction(action);
        entry.setTargetType(targetType);
        entry.setTargetId(targetId);
        entry.setDetail(detail);
        repo.append(entry);
    }
}
