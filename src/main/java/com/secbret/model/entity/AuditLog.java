package com.secbret.model.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Maps audit_log (Part IV V18 DDL). Append-only — never update or delete.
 *
 * <p>actor_username is a snapshot captured at insert time (before GDPR delete);
 * the V20 tombstone trigger updates it to 'deleted_{uuid}' if the actor is deleted.
 */
@Entity
@Table(name = "audit_log")
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id")
    private UUID id;

    /** ON DELETE SET NULL — nullified after GDPR deletion. V20 trigger writes tombstone first. */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "actor_id")
    private SecBretUser actor;

    /** Snapshot of username at insert time. V20 trigger tombstones to 'deleted_{uuid}'. */
    @Column(name = "actor_username", length = 50)
    private String actorUsername;

    @Column(name = "action", nullable = false, length = 100)
    private String action;

    @Column(name = "target_type", length = 50)
    private String targetType;

    @Column(name = "target_id")
    private UUID targetId;

    /** JSONB detail blob. */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "detail")
    private String detail;

    @Column(name = "internal_error_details", columnDefinition = "TEXT")
    private String internalErrorDetails;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    void onCreate() {
        createdAt = LocalDateTime.now();
    }

    // Getters (append-only; no setters for id/createdAt)

    public UUID getId() { return id; }

    public SecBretUser getActor() { return actor; }
    public void setActor(SecBretUser actor) { this.actor = actor; }

    public String getActorUsername() { return actorUsername; }
    public void setActorUsername(String actorUsername) { this.actorUsername = actorUsername; }

    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }

    public String getTargetType() { return targetType; }
    public void setTargetType(String targetType) { this.targetType = targetType; }

    public UUID getTargetId() { return targetId; }
    public void setTargetId(UUID targetId) { this.targetId = targetId; }

    public String getDetail() { return detail; }
    public void setDetail(String detail) { this.detail = detail; }

    public String getInternalErrorDetails() { return internalErrorDetails; }
    public void setInternalErrorDetails(String internalErrorDetails) { this.internalErrorDetails = internalErrorDetails; }

    public LocalDateTime getCreatedAt() { return createdAt; }
}
