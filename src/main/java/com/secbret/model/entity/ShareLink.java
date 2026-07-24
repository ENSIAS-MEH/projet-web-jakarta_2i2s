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

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Maps V9__create_share_link.sql (Part IV §share_link).
 *
 * <h2>access_count concurrency (Part IV)</h2>
 * {@code access_count} MUST be incremented via atomic SQL:
 * <pre>
 *   UPDATE share_link SET access_count = access_count + 1, last_accessed_at = NOW() WHERE id = :id
 * </pre>
 * Never use ORM read-modify-write — concurrent readers produce lost updates.
 *
 * <h2>GDPR</h2>
 * {@code created_by} is NULL after hard-delete of the creating user (ON DELETE SET NULL).
 */
@Entity
@Table(name = "share_link")
public class ShareLink {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id")
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "report_job_id", nullable = false)
    private ReportJob reportJob;

    /**
     * NULL after GDPR hard-delete of the creating user (ON DELETE SET NULL).
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "created_by")
    private SecBretUser createdBy;

    @Column(name = "uuid_token", nullable = false, length = 36, unique = true)
    private String uuidToken;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "is_revoked", nullable = false)
    private boolean isRevoked = false;

    @Column(name = "access_count", nullable = false)
    private int accessCount = 0;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "last_accessed_at")
    private LocalDateTime lastAccessedAt;

    @PrePersist
    void onCreate() {
        createdAt = LocalDateTime.now();
        if (uuidToken == null) {
            uuidToken = UUID.randomUUID().toString();
        }
    }

    // Getters / setters

    public UUID getId() { return id; }
    public ReportJob getReportJob() { return reportJob; }
    public void setReportJob(ReportJob reportJob) { this.reportJob = reportJob; }
    public SecBretUser getCreatedBy() { return createdBy; }
    public void setCreatedBy(SecBretUser createdBy) { this.createdBy = createdBy; }
    public String getUuidToken() { return uuidToken; }
    public void setUuidToken(String uuidToken) { this.uuidToken = uuidToken; }
    public LocalDateTime getExpiresAt() { return expiresAt; }
    public void setExpiresAt(LocalDateTime expiresAt) { this.expiresAt = expiresAt; }
    public boolean isRevoked() { return isRevoked; }
    public void setRevoked(boolean revoked) { isRevoked = revoked; }
    public int getAccessCount() { return accessCount; }
    public void setAccessCount(int accessCount) { this.accessCount = accessCount; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getLastAccessedAt() { return lastAccessedAt; }
    public void setLastAccessedAt(LocalDateTime lastAccessedAt) { this.lastAccessedAt = lastAccessedAt; }
}
