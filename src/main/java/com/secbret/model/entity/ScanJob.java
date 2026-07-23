package com.secbret.model.entity;

import com.secbret.model.enums.ScanDepth;
import com.secbret.model.enums.ScanJobStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.persistence.Version;

import java.time.LocalDateTime;
import java.util.UUID;

/** Maps V3__create_scan_job.sql (+ V17 idempotent guards for superseded_by/error_message). */
@Entity
@Table(name = "scan_job")
public class ScanJob {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id")
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "url_id", nullable = false)
    private ScannedUrl url;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "submitted_by")
    private SecBretUser submittedBy;

    /**
     * Back-pointer to the job that superseded this one.
     *
     * <p><strong>Trigger-owned (Part II §1 decision #2 / V20):</strong> only the
     * {@code link_superseded_scan_job} AFTER INSERT trigger may write this column.
     * Mapped {@code insertable = false, updatable = false} so no application code
     * path — including a future refactor — can ever UPDATE it through JPA.</p>
     */
    @Column(name = "superseded_by", insertable = false, updatable = false)
    private UUID supersededBy;

    @Enumerated(EnumType.STRING)
    @Column(name = "scan_depth", nullable = false, length = 10)
    private ScanDepth scanDepth = ScanDepth.QUICK;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private ScanJobStatus status = ScanJobStatus.PENDING;

    @Version
    @Column(name = "version", nullable = false)
    private long version;

    @Column(name = "error_message")
    private String errorMessage;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "started_at")
    private LocalDateTime startedAt;

    @Column(name = "completed_at")
    private LocalDateTime completedAt;

    @PrePersist
    void onCreate() {
        createdAt = LocalDateTime.now();
    }

    public UUID getId() { return id; }
    public ScannedUrl getUrl() { return url; }
    public void setUrl(ScannedUrl url) { this.url = url; }
    public SecBretUser getSubmittedBy() { return submittedBy; }
    public void setSubmittedBy(SecBretUser submittedBy) { this.submittedBy = submittedBy; }
    public UUID getSupersededBy() { return supersededBy; }
    public ScanDepth getScanDepth() { return scanDepth; }
    public void setScanDepth(ScanDepth scanDepth) { this.scanDepth = scanDepth; }
    public ScanJobStatus getStatus() { return status; }
    public void setStatus(ScanJobStatus status) { this.status = status; }
    public long getVersion() { return version; }
    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getStartedAt() { return startedAt; }
    public void setStartedAt(LocalDateTime startedAt) { this.startedAt = startedAt; }
    public LocalDateTime getCompletedAt() { return completedAt; }
    public void setCompletedAt(LocalDateTime completedAt) { this.completedAt = completedAt; }
}
