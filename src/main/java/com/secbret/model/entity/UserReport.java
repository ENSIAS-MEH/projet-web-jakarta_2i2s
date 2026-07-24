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
import jakarta.persistence.Version;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Maps user_report (Part IV DDL).
 *
 * <p>status values: PENDING, PENDING_REVIEW, VERIFIED, REJECTED, FAILED (§3.9 ReportStatus)
 * <p>verdict values: VERIFIED_MALICIOUS, VERIFIED_BENIGN, REJECTED — NEVER BENIGN/SUSPICIOUS (C4).
 *
 * <p>deleted_at and version are mapped per DDL but:
 * - deleted_at: no v1 write path; no @Where (Part II §16).
 * - version: @Version for optimistic locking (mirrors scan_job).
 */
@Entity
@Table(name = "user_report")
public class UserReport {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id")
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "url_id", nullable = false)
    private ScannedUrl url;

    /** ON DELETE SET NULL — may be null after GDPR deletion. */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "reported_by")
    private SecBretUser reportedBy;

    @Column(name = "evidence_description", nullable = false, columnDefinition = "TEXT")
    private String evidenceDescription;

    /** JSONB array of URLs as JSON string. May be null if none provided. */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "evidence_urls")
    private String evidenceUrls;

    @Column(name = "status", nullable = false, length = 20)
    private String status = "PENDING";

    /**
     * Final verdict — VERIFIED_MALICIOUS, VERIFIED_BENIGN, or REJECTED only.
     * C4: NEVER write BENIGN or SUSPICIOUS here (chk_report_verdict enforces at DB level).
     */
    @Column(name = "verdict", length = 30)
    private String verdict;

    @Column(name = "error_message", columnDefinition = "TEXT")
    private String errorMessage;

    /** Optimistic locking — mirrors scan_job convention. */
    @Version
    @Column(name = "version", nullable = false)
    private long version;

    /** Soft-delete tombstone. No v1 write path; no @Where (Part II §16). */
    @Column(name = "deleted_at", insertable = false, updatable = false)
    private LocalDateTime deletedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "resolved_at")
    private LocalDateTime resolvedAt;

    @PrePersist
    void onCreate() {
        createdAt = LocalDateTime.now();
    }

    // Getters / setters

    public UUID getId() { return id; }

    public ScannedUrl getUrl() { return url; }
    public void setUrl(ScannedUrl url) { this.url = url; }

    public SecBretUser getReportedBy() { return reportedBy; }
    public void setReportedBy(SecBretUser reportedBy) { this.reportedBy = reportedBy; }

    public String getEvidenceDescription() { return evidenceDescription; }
    public void setEvidenceDescription(String evidenceDescription) { this.evidenceDescription = evidenceDescription; }

    public String getEvidenceUrls() { return evidenceUrls; }
    public void setEvidenceUrls(String evidenceUrls) { this.evidenceUrls = evidenceUrls; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getVerdict() { return verdict; }
    public void setVerdict(String verdict) { this.verdict = verdict; }

    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }

    public long getVersion() { return version; }

    public LocalDateTime getDeletedAt() { return deletedAt; }

    public LocalDateTime getCreatedAt() { return createdAt; }

    public LocalDateTime getResolvedAt() { return resolvedAt; }
    public void setResolvedAt(LocalDateTime resolvedAt) { this.resolvedAt = resolvedAt; }
}
