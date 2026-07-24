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
 * Maps V8__create_report_job.sql (Part IV §report_job).
 *
 * <h2>BLOB / Bytecode-Enhancement note (Part II §1 decision #13)</h2>
 * Hibernate bytecode enhancement is DISABLED in persistence.xml (ClassCircularityError
 * fix). {@code @Basic(LAZY)} on a {@code byte[]} without enhancement loads eagerly on
 * every SELECT. Therefore:
 * <ul>
 *   <li>{@code file_data} must NOT be loaded in list/poll paths — use constructor
 *       projections or dedicated named queries that exclude this column.</li>
 *   <li>{@code file_data} is written ONLY on the final COMPLETED status update,
 *       never on PENDING or GENERATING (decision #13 / MVCC TOAST mitigation).</li>
 * </ul>
 */
@Entity
@Table(name = "report_job")
public class ReportJob {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id")
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "url_id", nullable = false)
    private ScannedUrl url;

    /**
     * NULL after GDPR hard-delete of the requesting user (ON DELETE SET NULL).
     * Render as "[deleted]" in API responses per Part II §8.5.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "requested_by")
    private SecBretUser requestedBy;

    @Column(name = "status", nullable = false, length = 20)
    private String status = "PENDING";

    /**
     * PDF bytes — loaded ONLY in the download path.
     * Decision #13: set ONLY on the COMPLETED update; never on PENDING/GENERATING.
     * ponytail: eager load due to disabled bytecode enhancement; excluded from all
     *           list/poll queries via constructor projections.
     */
    @Column(name = "file_data")
    private byte[] fileData;

    @Column(name = "file_size_bytes")
    private Long fileSizeBytes;

    @Column(name = "error_message")
    private String errorMessage;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "completed_at")
    private LocalDateTime completedAt;

    @PrePersist
    void onCreate() {
        createdAt = LocalDateTime.now();
    }

    // Getters / setters

    public UUID getId() { return id; }
    public ScannedUrl getUrl() { return url; }
    public void setUrl(ScannedUrl url) { this.url = url; }
    public SecBretUser getRequestedBy() { return requestedBy; }
    public void setRequestedBy(SecBretUser requestedBy) { this.requestedBy = requestedBy; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public byte[] getFileData() { return fileData; }
    public void setFileData(byte[] fileData) { this.fileData = fileData; }
    public Long getFileSizeBytes() { return fileSizeBytes; }
    public void setFileSizeBytes(Long fileSizeBytes) { this.fileSizeBytes = fileSizeBytes; }
    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getCompletedAt() { return completedAt; }
    public void setCompletedAt(LocalDateTime completedAt) { this.completedAt = completedAt; }
}
