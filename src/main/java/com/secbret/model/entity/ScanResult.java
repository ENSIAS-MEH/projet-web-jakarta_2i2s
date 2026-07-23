package com.secbret.model.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Maps V4__create_scan_result.sql.
 *
 * <p>Tier findings are JSONB; mapped as raw JSON strings via Hibernate 6
 * {@code @JdbcTypeCode(SqlTypes.JSON)}. The canonical JSONB structure is defined in
 * Part IV; typed DTOs are the scanner layer's concern (Phase 3), not the entity's.</p>
 */
@Entity
@Table(name = "scan_result")
public class ScanResult {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id")
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "url_id", nullable = false)
    private ScannedUrl url;

    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "scan_job_id", nullable = false, unique = true)
    private ScanJob scanJob;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "tier1_findings")
    private String tier1Findings;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "tier2_findings")
    private String tier2Findings;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "tier3_findings")
    private String tier3Findings;

    @Column(name = "overall_score", precision = 3, scale = 2)
    private BigDecimal overallScore;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    void onCreate() {
        createdAt = LocalDateTime.now();
    }

    public UUID getId() { return id; }
    public ScannedUrl getUrl() { return url; }
    public void setUrl(ScannedUrl url) { this.url = url; }
    public ScanJob getScanJob() { return scanJob; }
    public void setScanJob(ScanJob scanJob) { this.scanJob = scanJob; }
    public String getTier1Findings() { return tier1Findings; }
    public void setTier1Findings(String tier1Findings) { this.tier1Findings = tier1Findings; }
    public String getTier2Findings() { return tier2Findings; }
    public void setTier2Findings(String tier2Findings) { this.tier2Findings = tier2Findings; }
    public String getTier3Findings() { return tier3Findings; }
    public void setTier3Findings(String tier3Findings) { this.tier3Findings = tier3Findings; }
    public BigDecimal getOverallScore() { return overallScore; }
    public void setOverallScore(BigDecimal overallScore) { this.overallScore = overallScore; }
    public LocalDateTime getCreatedAt() { return createdAt; }
}
