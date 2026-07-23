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

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Maps secbret_analysis (Part IV DDL).
 *
 * <p><strong>C4 — AI-only verdict domain.</strong>
 * {@code verdict} is constrained by {@code chk_analysis_verdict} to BENIGN/SUSPICIOUS ONLY.
 * VERIFIED_MALICIOUS, VERIFIED_BENIGN, REJECTED MUST NEVER be written here.
 * Those live on user_report.verdict and security_team_review.final_verdict.
 */
@Entity
@Table(name = "secbret_analysis")
public class SecBretAnalysis {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id")
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "url_id", nullable = false)
    private ScannedUrl url;

    /** ON DELETE SET NULL */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scan_result_id")
    private ScanResult scanResult;

    /** ON DELETE SET NULL */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_report_id")
    private UserReport userReport;

    @Column(name = "threat_score", nullable = false, precision = 3, scale = 2)
    private BigDecimal threatScore;

    /**
     * AI tentative verdict: BENIGN or SUSPICIOUS only (chk_analysis_verdict).
     * C4: NEVER write VERIFIED_MALICIOUS/VERIFIED_BENIGN/REJECTED here.
     */
    @Column(name = "verdict", nullable = false, length = 30)
    private String verdict;

    @Column(name = "reasoning_chain", nullable = false, columnDefinition = "TEXT")
    private String reasoningChain;

    @Column(name = "ml_consulted", nullable = false)
    private boolean mlConsulted;

    @Column(name = "ml_score", precision = 3, scale = 2)
    private BigDecimal mlScore;

    /** ML sidecar model version at classification time; NULL when rules-only. */
    @Column(name = "model_version", length = 50)
    private String modelVersion;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    void onCreate() {
        createdAt = LocalDateTime.now();
    }

    // Getters / setters

    public UUID getId() { return id; }

    public ScannedUrl getUrl() { return url; }
    public void setUrl(ScannedUrl url) { this.url = url; }

    public ScanResult getScanResult() { return scanResult; }
    public void setScanResult(ScanResult scanResult) { this.scanResult = scanResult; }

    public UserReport getUserReport() { return userReport; }
    public void setUserReport(UserReport userReport) { this.userReport = userReport; }

    public BigDecimal getThreatScore() { return threatScore; }
    public void setThreatScore(BigDecimal threatScore) { this.threatScore = threatScore; }

    public String getVerdict() { return verdict; }
    public void setVerdict(String verdict) { this.verdict = verdict; }

    public String getReasoningChain() { return reasoningChain; }
    public void setReasoningChain(String reasoningChain) { this.reasoningChain = reasoningChain; }

    public boolean isMlConsulted() { return mlConsulted; }
    public void setMlConsulted(boolean mlConsulted) { this.mlConsulted = mlConsulted; }

    public BigDecimal getMlScore() { return mlScore; }
    public void setMlScore(BigDecimal mlScore) { this.mlScore = mlScore; }

    public String getModelVersion() { return modelVersion; }
    public void setModelVersion(String modelVersion) { this.modelVersion = modelVersion; }

    public LocalDateTime getCreatedAt() { return createdAt; }
}
