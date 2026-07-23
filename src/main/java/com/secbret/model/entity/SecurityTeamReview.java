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

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Maps security_team_review (Part IV DDL).
 *
 * <p><strong>C4 — Final-verdict domain.</strong>
 * {@code finalVerdict} stores VERIFIED_MALICIOUS, VERIFIED_BENIGN, or REJECTED.
 * BENIGN and SUSPICIOUS are AI-only values that must never appear here.
 *
 * <p>status values: APPROVED, REJECTED, MODIFIED (chk_review_status).
 *
 * <p>created_at and reviewed_at both set at POST /admin/reviews/{reportId} time in v1
 * (no draft state — Part II §8.5 security_team_review Timestamps).
 */
@Entity
@Table(name = "security_team_review")
public class SecurityTeamReview {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id")
    private UUID id;

    /** UNIQUE NOT NULL — one review per report. ON DELETE CASCADE. */
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_report_id", nullable = false, unique = true)
    private UserReport userReport;

    /** NOT NULL — secbret_analysis_id is required (§16.5 FAILED path exists to handle missing analysis). */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "secbret_analysis_id", nullable = false)
    private SecBretAnalysis secbretAnalysis;

    /** ON DELETE SET NULL — null after GDPR account deletion. */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "reviewed_by")
    private SecBretUser reviewedBy;

    /** status: APPROVED, REJECTED, or MODIFIED (chk_review_status). */
    @Column(name = "status", nullable = false, length = 20)
    private String status;

    @Column(name = "reviewer_notes", columnDefinition = "TEXT")
    private String reviewerNotes;

    /**
     * final_verdict: VERIFIED_MALICIOUS, VERIFIED_BENIGN, or REJECTED (chk_review_verdict).
     * C4: NEVER write BENIGN or SUSPICIOUS here.
     */
    @Column(name = "final_verdict", nullable = false, length = 30)
    private String finalVerdict;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    /** Both created_at and reviewed_at are set together in v1 (§8.5). */
    @Column(name = "reviewed_at")
    private LocalDateTime reviewedAt;

    @PrePersist
    void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        createdAt = now;
        reviewedAt = now;   // v1: no draft state; set both at insert time
    }

    // Getters / setters

    public UUID getId() { return id; }

    public UserReport getUserReport() { return userReport; }
    public void setUserReport(UserReport userReport) { this.userReport = userReport; }

    public SecBretAnalysis getSecbretAnalysis() { return secbretAnalysis; }
    public void setSecbretAnalysis(SecBretAnalysis secbretAnalysis) { this.secbretAnalysis = secbretAnalysis; }

    public SecBretUser getReviewedBy() { return reviewedBy; }
    public void setReviewedBy(SecBretUser reviewedBy) { this.reviewedBy = reviewedBy; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getReviewerNotes() { return reviewerNotes; }
    public void setReviewerNotes(String reviewerNotes) { this.reviewerNotes = reviewerNotes; }

    public String getFinalVerdict() { return finalVerdict; }
    public void setFinalVerdict(String finalVerdict) { this.finalVerdict = finalVerdict; }

    public LocalDateTime getCreatedAt() { return createdAt; }

    public LocalDateTime getReviewedAt() { return reviewedAt; }
    public void setReviewedAt(LocalDateTime reviewedAt) { this.reviewedAt = reviewedAt; }
}
