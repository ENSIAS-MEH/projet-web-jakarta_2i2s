package com.secbret.model.dto;

import com.secbret.model.entity.SecBretAnalysis;
import com.secbret.model.entity.SecurityTeamReview;
import com.secbret.model.entity.UserReport;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Response for GET /incident/{reportId} and list items (Part III §3).
 *
 * <p>Shape adapts to report state:
 * - PENDING: no secbretAnalysis / securityTeamReview
 * - PENDING_REVIEW: secbretAnalysis present
 * - VERIFIED: secbretAnalysis + optionally securityTeamReview + finalVerdict + resolvedAt
 * - FAILED: errorCode + message
 */
public class IncidentResponse {

    private UUID reportId;
    private String url;
    private String status;
    private String finalVerdict;
    private String evidenceDescription;
    private List<String> evidenceUrls;
    private String errorCode;
    private String message;
    private LocalDateTime resolvedAt;
    private LocalDateTime createdAt;
    private String reportedBy;

    private AnalysisDto secbretAnalysis;
    private ReviewDto securityTeamReview;

    // Nested DTOs

    public static class AnalysisDto {
        public double threatScore;
        public String verdict;
        public String reasoningChain;
        public boolean mlConsulted;
        public Double mlScore;
        public String modelVersion;
    }

    public static class ReviewDto {
        public UUID id;
        public String reviewedBy;
        public String status;
        public String finalVerdict;
        public String reviewerNotes;
        public LocalDateTime reviewedAt;
    }

    // Builder-style static factory

    public static IncidentResponse from(UserReport report, SecBretAnalysis analysis,
                                        SecurityTeamReview review) {
        IncidentResponse r = new IncidentResponse();
        r.reportId = report.getId();
        r.url = report.getUrl() != null ? report.getUrl().getOriginalUrl() : null;
        r.status = report.getStatus();
        r.finalVerdict = report.getVerdict();
        r.evidenceDescription = report.getEvidenceDescription();
        r.resolvedAt = report.getResolvedAt();
        r.createdAt = report.getCreatedAt();
        r.reportedBy = report.getReportedBy() != null
                ? report.getReportedBy().getUsername() : "[deleted]";

        // Parse evidenceUrls JSON array → list (lazy: pass through raw or null)
        r.evidenceUrls = null; // populated by resource from raw JSON if needed

        if ("FAILED".equals(report.getStatus())) {
            r.errorCode = "ANALYSIS_FAILED";
            r.message = "Analysis could not be completed.";
            r.evidenceDescription = report.getEvidenceDescription();
        }

        if (analysis != null) {
            AnalysisDto a = new AnalysisDto();
            a.threatScore = analysis.getThreatScore().doubleValue();
            a.verdict = analysis.getVerdict();
            a.reasoningChain = analysis.getReasoningChain();
            a.mlConsulted = analysis.isMlConsulted();
            a.mlScore = analysis.getMlScore() != null ? analysis.getMlScore().doubleValue() : null;
            a.modelVersion = analysis.getModelVersion();
            r.secbretAnalysis = a;
        }

        if (review != null) {
            ReviewDto rv = new ReviewDto();
            rv.id = review.getId();
            rv.reviewedBy = review.getReviewedBy() != null
                    ? review.getReviewedBy().getUsername() : "[deleted]";
            rv.status = review.getStatus();
            rv.finalVerdict = review.getFinalVerdict();
            rv.reviewerNotes = review.getReviewerNotes();
            rv.reviewedAt = review.getReviewedAt();
            r.securityTeamReview = rv;
        }

        return r;
    }

    // Getters

    public UUID getReportId() { return reportId; }
    public String getUrl() { return url; }
    public String getStatus() { return status; }
    public String getFinalVerdict() { return finalVerdict; }
    public String getEvidenceDescription() { return evidenceDescription; }
    public List<String> getEvidenceUrls() { return evidenceUrls; }
    public void setEvidenceUrls(List<String> evidenceUrls) { this.evidenceUrls = evidenceUrls; }
    public String getErrorCode() { return errorCode; }
    public String getMessage() { return message; }
    public LocalDateTime getResolvedAt() { return resolvedAt; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public String getReportedBy() { return reportedBy; }
    public AnalysisDto getSecbretAnalysis() { return secbretAnalysis; }
    public ReviewDto getSecurityTeamReview() { return securityTeamReview; }
}
