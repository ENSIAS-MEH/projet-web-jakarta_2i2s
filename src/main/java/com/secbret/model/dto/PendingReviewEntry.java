package com.secbret.model.dto;

import com.secbret.model.entity.SecBretAnalysis;
import com.secbret.model.entity.UserReport;

import java.time.LocalDateTime;
import java.util.UUID;

/** One entry in GET /api/v1/admin/reviews/pending list. */
public class PendingReviewEntry {

    private UUID reportId;
    private String url;
    private Double threatScore;
    private String verdict;
    private String reportedBy;
    private LocalDateTime reportedAt;

    public static PendingReviewEntry from(UserReport report, SecBretAnalysis analysis) {
        PendingReviewEntry e = new PendingReviewEntry();
        e.reportId = report.getId();
        e.url = report.getUrl() != null ? report.getUrl().getOriginalUrl() : null;
        e.threatScore = analysis != null ? analysis.getThreatScore().doubleValue() : null;
        e.verdict = analysis != null ? analysis.getVerdict() : null;
        e.reportedBy = report.getReportedBy() != null
                ? report.getReportedBy().getUsername() : "[deleted]";
        e.reportedAt = report.getCreatedAt();
        return e;
    }

    public UUID getReportId() { return reportId; }
    public String getUrl() { return url; }
    public Double getThreatScore() { return threatScore; }
    public String getVerdict() { return verdict; }
    public String getReportedBy() { return reportedBy; }
    public LocalDateTime getReportedAt() { return reportedAt; }
}
