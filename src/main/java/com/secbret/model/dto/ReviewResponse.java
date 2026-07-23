package com.secbret.model.dto;

import com.secbret.model.entity.SecurityTeamReview;

import java.time.LocalDateTime;
import java.util.UUID;

/** Response for POST /api/v1/admin/reviews/{reportId}. */
public class ReviewResponse {

    private UUID reviewId;
    private UUID reportId;
    private String reviewedBy;
    private String status;
    private String finalVerdict;
    private LocalDateTime reviewedAt;

    public static ReviewResponse from(SecurityTeamReview review) {
        ReviewResponse r = new ReviewResponse();
        r.reviewId = review.getId();
        r.reportId = review.getUserReport() != null ? review.getUserReport().getId() : null;
        r.reviewedBy = review.getReviewedBy() != null
                ? review.getReviewedBy().getUsername() : "[deleted]";
        r.status = review.getStatus();
        r.finalVerdict = review.getFinalVerdict();
        r.reviewedAt = review.getReviewedAt();
        return r;
    }

    public UUID getReviewId() { return reviewId; }
    public UUID getReportId() { return reportId; }
    public String getReviewedBy() { return reviewedBy; }
    public String getStatus() { return status; }
    public String getFinalVerdict() { return finalVerdict; }
    public LocalDateTime getReviewedAt() { return reviewedAt; }
}
