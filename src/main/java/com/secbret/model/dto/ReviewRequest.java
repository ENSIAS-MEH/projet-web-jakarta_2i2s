package com.secbret.model.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Request body for POST /api/v1/admin/reviews/{reportId}. */
public class ReviewRequest {

    @NotBlank(message = "action is required (APPROVE, REJECT, or MODIFY)")
    private String action;        // APPROVE, REJECT, MODIFY

    private String finalVerdict;  // required for MODIFY (validated in service)

    @Size(max = 5000, message = "reviewerNotes must not exceed 5000 characters")
    private String reviewerNotes; // optional, max 5000 chars

    public ReviewRequest() {}

    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }

    public String getFinalVerdict() { return finalVerdict; }
    public void setFinalVerdict(String finalVerdict) { this.finalVerdict = finalVerdict; }

    public String getReviewerNotes() { return reviewerNotes; }
    public void setReviewerNotes(String reviewerNotes) { this.reviewerNotes = reviewerNotes; }
}
