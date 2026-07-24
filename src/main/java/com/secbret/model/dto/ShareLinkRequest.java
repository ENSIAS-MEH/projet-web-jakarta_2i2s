package com.secbret.model.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import java.util.UUID;

/** POST /share request body (Part III §5). */
public class ShareLinkRequest {

    @NotNull(message = "reportJobId is required")
    private UUID reportJobId;

    @Min(value = 1, message = "expiryDays must be at least 1")
    @Max(value = 365, message = "expiryDays must not exceed 365")
    private Integer expiryDays; // 1-365, default 30

    public UUID getReportJobId() { return reportJobId; }
    public void setReportJobId(UUID reportJobId) { this.reportJobId = reportJobId; }
    public Integer getExpiryDays() { return expiryDays; }
    public void setExpiryDays(Integer expiryDays) { this.expiryDays = expiryDays; }
}
