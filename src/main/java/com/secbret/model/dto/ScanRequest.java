package com.secbret.model.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Request body for POST /api/v1/scan (Part III §2).
 *
 * <p>Bean Validation enforces structural constraints before any normalization
 * is applied. The {@code depth} field accepts both cases; it is normalized to
 * uppercase by {@code ScanResource} before being converted to {@code ScanDepth}.
 */
public class ScanRequest {

    @NotBlank(message = "url is required")
    @Size(max = 2048, message = "url must not exceed 2048 characters")
    private String url;

    /** Optional: QUICK (default) or DEEP. Both cases accepted (§2 table). */
    private String depth;

    public ScanRequest() {
    }

    public ScanRequest(String url, String depth) {
        this.url = url;
        this.depth = depth;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getDepth() {
        return depth;
    }

    public void setDepth(String depth) {
        this.depth = depth;
    }
}
