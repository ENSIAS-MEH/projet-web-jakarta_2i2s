package com.secbret.model.dto;

import com.secbret.model.entity.ReportJob;
import com.secbret.model.entity.ShareLink;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Response DTO for GET /report-jobs/{jobId} (Part III §4).
 *
 * Shape varies by status:
 * - PENDING/GENERATING: jobId, urlId, status, createdAt
 * - COMPLETED: + shareLink embedded object, fileSizeBytes, completedAt
 * - FAILED: + errorMessage
 */
public class ReportJobResponse {

    private UUID jobId;
    private UUID urlId;
    private String status;
    private LocalDateTime createdAt;
    private LocalDateTime completedAt;
    private Long fileSizeBytes;
    private String errorMessage;
    private ShareLinkEmbed shareLink;

    /** Nested share link embed for COMPLETED response. */
    public static class ShareLinkEmbed {
        private String uuid;
        private String downloadUrl;
        private String htmlViewUrl;
        private LocalDateTime expiresAt;

        public ShareLinkEmbed() {}

        public String getUuid() { return uuid; }
        public void setUuid(String uuid) { this.uuid = uuid; }
        public String getDownloadUrl() { return downloadUrl; }
        public void setDownloadUrl(String downloadUrl) { this.downloadUrl = downloadUrl; }
        public String getHtmlViewUrl() { return htmlViewUrl; }
        public void setHtmlViewUrl(String htmlViewUrl) { this.htmlViewUrl = htmlViewUrl; }
        public LocalDateTime getExpiresAt() { return expiresAt; }
        public void setExpiresAt(LocalDateTime expiresAt) { this.expiresAt = expiresAt; }
    }

    public static ReportJobResponse from(ReportJob job, ShareLink activeLink) {
        ReportJobResponse r = new ReportJobResponse();
        r.jobId = job.getId();
        r.urlId = job.getUrl() != null ? job.getUrl().getId() : null;
        r.status = job.getStatus();
        r.createdAt = job.getCreatedAt();
        r.completedAt = job.getCompletedAt();
        r.fileSizeBytes = job.getFileSizeBytes();
        r.errorMessage = job.getErrorMessage();

        if ("COMPLETED".equals(job.getStatus()) && activeLink != null) {
            ShareLinkEmbed embed = new ShareLinkEmbed();
            embed.uuid = activeLink.getUuidToken();
            embed.downloadUrl = "/api/v1/share/" + activeLink.getUuidToken();
            embed.htmlViewUrl = "/share/" + activeLink.getUuidToken();
            embed.expiresAt = activeLink.getExpiresAt();
            r.shareLink = embed;
        }
        return r;
    }

    // Getters
    public UUID getJobId() { return jobId; }
    public UUID getUrlId() { return urlId; }
    public String getStatus() { return status; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getCompletedAt() { return completedAt; }
    public Long getFileSizeBytes() { return fileSizeBytes; }
    public String getErrorMessage() { return errorMessage; }
    public ShareLinkEmbed getShareLink() { return shareLink; }
}
