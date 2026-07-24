package com.secbret.model.dto;

import com.secbret.model.entity.ShareLink;

import java.time.LocalDateTime;

/** Response for POST /share (201) and entries in GET /share list. */
public class ShareLinkResponse {

    private String uuid;
    private String downloadUrl;
    private String htmlViewUrl;
    private LocalDateTime expiresAt;
    // list view extras
    private String url;
    private String reportJobId;
    private LocalDateTime createdAt;
    private boolean isRevoked;
    private int accessCount;

    public static ShareLinkResponse from(ShareLink link) {
        ShareLinkResponse r = new ShareLinkResponse();
        r.uuid = link.getUuidToken();
        r.downloadUrl = "/api/v1/share/" + link.getUuidToken();
        r.htmlViewUrl = "/share/" + link.getUuidToken();
        r.expiresAt = link.getExpiresAt();
        r.createdAt = link.getCreatedAt();
        r.isRevoked = link.isRevoked();
        r.accessCount = link.getAccessCount();
        if (link.getReportJob() != null) {
            r.reportJobId = link.getReportJob().getId() != null ? link.getReportJob().getId().toString() : null;
            if (link.getReportJob().getUrl() != null) {
                r.url = link.getReportJob().getUrl().getOriginalUrl();
            }
        }
        return r;
    }

    public String getUuid() { return uuid; }
    public String getDownloadUrl() { return downloadUrl; }
    public String getHtmlViewUrl() { return htmlViewUrl; }
    public LocalDateTime getExpiresAt() { return expiresAt; }
    public String getUrl() { return url; }
    public String getReportJobId() { return reportJobId; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public boolean isRevoked() { return isRevoked; }
    public int getAccessCount() { return accessCount; }
}
