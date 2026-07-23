package com.secbret.model.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.secbret.model.entity.ScannedUrl;
import com.secbret.model.entity.ScanResult;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Response DTO for GET /api/v1/scan/url/{urlId} (Part III §2).
 *
 * <pre>
 * {
 *   "urlId": "...",
 *   "url": "...",
 *   "communityVerdict": "MALICIOUS",
 *   "lastScannedAt": "...",
 *   "latestResult": { ... }
 * }
 * </pre>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UrlScanView {

    private UUID urlId;
    private String url;
    private String communityVerdict;
    private LocalDateTime lastScannedAt;
    private ScanJobResponse.ScanResultPayload latestResult;

    public static UrlScanView from(ScannedUrl scannedUrl, ScanResult latestResult) {
        UrlScanView v = new UrlScanView();
        v.urlId = scannedUrl.getId();
        v.url = scannedUrl.getOriginalUrl();
        v.communityVerdict = scannedUrl.getCommunityVerdict() != null
                ? scannedUrl.getCommunityVerdict().name() : null;
        v.lastScannedAt = scannedUrl.getLastScannedAt();
        if (latestResult != null) {
            v.latestResult = ScanJobResponse.ScanResultPayload.from(latestResult);
        }
        return v;
    }

    public UUID getUrlId() { return urlId; }
    public String getUrl() { return url; }
    public String getCommunityVerdict() { return communityVerdict; }
    public LocalDateTime getLastScannedAt() { return lastScannedAt; }
    public ScanJobResponse.ScanResultPayload getLatestResult() { return latestResult; }
}
