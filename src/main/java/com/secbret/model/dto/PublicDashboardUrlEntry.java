package com.secbret.model.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.secbret.model.entity.ScannedUrl;

import java.time.LocalDateTime;

/**
 * Single-URL lookup response for GET /api/v1/dashboard/public?url=... (Part III §7).
 *
 * <pre>
 * {
 *   "url": "https://phishing-site.com/...",
 *   "communityVerdict": "MALICIOUS",
 *   "threatScore": 0.97,
 *   "secbretReasoning": "...",
 *   "lastScannedAt": "2026-06-17T10:00:00Z"
 * }
 * </pre>
 *
 * {@code threatScore} and {@code secbretReasoning} are omitted when unavailable.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PublicDashboardUrlEntry {

    private final String url;
    private final String communityVerdict;
    private final Double threatScore;
    private final String secbretReasoning;
    private final LocalDateTime lastScannedAt;

    public PublicDashboardUrlEntry(String url, String communityVerdict,
                                   Double threatScore, String secbretReasoning,
                                   LocalDateTime lastScannedAt) {
        this.url = url;
        this.communityVerdict = communityVerdict;
        this.threatScore = threatScore;
        this.secbretReasoning = secbretReasoning;
        this.lastScannedAt = lastScannedAt;
    }

    public static PublicDashboardUrlEntry from(ScannedUrl su, Double threatScore,
                                               String secbretReasoning) {
        return new PublicDashboardUrlEntry(
                su.getOriginalUrl(),
                su.getCommunityVerdict() != null ? su.getCommunityVerdict().name() : null,
                threatScore,
                secbretReasoning,
                su.getLastScannedAt());
    }

    public String getUrl() { return url; }
    public String getCommunityVerdict() { return communityVerdict; }
    public Double getThreatScore() { return threatScore; }
    public String getSecbretReasoning() { return secbretReasoning; }
    public LocalDateTime getLastScannedAt() { return lastScannedAt; }
}
