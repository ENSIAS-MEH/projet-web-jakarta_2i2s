package com.secbret.model.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.secbret.model.entity.ScannedUrl;

import java.time.LocalDateTime;

/**
 * Single URL entry in the public dashboard list (Part III §7).
 *
 * <pre>
 * {
 *   "url": "https://phishing-site.com/...",
 *   "communityVerdict": "MALICIOUS",
 *   "threatScore": 0.97,
 *   "lastScannedAt": "2026-06-17T10:00:00Z"
 * }
 * </pre>
 *
 * {@code threatScore} is omitted when no scan result is associated.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PublicDashboardEntry {

    private final String url;
    private final String communityVerdict;
    private final Double threatScore;
    private final LocalDateTime lastScannedAt;

    public PublicDashboardEntry(String url, String communityVerdict,
                                Double threatScore, LocalDateTime lastScannedAt) {
        this.url = url;
        this.communityVerdict = communityVerdict;
        this.threatScore = threatScore;
        this.lastScannedAt = lastScannedAt;
    }

    /**
     * Build from a ScannedUrl entity; threatScore requires a join to scan_result
     * and is passed in separately (null if no result row exists).
     */
    public static PublicDashboardEntry from(ScannedUrl su, Double threatScore) {
        return new PublicDashboardEntry(
                su.getOriginalUrl(),
                su.getCommunityVerdict() != null ? su.getCommunityVerdict().name() : null,
                threatScore,
                su.getLastScannedAt());
    }

    public String getUrl() { return url; }
    public String getCommunityVerdict() { return communityVerdict; }
    public Double getThreatScore() { return threatScore; }
    public LocalDateTime getLastScannedAt() { return lastScannedAt; }
}
