package com.secbret.controller;

import com.secbret.exception.ResourceNotFoundException;
import com.secbret.exception.ValidationException;
import com.secbret.model.dto.PublicDashboardEntry;
import com.secbret.model.dto.PublicDashboardResponse;
import com.secbret.model.dto.PublicDashboardUrlEntry;
import com.secbret.model.entity.ScanResult;
import com.secbret.model.entity.ScannedUrl;
import com.secbret.model.enums.CommunityVerdict;
import com.secbret.repository.ScanResultRepository;
import com.secbret.repository.ScannedUrlRepository;
import com.secbret.scanner.UrlNormalizer;
import jakarta.annotation.security.PermitAll;

import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Public (anonymous) dashboard REST resource — GET /api/v1/dashboard/public (Part III §7).
 *
 * <p>No authentication required (@PermitAll). No CSRF (public read-only per Part II §5).
 * No rate limiting (Phase 5). Does not write community_verdict (Phase 4 Lane A).
 *
 * <h2>Filtering (Part III §7)</h2>
 * Only MALICIOUS and BENIGN verdicts are surfaced. SUSPICIOUS is never written in v1;
 * UNKNOWN/NULL entries are deliberately excluded. Any other ?verdict value → 400.
 *
 * <h2>Soft-delete</h2>
 * deleted_at IS NULL filter applied at query level; no @Where on the entity (Part II §16).
 */
@Path("/dashboard/public")
@RequestScoped
@PermitAll
@Produces(MediaType.APPLICATION_JSON)
public class PublicDashboardResource {

    private static final Logger log = LoggerFactory.getLogger(PublicDashboardResource.class);

    /** Spec §7: default page size 20, max 50. */
    private static final int MAX_SIZE = 50;

    @Inject
    private ScannedUrlRepository scannedUrlRepository;

    @Inject
    private ScanResultRepository scanResultRepository;

    @Inject
    private UrlNormalizer urlNormalizer;

    // =========================================================================
    // GET /api/v1/dashboard/public
    // =========================================================================

    /**
     * List URLs with an established community verdict, or look up a single URL.
     *
     * @param verdictParam optional; MALICIOUS or BENIGN only (per spec §7)
     * @param urlParam     optional; if provided, single-URL lookup
     * @param page         1-based page (default 1)
     * @param size         page size (default 20, max 50)
     */
    @GET
    public Response getPublicDashboard(
            @QueryParam("verdict") String verdictParam,
            @QueryParam("url") String urlParam,
            @QueryParam("page") @DefaultValue("1") int page,
            @QueryParam("size") @DefaultValue("20") int size) {

        // ---- Single URL lookup ----
        if (urlParam != null && !urlParam.isBlank()) {
            return handleUrlLookup(urlParam);
        }

        // ---- Verdict filter validation ----
        CommunityVerdict verdictFilter = parseVerdictFilter(verdictParam);

        // ---- Clamp pagination ----
        if (page < 1) page = 1;
        size = Math.max(1, Math.min(size, MAX_SIZE));

        long total = scannedUrlRepository.countPublicDashboard(verdictFilter);
        List<ScannedUrl> urls = scannedUrlRepository.findPublicDashboardPage(verdictFilter, page, size);

        List<PublicDashboardEntry> entries = urls.stream()
                .map(su -> {
                    Double score = scanResultRepository.findLatestByUrlId(su.getId())
                            .map(r -> r.getOverallScore() != null
                                    ? r.getOverallScore().doubleValue() : null)
                            .orElse(null);
                    return PublicDashboardEntry.from(su, score);
                })
                .collect(Collectors.toList());

        return Response.ok(new PublicDashboardResponse(entries, total, page, size)).build();
    }

    // =========================================================================
    // Single URL lookup (Part III §7 ?url= parameter)
    // =========================================================================

    private Response handleUrlLookup(String rawUrl) {
        String hash;
        try {
            // hash() normalizes then SHA-256s the result (UrlNormalizer design).
            hash = urlNormalizer.hash(rawUrl);
        } catch (ValidationException e) {
            // Malformed URL → 404 (consistent with "URL not found or no community verdict")
            log.debug("Public dashboard URL lookup: invalid URL '{}': {}", rawUrl, e.getMessage());
            throw new ResourceNotFoundException("No community verdict found for the given URL");
        }

        ScannedUrl su = scannedUrlRepository.findPublicDashboardByHash(hash)
                .orElseThrow(() ->
                        new ResourceNotFoundException("No community verdict found for the given URL"));

        Double score = scanResultRepository.findLatestByUrlId(su.getId())
                .map(r -> r.getOverallScore() != null ? r.getOverallScore().doubleValue() : null)
                .orElse(null);

        // secbretReasoning: not yet available from the Phase 4 analysis tables (null is fine).
        return Response.ok(PublicDashboardUrlEntry.from(su, score, null)).build();
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Parse and validate the ?verdict filter.
     *
     * <p>Per Part III §7: only MALICIOUS and BENIGN are filterable;
     * SUSPICIOUS and UNKNOWN are not surfaced on the public dashboard.
     * Any other value → 400 ValidationException.
     * Null/blank → both verdicts (no filter).
     */
    private CommunityVerdict parseVerdictFilter(String verdictParam) {
        if (verdictParam == null || verdictParam.isBlank()) {
            return null; // both MALICIOUS + BENIGN
        }
        switch (verdictParam.toUpperCase()) {
            case "MALICIOUS": return CommunityVerdict.MALICIOUS;
            case "BENIGN":    return CommunityVerdict.BENIGN;
            default:
                throw new ValidationException(
                        "verdict must be MALICIOUS or BENIGN (or omitted for all)");
        }
    }
}
