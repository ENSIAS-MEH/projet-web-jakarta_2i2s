package com.secbret.controller;

import com.secbret.exception.ValidationException;
import com.secbret.model.dto.PublicDashboardEntry;
import com.secbret.model.dto.PublicDashboardResponse;
import com.secbret.model.entity.ScannedUrl;
import com.secbret.model.enums.CommunityVerdict;
import com.secbret.repository.ScanResultRepository;
import com.secbret.repository.ScannedUrlRepository;
import jakarta.annotation.security.PermitAll;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.mvc.Controller;
import jakarta.mvc.Models;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Jakarta MVC (Krazo) web controller for the public dashboard (Part III §7).
 *
 * <h2>Routes</h2>
 * <ul>
 *   <li>GET /dashboard/public — anonymous, no auth required</li>
 * </ul>
 *
 * <p>@PermitAll ensures the Jakarta Security layer grants access without a session.
 * No CSRF token required (public read-only per Part II §5).
 */
@Controller
@RequestScoped
@Path("/dashboard/public")
@PermitAll
public class PublicDashboardWebController {

    private static final Logger log = LoggerFactory.getLogger(PublicDashboardWebController.class);
    private static final String LAYOUT = "/WEB-INF/views/layout/default.jsp";
    private static final int MAX_SIZE = 50;

    @Inject
    private Models models;

    @Inject
    private ScannedUrlRepository scannedUrlRepository;

    @Inject
    private ScanResultRepository scanResultRepository;

    // =========================================================================
    // GET /dashboard/public
    // =========================================================================

    @GET
    public String showPublicDashboard(
            @QueryParam("verdict") String verdictParam,
            @QueryParam("page") @DefaultValue("1") int page,
            @QueryParam("size") @DefaultValue("20") int size) {

        // ---- Validate and clamp ----
        CommunityVerdict verdictFilter = null;
        String verdictError = null;
        if (verdictParam != null && !verdictParam.isBlank()) {
            switch (verdictParam.toUpperCase()) {
                case "MALICIOUS": verdictFilter = CommunityVerdict.MALICIOUS; break;
                case "BENIGN":    verdictFilter = CommunityVerdict.BENIGN;    break;
                default:
                    verdictError = "Invalid verdict filter '" + verdictParam
                            + "'. Use MALICIOUS or BENIGN.";
            }
        }

        if (page < 1) page = 1;
        size = Math.max(1, Math.min(size, MAX_SIZE));

        if (verdictError != null) {
            models.put("pageTitle", "Community Verdicts | SecBret");
            models.put("error", verdictError);
            models.put("entries", List.of());
            models.put("totalElements", 0L);
            models.put("totalPages", 0);
            models.put("currentPage", 1);
            models.put("pageSize", size);
            // verdictFilter intentionally omitted on the error path — raw param is not displayed
            models.put("verdictFilter", "");
            models.put("contentView", "/WEB-INF/views/dashboard/public.jsp");
            return LAYOUT;
        }

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

        int totalPages = size > 0 ? (int) Math.ceil((double) total / size) : 0;

        models.put("pageTitle", "Community Verdicts | SecBret");
        models.put("entries", entries);
        models.put("totalElements", total);
        models.put("totalPages", totalPages);
        models.put("currentPage", page);
        models.put("pageSize", size);
        models.put("verdictFilter", verdictParam != null ? verdictParam.toUpperCase() : "");
        models.put("contentView", "/WEB-INF/views/dashboard/public.jsp");
        return LAYOUT;
    }
}
