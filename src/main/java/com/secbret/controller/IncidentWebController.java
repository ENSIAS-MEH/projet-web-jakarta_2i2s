package com.secbret.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.secbret.exception.ResourceNotFoundException;
import com.secbret.model.entity.SecBretAnalysis;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.entity.SecurityTeamReview;
import com.secbret.model.entity.UserReport;
import com.secbret.repository.SecBretAnalysisRepository;
import com.secbret.repository.SecurityTeamReviewRepository;
import com.secbret.repository.UserReportRepository;
import com.secbret.repository.UserRepository;
import com.secbret.service.IncidentService;
import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.mvc.Controller;
import jakarta.mvc.Models;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Krazo MVC controller for the incident UI (Part III §3 / Part II §3).
 *
 * <ul>
 *   <li>GET  /incident/new        — submit form</li>
 *   <li>POST /incident/submit     — create report + redirect</li>
 *   <li>GET  /incident            — list</li>
 *   <li>GET  /incident/{id}       — detail with analysis</li>
 * </ul>
 */
@Controller
@RequestScoped
@Path("/incident")
@RolesAllowed({"REPORTER", "ANALYST", "ADMIN"})
public class IncidentWebController {

    private static final Logger log = LoggerFactory.getLogger(IncidentWebController.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Inject private Models models;
    @Inject private IncidentService incidentService;
    @Inject private UserReportRepository reportRepository;
    @Inject private SecBretAnalysisRepository analysisRepository;
    @Inject private SecurityTeamReviewRepository reviewRepository;
    @Inject private UserRepository userRepository;

    @Context private jakarta.servlet.http.HttpServletRequest request;
    @Context private jakarta.servlet.http.HttpServletResponse httpResponse;

    // =========================================================================
    // GET /incident/new
    // =========================================================================

    @GET
    @Path("new")
    public String newForm() {
        models.put("pageTitle", "Report Incident");
        models.put("contentView", "/WEB-INF/views/incident/new.jsp");
        return "/WEB-INF/views/layout/default.jsp";
    }

    // =========================================================================
    // POST /incident/submit
    // =========================================================================

    @POST
    @Path("submit")
    public Response submitForm(
            @FormParam("url") String url,
            @FormParam("evidenceDescription") String evidenceDescription,
            @FormParam("evidenceUrls") String evidenceUrlsRaw) {

        // Basic server-side validation (Phase 5 will add proper Bean Validation)
        if (url == null || url.isBlank()) {
            return badRequest("URL is required", "/WEB-INF/views/incident/new.jsp");
        }

        UUID userId = resolveCurrentUserId();

        String validationError = validateEvidenceUrls(evidenceUrlsRaw);
        if (validationError != null) {
            return badRequest(validationError, "/WEB-INF/views/incident/new.jsp");
        }

        String evidenceUrlsJson = null;
        if (evidenceUrlsRaw != null && !evidenceUrlsRaw.isBlank()) {
            List<String> urls = Arrays.stream(evidenceUrlsRaw.split(","))
                    .map(String::trim)
                    .filter(s -> !s.isBlank())
                    .toList();
            try {
                evidenceUrlsJson = MAPPER.writeValueAsString(urls);
            } catch (JsonProcessingException e) {
                return badRequest("Invalid evidence URLs", "/WEB-INF/views/incident/new.jsp");
            }
        }

        try {
            UserReport report = incidentService.submitReport(url, evidenceDescription, evidenceUrlsJson, userId);
            incidentService.triggerAnalysis(report.getId(), report.getUrl().getId());
            return Response.seeOther(URI.create("/incident/" + report.getId())).build();
        } catch (Exception e) {
            log.warn("Incident submission failed: {}", e.getMessage());
            return badRequest(e.getMessage(), "/WEB-INF/views/incident/new.jsp");
        }
    }

    // =========================================================================
    // GET /incident
    // =========================================================================

    @GET
    public String listReports() {
        UUID userId = resolveCurrentUserId();
        boolean isAnalystOrAdmin = isAnalystOrAdmin();

        List<UserReport> reports;
        if (isAnalystOrAdmin) {
            reports = reportRepository.findAllPage(null, 1, 50);
        } else {
            reports = reportRepository.findByReportedByIdPage(userId, null, 1, 50);
        }

        models.put("reports", reports);
        models.put("pageTitle", "Incident Reports");
        models.put("contentView", "/WEB-INF/views/incident/list.jsp");
        return "/WEB-INF/views/layout/default.jsp";
    }

    // =========================================================================
    // GET /incident/{id}
    // =========================================================================

    @GET
    @Path("{id}")
    public String reportDetail(@PathParam("id") UUID reportId) {
        UserReport report = reportRepository.findByIdEager(reportId)
                .orElseThrow(() -> new ResourceNotFoundException("user_report", reportId));

        // REPORTER ownership check
        if (!isAnalystOrAdmin()) {
            UUID userId = resolveCurrentUserId();
            if (report.getReportedBy() == null || !userId.equals(report.getReportedBy().getId())) {
                throw new ResourceNotFoundException("user_report", reportId);
            }
        }

        Optional<SecBretAnalysis> analysis = analysisRepository.findByUserReportId(reportId);
        Optional<SecurityTeamReview> review = reviewRepository.findByUserReportId(reportId);

        models.put("report", report);
        models.put("analysis", analysis.orElse(null));
        models.put("review", review.orElse(null));
        models.put("evidenceUrls", parseEvidenceUrls(report.getEvidenceUrls()));
        models.put("pageTitle", "Incident #" + reportId);
        models.put("contentView", "/WEB-INF/views/incident/detail.jsp");
        return "/WEB-INF/views/layout/default.jsp";
    }

    // =========================================================================
    // GET /incident/{id}/status-fragment — HTMX polling fragment
    // =========================================================================

    /**
     * Polled every 3s by detail.jsp while the report is PENDING. The detail page
     * always referenced this route, but the endpoint never existed — every poll
     * 404'd (surfacing as the global error toast). On a terminal status the
     * response carries {@code HX-Trigger: stopPolling} and {@code HX-Refresh}
     * so the full page re-renders with the analysis section.
     */
    @GET
    @Path("{id}/status-fragment")
    public String statusFragment(@PathParam("id") UUID reportId) {
        UserReport report = reportRepository.findByIdEager(reportId)
                .orElseThrow(() -> new ResourceNotFoundException("user_report", reportId));

        if (!isAnalystOrAdmin()) {
            UUID userId = resolveCurrentUserId();
            if (report.getReportedBy() == null || !userId.equals(report.getReportedBy().getId())) {
                throw new ResourceNotFoundException("user_report", reportId);
            }
        }

        String status = String.valueOf(report.getStatus());
        if (!"PENDING".equals(status)) {
            httpResponse.setHeader("HX-Trigger", "stopPolling");
            httpResponse.setHeader("HX-Refresh", "true");
        }
        models.put("status", status);
        return "/WEB-INF/views/incident/status-fragment.jsp";
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Validates the raw comma-separated evidence URLs string.
     * Returns null on success, or an error message string on failure.
     * Package-private for unit testing (same pattern as ScanWebController.flattenJson).
     */
    static String validateEvidenceUrls(String evidenceUrlsRaw) {
        if (evidenceUrlsRaw == null || evidenceUrlsRaw.isBlank()) {
            return null;
        }
        List<String> urls = Arrays.stream(evidenceUrlsRaw.split(","))
                .map(String::trim)
                .filter(s -> !s.isBlank())
                .toList();
        if (urls.size() > 5) {
            return "At most 5 evidence URLs are allowed";
        }
        for (String eu : urls) {
            if (eu.length() > 2048 || !(eu.startsWith("http://") || eu.startsWith("https://"))) {
                return "Each evidence URL must be a valid HTTP(S) URL";
            }
        }
        return null;
    }

    private Response badRequest(String message, String contentView) {
        models.put("error", message);
        models.put("contentView", contentView);
        return Response.status(Response.Status.BAD_REQUEST)
                .entity("/WEB-INF/views/layout/default.jsp").build();
    }

    private UUID resolveCurrentUserId() {
        String username = request.getUserPrincipal() != null ? request.getUserPrincipal().getName() : null;
        if (username == null) throw new ResourceNotFoundException("current user principal not available");
        return userRepository.findByUsername(username)
                .map(SecBretUser::getId)
                .orElseThrow(() -> new ResourceNotFoundException("user", username));
    }

    private boolean isAnalystOrAdmin() {
        return request.isUserInRole("ANALYST") || request.isUserInRole("ADMIN");
    }

    private List<String> parseEvidenceUrls(String json) {
        if (json == null || json.isBlank()) return Collections.emptyList();
        try {
            return MAPPER.readValue(json, new TypeReference<List<String>>() {});
        } catch (Exception e) {
            return Collections.emptyList();
        }
    }
}
