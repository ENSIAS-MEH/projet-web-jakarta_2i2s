package com.secbret.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.secbret.exception.AuthorizationException;
import com.secbret.exception.ResourceNotFoundException;
import com.secbret.exception.ValidationException;
import com.secbret.model.dto.IncidentListResponse;
import com.secbret.model.dto.IncidentRequest;
import com.secbret.model.dto.IncidentResponse;
import com.secbret.model.entity.SecBretAnalysis;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.entity.SecurityTeamReview;
import com.secbret.model.entity.UserReport;
import com.secbret.model.enums.UserRole;
import com.secbret.repository.ScannedUrlRepository;
import com.secbret.repository.SecBretAnalysisRepository;
import com.secbret.repository.SecurityTeamReviewRepository;
import com.secbret.repository.UserReportRepository;
import com.secbret.repository.UserRepository;
import com.secbret.service.IncidentService;
import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import jakarta.ws.rs.core.UriInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * JAX-RS resource for incident reporting (Part III §3).
 *
 * <ul>
 *   <li>POST /api/v1/incident — submit report, 202</li>
 *   <li>GET  /api/v1/incident/{reportId} — ownership-404 (anti-enumeration)</li>
 *   <li>GET  /api/v1/incident — paginated list; REPORTER→own, ANALYST/ADMIN→all=true allowed</li>
 * </ul>
 */
@Path("/incident")
@RequestScoped
@RolesAllowed({"REPORTER", "ANALYST", "ADMIN"})
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class IncidentResource {

    private static final Logger log = LoggerFactory.getLogger(IncidentResource.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final int MAX_EVIDENCE_URLS = 5;
    private static final int MAX_URL_LENGTH = 2048;

    @Inject private IncidentService incidentService;
    @Inject private UserReportRepository reportRepository;
    @Inject private SecBretAnalysisRepository analysisRepository;
    @Inject private SecurityTeamReviewRepository reviewRepository;
    @Inject private UserRepository userRepository;
    @Inject private ScannedUrlRepository scannedUrlRepository;

    @Context private SecurityContext securityContext;
    @Context private UriInfo uriInfo;

    // =========================================================================
    // POST /incident
    // =========================================================================

    @POST
    public Response submitIncident(@Valid IncidentRequest request) {
        validateRequest(request);

        UUID userId = resolveCurrentUserId();
        String evidenceUrlsJson = serializeEvidenceUrls(request.getEvidenceUrls());

        UserReport report = incidentService.submitReport(
                request.getUrl(),
                request.getEvidenceDescription(),
                evidenceUrlsJson,
                userId);

        // Fire async analysis AFTER the persist tx committed (row now visible on worker thread)
        incidentService.triggerAnalysis(report.getId(), report.getUrl().getId());

        // 202 response with minimal body
        var body = new java.util.HashMap<String, Object>();
        body.put("reportId", report.getId());
        body.put("urlId", report.getUrl() != null ? report.getUrl().getId() : null);
        body.put("status", report.getStatus());
        body.put("createdAt", report.getCreatedAt());

        URI location = uriInfo.getAbsolutePathBuilder().path(report.getId().toString()).build();
        return Response.accepted(body).location(location).build();
    }

    // =========================================================================
    // GET /incident/{reportId}
    // =========================================================================

    @GET
    @Path("{reportId}")
    public Response getReport(@PathParam("reportId") UUID reportId) {
        UserReport report = reportRepository.findByIdEager(reportId)
                .orElseThrow(() -> new ResourceNotFoundException("user_report", reportId));

        // Ownership: REPORTER may only see own reports (anti-enumeration: return 404)
        enforceOwnership(report);

        Optional<SecBretAnalysis> analysis = analysisRepository.findByUserReportId(reportId);
        Optional<SecurityTeamReview> review = reviewRepository.findByUserReportId(reportId);

        IncidentResponse response = IncidentResponse.from(
                report,
                analysis.orElse(null),
                review.orElse(null));

        // Deserialize evidence URLs for response
        response.setEvidenceUrls(parseEvidenceUrls(report.getEvidenceUrls()));

        return Response.ok(response).build();
    }

    // =========================================================================
    // GET /incident
    // =========================================================================

    @GET
    public Response listReports(
            @QueryParam("status") String status,
            @QueryParam("all") @DefaultValue("false") boolean all,
            @QueryParam("page") @DefaultValue("1") int page,
            @QueryParam("size") @DefaultValue("20") int size) {

        size = Math.min(Math.max(size, 1), 100);
        if (page < 1) page = 1;

        if (all && isReporter()) {
            throw new AuthorizationException("REPORTER role may not use ?all=true");
        }

        List<UserReport> reports;
        long total;

        if (isReporter() || !all) {
            UUID userId = resolveCurrentUserId();
            reports = reportRepository.findByReportedByIdPage(userId, status, page, size);
            total = reportRepository.countByReportedById(userId, status);
        } else {
            reports = reportRepository.findAllPage(status, page, size);
            total = reportRepository.countAll(status);
        }

        List<IncidentResponse> items = reports.stream()
                .map(r -> {
                    Optional<SecBretAnalysis> a = analysisRepository.findByUserReportId(r.getId());
                    Optional<SecurityTeamReview> rv = reviewRepository.findByUserReportId(r.getId());
                    IncidentResponse ir = IncidentResponse.from(r, a.orElse(null), rv.orElse(null));
                    ir.setEvidenceUrls(parseEvidenceUrls(r.getEvidenceUrls()));
                    return ir;
                })
                .collect(Collectors.toList());

        return Response.ok(new IncidentListResponse(items, total, page, size)).build();
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private void validateRequest(IncidentRequest request) {
        if (request == null || request.getUrl() == null || request.getUrl().isBlank()) {
            throw new ValidationException("url is required");
        }
        if (request.getUrl().length() > MAX_URL_LENGTH) {
            throw new ValidationException("url must not exceed 2048 characters");
        }
        if (request.getEvidenceDescription() == null || request.getEvidenceDescription().length() < 10) {
            throw new ValidationException("evidenceDescription must be at least 10 characters");
        }
        if (request.getEvidenceDescription().length() > 2000) {
            throw new ValidationException("evidenceDescription must not exceed 2000 characters");
        }
        if (request.getEvidenceUrls() != null) {
            if (request.getEvidenceUrls().size() > MAX_EVIDENCE_URLS) {
                throw new ValidationException("evidenceUrls may contain at most 5 entries");
            }
            for (int i = 0; i < request.getEvidenceUrls().size(); i++) {
                String eu = request.getEvidenceUrls().get(i);
                if (eu == null || eu.isBlank() || eu.length() > MAX_URL_LENGTH) {
                    throw new ValidationException("evidenceUrls[" + i + "] is invalid (null, blank, or >2048 chars)");
                }
                if (!eu.startsWith("http://") && !eu.startsWith("https://")) {
                    throw new ValidationException("evidenceUrls[" + i + "] must be a valid HTTP(S) URL");
                }
            }
        }
    }

    private void enforceOwnership(UserReport report) {
        if (isReporter()) {
            UUID userId = resolveCurrentUserId();
            if (report.getReportedBy() == null || !userId.equals(report.getReportedBy().getId())) {
                // Anti-enumeration: 404 not 403 (§A.2)
                throw new ResourceNotFoundException("user_report", report.getId());
            }
        }
    }

    private boolean isReporter() {
        return securityContext.isUserInRole("REPORTER")
                && !securityContext.isUserInRole("ANALYST")
                && !securityContext.isUserInRole("ADMIN");
    }

    private UUID resolveCurrentUserId() {
        java.security.Principal p = securityContext.getUserPrincipal();
        if (p == null || p.getName() == null) {
            throw new ResourceNotFoundException("current user principal not available");
        }
        return userRepository.findByUsername(p.getName())
                .map(SecBretUser::getId)
                .orElseThrow(() -> new ResourceNotFoundException("user", p.getName()));
    }

    private String serializeEvidenceUrls(List<String> urls) {
        if (urls == null || urls.isEmpty()) return null;
        try {
            return MAPPER.writeValueAsString(urls);
        } catch (JsonProcessingException e) {
            throw new ValidationException("Failed to serialize evidenceUrls: " + e.getMessage());
        }
    }

    private List<String> parseEvidenceUrls(String json) {
        if (json == null || json.isBlank()) return Collections.emptyList();
        try {
            return MAPPER.readValue(json, new TypeReference<List<String>>() {});
        } catch (Exception e) {
            log.warn("Failed to parse evidenceUrls JSON: {}", e.getMessage());
            return Collections.emptyList();
        }
    }
}
