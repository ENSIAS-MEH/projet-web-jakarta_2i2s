package com.secbret.controller;

import com.secbret.exception.ResourceNotFoundException;
import com.secbret.model.dto.PendingReviewEntry;
import com.secbret.model.dto.PendingReviewListResponse;
import com.secbret.model.dto.ReviewRequest;
import com.secbret.model.dto.ReviewResponse;
import com.secbret.model.entity.SecBretAnalysis;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.entity.SecurityTeamReview;
import com.secbret.model.entity.UserReport;
import com.secbret.repository.SecBretAnalysisRepository;
import com.secbret.repository.SecurityTeamReviewRepository;
import com.secbret.repository.UserReportRepository;
import com.secbret.repository.UserRepository;
import com.secbret.service.SecurityTeamReviewService;
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

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Security team review REST endpoints (Part III §6).
 *
 * <ul>
 *   <li>GET  /api/v1/admin/reviews/pending — list PENDING_REVIEW reports</li>
 *   <li>GET  /api/v1/admin/reviews/{reportId} — full detail with analysis</li>
 *   <li>POST /api/v1/admin/reviews/{reportId} — submit APPROVE/REJECT/MODIFY</li>
 * </ul>
 *
 * All endpoints require ANALYST or ADMIN role.
 */
@Path("/admin/reviews")
@RequestScoped
@RolesAllowed({"ANALYST", "ADMIN"})
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class AdminReviewResource {

    @Inject private SecurityTeamReviewService reviewService;
    @Inject private UserReportRepository reportRepository;
    @Inject private SecBretAnalysisRepository analysisRepository;
    @Inject private SecurityTeamReviewRepository reviewRepository;
    @Inject private UserRepository userRepository;

    @Context private SecurityContext securityContext;

    // =========================================================================
    // GET /admin/reviews/pending
    // =========================================================================

    @GET
    @Path("pending")
    public Response getPendingReviews(
            @QueryParam("page") @DefaultValue("1") int page,
            @QueryParam("size") @DefaultValue("20") int size,
            @QueryParam("sortBy") @DefaultValue("createdAt") String sortBy,
            @QueryParam("sortOrder") @DefaultValue("asc") String sortOrder) {

        size = Math.min(Math.max(size, 1), 100);
        if (page < 1) page = 1;

        List<UserReport> reports = reportRepository.findPendingReviewPage(page, size);
        long total = reportRepository.countPendingReview();

        List<PendingReviewEntry> entries = reports.stream()
                .map(r -> {
                    Optional<SecBretAnalysis> a = analysisRepository.findByUserReportId(r.getId());
                    return PendingReviewEntry.from(r, a.orElse(null));
                })
                .collect(Collectors.toList());

        return Response.ok(new PendingReviewListResponse(entries, total, page, size)).build();
    }

    // =========================================================================
    // GET /admin/reviews/{reportId}
    // =========================================================================

    @GET
    @Path("{reportId}")
    public Response getReviewDetail(@PathParam("reportId") UUID reportId) {
        UserReport report = reportRepository.findByIdEager(reportId)
                .orElseThrow(() -> new ResourceNotFoundException("user_report", reportId));

        Optional<SecBretAnalysis> analysis = analysisRepository.findByUserReportId(reportId);

        // Build detail response
        var body = new java.util.HashMap<String, Object>();
        body.put("reportId", report.getId());
        body.put("url", report.getUrl() != null ? report.getUrl().getOriginalUrl() : null);
        body.put("reportedBy", buildReportedByEntry(report));
        body.put("evidence", java.util.Map.of(
                "description", report.getEvidenceDescription(),
                "urls", report.getEvidenceUrls() != null ? report.getEvidenceUrls() : "[]"
        ));
        analysis.ifPresent(a -> body.put("secbretAnalysis", buildAnalysisMap(a)));

        return Response.ok(body).build();
    }

    // =========================================================================
    // POST /admin/reviews/{reportId}
    // =========================================================================

    @POST
    @Path("{reportId}")
    public Response submitReview(@PathParam("reportId") UUID reportId,
                                  @Valid ReviewRequest request) {
        UUID reviewerId = resolveCurrentUserId();

        SecurityTeamReview review = reviewService.submitReview(
                reportId,
                reviewerId,
                request.getAction(),
                request.getFinalVerdict(),
                request.getReviewerNotes());

        return Response.ok(ReviewResponse.from(review)).build();
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private java.util.Map<String, Object> buildReportedByEntry(UserReport report) {
        var m = new java.util.HashMap<String, Object>();
        if (report.getReportedBy() != null) {
            m.put("id", report.getReportedBy().getId());
            m.put("username", report.getReportedBy().getUsername());
        } else {
            m.put("username", "[deleted]");
        }
        return m;
    }

    private java.util.Map<String, Object> buildAnalysisMap(SecBretAnalysis a) {
        var m = new java.util.HashMap<String, Object>();
        m.put("threatScore", a.getThreatScore().doubleValue());
        m.put("verdict", a.getVerdict());
        m.put("reasoningChain", a.getReasoningChain());
        m.put("mlConsulted", a.isMlConsulted());
        m.put("mlScore", a.getMlScore() != null ? a.getMlScore().doubleValue() : null);
        m.put("modelVersion", a.getModelVersion());
        return m;
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
}
