package com.secbret.controller;

import com.secbret.exception.ResourceNotFoundException;
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
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Krazo MVC controller for the analyst review UI (Part III §6 / Part II §3).
 *
 * <ul>
 *   <li>GET  /admin/reviews        — queue of PENDING_REVIEW reports</li>
 *   <li>GET  /admin/reviews/{id}   — detail for one report</li>
 *   <li>POST /admin/reviews/{id}   — submit APPROVE/REJECT/MODIFY (HTMX inline)</li>
 * </ul>
 */
@Controller
@RequestScoped
@Path("/admin/reviews")
@RolesAllowed({"ANALYST", "ADMIN"})
public class AdminWebController {

    private static final Logger log = LoggerFactory.getLogger(AdminWebController.class);

    @Inject private Models models;
    @Inject private SecurityTeamReviewService reviewService;
    @Inject private UserReportRepository reportRepository;
    @Inject private SecBretAnalysisRepository analysisRepository;
    @Inject private SecurityTeamReviewRepository reviewRepository;
    @Inject private UserRepository userRepository;

    @Context private jakarta.servlet.http.HttpServletRequest request;

    // =========================================================================
    // GET /admin/reviews — queue
    // =========================================================================

    @GET
    public String reviewQueue() {
        List<UserReport> reports = reportRepository.findPendingReviewPage(1, 50);
        long total = reportRepository.countPendingReview();

        models.put("reports", reports);
        models.put("total", total);
        models.put("pageTitle", "Review Queue");
        models.put("contentView", "/WEB-INF/views/admin/review-queue.jsp");
        return "/WEB-INF/views/layout/default.jsp";
    }

    // =========================================================================
    // GET /admin/reviews/{id}
    // =========================================================================

    @GET
    @Path("{id}")
    public String reviewDetail(@PathParam("id") UUID reportId) {
        UserReport report = reportRepository.findByIdEager(reportId)
                .orElseThrow(() -> new ResourceNotFoundException("user_report", reportId));

        Optional<SecBretAnalysis> analysis = analysisRepository.findByUserReportId(reportId);
        Optional<SecurityTeamReview> existingReview = reviewRepository.findByUserReportId(reportId);

        models.put("report", report);
        models.put("analysis", analysis.orElse(null));
        models.put("existingReview", existingReview.orElse(null));
        models.put("pageTitle", "Review Report");
        models.put("contentView", "/WEB-INF/views/admin/review-detail.jsp");
        return "/WEB-INF/views/layout/default.jsp";
    }

    // =========================================================================
    // POST /admin/reviews/{id}
    // =========================================================================

    @POST
    @Path("{id}")
    public Response submitReview(
            @PathParam("id") UUID reportId,
            @FormParam("action") String action,
            @FormParam("finalVerdict") String finalVerdict,
            @FormParam("reviewerNotes") String reviewerNotes) {

        UUID reviewerId = resolveCurrentUserId();

        try {
            reviewService.submitReview(reportId, reviewerId, action, finalVerdict, reviewerNotes);
            // Redirect back to queue on success
            return Response.seeOther(URI.create("/admin/reviews")).build();
        } catch (Exception e) {
            log.warn("Review submission failed for report {}: {}", reportId, e.getMessage());
            models.put("error", e.getMessage());
            models.put("contentView", "/WEB-INF/views/admin/review-detail.jsp");
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("/WEB-INF/views/layout/default.jsp").build();
        }
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private UUID resolveCurrentUserId() {
        String username = request.getUserPrincipal() != null ? request.getUserPrincipal().getName() : null;
        if (username == null) throw new ResourceNotFoundException("current user principal not available");
        return userRepository.findByUsername(username)
                .map(SecBretUser::getId)
                .orElseThrow(() -> new ResourceNotFoundException("user", username));
    }
}
