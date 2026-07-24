package com.secbret.controller;

import com.secbret.exception.ResourceNotFoundException;
import com.secbret.model.entity.ReportJob;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.entity.ShareLink;
import com.secbret.repository.ReportJobRepository;
import com.secbret.repository.UserRepository;
import com.secbret.service.ReportGenerationService;
import com.secbret.service.ShareLinkService;
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
import java.util.Optional;
import java.util.UUID;

/**
 * Krazo MVC web controller for the report-job UI (Part II §8, Part III §4).
 *
 * <h2>Routes</h2>
 * <ul>
 *   <li>POST /report/request          — request report for a URL (form submit from scan result page)</li>
 *   <li>GET  /report/status/{jobId}   — HTMX polling fragment + HX-Trigger:stopPolling on terminal</li>
 *   <li>GET  /report/{jobId}          — full report job status page</li>
 * </ul>
 */
@Controller
@RequestScoped
@Path("/report")
@RolesAllowed({"REPORTER", "ANALYST", "ADMIN"})
public class ReportWebController {

    private static final Logger log = LoggerFactory.getLogger(ReportWebController.class);
    private static final String LAYOUT = "/WEB-INF/views/layout/default.jsp";

    @Inject private Models models;
    @Inject private ReportGenerationService reportGenerationService;
    @Inject private ReportJobRepository reportJobRepository;
    @Inject private ShareLinkService shareLinkService;
    @Inject private UserRepository userRepository;

    @Context private jakarta.servlet.http.HttpServletRequest request;
    @Context private jakarta.servlet.http.HttpServletResponse httpResponse;

    // =========================================================================
    // POST /report/request — form submit from scan result page
    // =========================================================================

    @POST
    @Path("request")
    public Response requestReport(@FormParam("urlId") String urlIdStr) {
        if (urlIdStr == null || urlIdStr.isBlank()) {
            return errorPage("URL ID is required");
        }
        UUID urlId;
        try {
            urlId = UUID.fromString(urlIdStr.trim());
        } catch (IllegalArgumentException e) {
            return errorPage("Invalid URL ID format");
        }

        UUID requesterId = resolveCurrentUserId();

        ReportJob job = reportGenerationService.createJob(urlId, requesterId);

        if ("PENDING".equals(job.getStatus())) {
            reportGenerationService.triggerGeneration(job.getId(), urlId);
        }

        // Redirect to status polling page
        return Response.seeOther(URI.create("/report/" + job.getId())).build();
    }

    // =========================================================================
    // GET /report/{jobId} — full status page
    // =========================================================================

    @GET
    @Path("{jobId}")
    public Response reportStatusPage(@PathParam("jobId") UUID jobId) {
        ReportJob job = reportJobRepository.findByIdEager(jobId)
                .orElseThrow(() -> new ResourceNotFoundException("report_job", jobId));

        if (isReporter()) {
            UUID userId = resolveCurrentUserId();
            boolean isOwner = job.getRequestedBy() != null
                    && userId.equals(job.getRequestedBy().getId());
            if (!isOwner) throw new ResourceNotFoundException("report_job", jobId);
        }

        String status = job.getStatus();
        boolean isTerminal = "COMPLETED".equals(status) || "FAILED".equals(status);

        models.put("job", job);
        models.put("status", status);
        models.put("isTerminal", isTerminal);

        if ("COMPLETED".equals(status)) {
            shareLinkService.findActiveShareForJob(jobId).ifPresent(sl -> models.put("shareLink", sl));
        }

        models.put("pageTitle", "Report Generation | SecBret");
        models.put("contentView", "/WEB-INF/views/report/status.jsp");
        return Response.ok(LAYOUT).build();
    }

    // =========================================================================
    // GET /report/status/{jobId} — HTMX polling fragment
    // =========================================================================

    @GET
    @Path("status/{jobId}")
    public Response reportStatusFragment(@PathParam("jobId") UUID jobId) {
        ReportJob job = reportJobRepository.findByIdEager(jobId)
                .orElseThrow(() -> new ResourceNotFoundException("report_job", jobId));

        if (isReporter()) {
            UUID userId = resolveCurrentUserId();
            boolean isOwner = job.getRequestedBy() != null
                    && userId.equals(job.getRequestedBy().getId());
            if (!isOwner) throw new ResourceNotFoundException("report_job", jobId);
        }

        String status = job.getStatus();
        boolean isTerminal = "COMPLETED".equals(status) || "FAILED".equals(status);

        models.put("job", job);
        models.put("status", status);
        models.put("isTerminal", isTerminal);

        if (isTerminal) {
            httpResponse.setHeader("HX-Trigger", "stopPolling");
            // Reload the full page so the server-rendered terminal block
            // (share link + PDF download) replaces the polling region.
            httpResponse.setHeader("HX-Refresh", "true");
        }
        if ("COMPLETED".equals(status)) {
            shareLinkService.findActiveShareForJob(jobId).ifPresent(sl -> models.put("shareLink", sl));
        }

        return Response.ok("/WEB-INF/views/report/status-fragment.jsp").build();
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private Response errorPage(String message) {
        models.put("error", message);
        models.put("pageTitle", "Report Error | SecBret");
        models.put("contentView", "/WEB-INF/views/report/error.jsp");
        return Response.ok(LAYOUT).build();
    }

    private boolean isReporter() {
        jakarta.ws.rs.core.SecurityContext sc =
                (jakarta.ws.rs.core.SecurityContext) request.getAttribute("jakarta.ws.rs.core.SecurityContext");
        if (sc != null) {
            return sc.isUserInRole("REPORTER")
                    && !sc.isUserInRole("ANALYST")
                    && !sc.isUserInRole("ADMIN");
        }
        return request.isUserInRole("REPORTER")
                && !request.isUserInRole("ANALYST")
                && !request.isUserInRole("ADMIN");
    }

    private UUID resolveCurrentUserId() {
        String username = request.getUserPrincipal() != null ? request.getUserPrincipal().getName() : null;
        if (username == null) throw new ResourceNotFoundException("current user principal not available");
        return userRepository.findByUsername(username)
                .map(SecBretUser::getId)
                .orElseThrow(() -> new ResourceNotFoundException("user", username));
    }
}
