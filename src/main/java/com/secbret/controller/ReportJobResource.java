package com.secbret.controller;

import com.secbret.exception.ResourceNotFoundException;
import com.secbret.model.dto.ReportJobResponse;
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
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;
import java.util.UUID;

/**
 * REST resource for report jobs (Part III §4).
 *
 * <ul>
 *   <li>POST /api/v1/report-jobs/{urlId}  — 202; roles REPORTER/ANALYST/ADMIN</li>
 *   <li>GET  /api/v1/report-jobs/{jobId}  — 200; ownership 404-not-403</li>
 * </ul>
 *
 * Note: POST and GET use DIFFERENT path parameters ({urlId} vs {jobId})
 * per spec §4 C1 fix. They are on SEPARATE @Path methods so Jersey/JAX-RS
 * can match them without ambiguity.
 */
@Path("/report-jobs")
@RequestScoped
@RolesAllowed({"REPORTER", "ANALYST", "ADMIN"})
@Produces(MediaType.APPLICATION_JSON)
public class ReportJobResource {

    private static final Logger log = LoggerFactory.getLogger(ReportJobResource.class);

    @Inject private ReportGenerationService reportGenerationService;
    @Inject private ReportJobRepository reportJobRepository;
    @Inject private ShareLinkService shareLinkService;
    @Inject private UserRepository userRepository;

    @Context private SecurityContext securityContext;

    // =========================================================================
    // POST /report-jobs/{urlId}
    // =========================================================================

    @POST
    @Path("{urlId}")
    public Response createReportJob(@PathParam("urlId") UUID urlId) {
        UUID requesterId = resolveCurrentUserId();

        // createJob is @Transactional; idempotent de-dup happens inside it
        ReportJob job = reportGenerationService.createJob(urlId, requesterId);

        // Fire async generation AFTER the persist tx committed (mirrors ScanResource→ScanExecutor)
        // Only trigger for a brand-new PENDING job (not the returned de-duped one, it's already running)
        if ("PENDING".equals(job.getStatus())) {
            reportGenerationService.triggerGeneration(job.getId(), urlId);
        }

        ReportJobResponse body = ReportJobResponse.from(job, null);
        return Response.accepted(body).build();
    }

    // =========================================================================
    // GET /report-jobs/{jobId}
    // =========================================================================

    @GET
    @Path("{jobId}")
    public Response getReportJob(@PathParam("jobId") UUID jobId) {
        ReportJob job = reportJobRepository.findByIdEager(jobId)
                .orElseThrow(() -> new ResourceNotFoundException("report_job", jobId));

        // Ownership check: 404-not-403 (anti-enumeration §A.2)
        enforceOwnership(job);

        Optional<ShareLink> shareLink = Optional.empty();
        if ("COMPLETED".equals(job.getStatus())) {
            shareLink = shareLinkService.findActiveShareForJob(jobId);
        }

        ReportJobResponse body = ReportJobResponse.from(job, shareLink.orElse(null));
        return Response.ok(body).build();
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private void enforceOwnership(ReportJob job) {
        if (isReporter()) {
            UUID userId = resolveCurrentUserId();
            boolean isOwner = job.getRequestedBy() != null
                    && userId.equals(job.getRequestedBy().getId());
            if (!isOwner) {
                throw new ResourceNotFoundException("report_job", job.getId());
            }
        }
        // ANALYST and ADMIN can see all jobs
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
}
