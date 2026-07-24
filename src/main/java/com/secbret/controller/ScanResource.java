package com.secbret.controller;

import com.secbret.exception.AuthorizationException;
import com.secbret.exception.ResourceNotFoundException;
import com.secbret.exception.ValidationException;
import com.secbret.model.dto.ScanJobResponse;
import com.secbret.model.dto.ScanListResponse;
import com.secbret.model.dto.ScanRequest;
import com.secbret.model.dto.UrlScanView;
import com.secbret.model.entity.ScanJob;
import com.secbret.model.entity.ScanResult;
import com.secbret.model.entity.ScannedUrl;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.enums.ScanDepth;
import com.secbret.model.enums.ScanJobStatus;
import com.secbret.model.enums.UserRole;
import com.secbret.repository.ScanJobRepository;
import com.secbret.repository.ScanResultRepository;
import com.secbret.repository.ScannedUrlRepository;
import com.secbret.repository.UserRepository;
import com.secbret.service.ScanExecutor;
import com.secbret.service.ScanPersistence;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * JAX-RS resource for URL scanning operations (Part III §2).
 *
 * <h2>Authorization semantics (Part II §A.2)</h2>
 * <ul>
 *   <li>Ownership failures return 404 (anti-enumeration), never 403.</li>
 *   <li>?all=true misuse by REPORTER returns 403 (role-permission failure).</li>
 * </ul>
 *
 * <h2>Endpoints</h2>
 * <ul>
 *   <li>POST /api/v1/scan — submit URL, 202 Accepted + job representation</li>
 *   <li>GET  /api/v1/scan/{jobId} — poll job status / result</li>
 *   <li>GET  /api/v1/scan — list jobs (with pagination + filters)</li>
 *   <li>GET  /api/v1/scan/url/{urlId} — latest consolidated result for a URL</li>
 * </ul>
 *
 * <p>Rate limiting is Phase 5 — not added here per task scope.
 */
@Path("/scan")
@RequestScoped
@RolesAllowed({"REPORTER", "ANALYST", "ADMIN"})
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class ScanResource {

    private static final Logger log = LoggerFactory.getLogger(ScanResource.class);

    @Inject
    private ScanPersistence scanPersistence;

    @Inject
    private ScanExecutor scanExecutor;

    @Inject
    private ScanJobRepository scanJobRepository;

    @Inject
    private ScanResultRepository scanResultRepository;

    @Inject
    private ScannedUrlRepository scannedUrlRepository;

    @Inject
    private UserRepository userRepository;

    @Context
    private SecurityContext securityContext;

    // =========================================================================
    // POST /scan
    // =========================================================================

    /**
     * Submit a URL for scanning (Part III §2 POST /scan).
     *
     * <p>Returns 202 Accepted immediately; processing is async. If a PENDING/RUNNING
     * job exists for the same URL, it is superseded by the V20 trigger.
     *
     * @param request body {url, depth}
     * @return 202 with job representation
     */
    @POST
    public Response submitScan(@Valid ScanRequest request) {
        String rawUrl = request.getUrl();
        ScanDepth depth = parseScanDepth(request.getDepth());

        UUID userId = resolveCurrentUserId();

        ScanJob job;
        try {
            job = scanPersistence.createJob(rawUrl, userId, depth);
        } catch (com.secbret.exception.ValidationException e) {
            throw e; // let the mapper handle it → 400
        }

        // Kick off async execution — fire and forget (result tracked via DB job status).
        scanExecutor.submit(job.getId());

        ScanJobResponse response = ScanJobResponse.from(job);
        return Response.accepted(response).build();
    }

    // =========================================================================
    // GET /scan/{jobId}
    // =========================================================================

    /**
     * Poll the status and result of a scan job (Part III §2 GET /scan/{jobId}).
     *
     * <p>REPORTER may only view their own jobs; unauthorized access returns 404
     * (anti-enumeration per §A.2), not 403.
     *
     * @param jobId the scan job UUID
     * @return 200 with job status + optional result
     */
    @GET
    @Path("{jobId}")
    public Response getJob(@PathParam("jobId") UUID jobId) {
        ScanJob job = scanJobRepository.findByIdEager(jobId)
                .orElseThrow(() -> new ResourceNotFoundException("scan_job", jobId));

        enforceJobOwnership(job);

        if (job.getStatus() == ScanJobStatus.COMPLETED) {
            Optional<ScanResult> result = scanResultRepository.findByScanJobId(jobId);
            return Response.ok(ScanJobResponse.fromCompleted(job, result.orElse(null))).build();
        }
        return Response.ok(ScanJobResponse.from(job)).build();
    }

    // =========================================================================
    // GET /scan
    // =========================================================================

    /**
     * List scan jobs with optional filters and pagination (Part III §2 GET /scan).
     *
     * <p>REPORTER sees only their own jobs.
     * ANALYST/ADMIN may pass {@code all=true} to see all users' jobs.
     * REPORTER + {@code all=true} → 403 (role-permission failure, not ownership).
     *
     * @param all     if true, show jobs for all users (ANALYST/ADMIN only)
     * @param status  optional status filter
     * @param depth   optional depth filter
     * @param page    1-based page number (default 1)
     * @param size    page size (default 20, max 100)
     */
    @GET
    public Response listScans(
            @QueryParam("all") @DefaultValue("false") boolean all,
            @QueryParam("status") String status,
            @QueryParam("depth") String depth,
            @QueryParam("page") @DefaultValue("1") int page,
            @QueryParam("size") @DefaultValue("20") int size) {

        // Clamp size to spec maximum of 100.
        size = Math.min(size, 100);
        if (size < 1) size = 20;
        if (page < 1) page = 1;

        boolean isReporter = isReporter();

        if (all && isReporter) {
            // REPORTER using ?all=true → 403 (role-permission failure, not ownership).
            throw new AuthorizationException("REPORTER role may not use ?all=true");
        }

        // Determine the ownerFilter: null means "all users" (ANALYST/ADMIN with all=true)
        UUID ownerFilter = null;
        if (isReporter || !all) {
            ownerFilter = resolveCurrentUserId();
        }

        ScanJobStatus statusFilter = parseStatusFilter(status);
        ScanDepth depthFilter = parseDepthFilter(depth);

        long total = scanJobRepository.count(ownerFilter, statusFilter, depthFilter);
        List<ScanJob> jobs = scanJobRepository.findPage(ownerFilter, statusFilter, depthFilter, page, size);

        List<ScanJobResponse> items = jobs.stream()
                .map(ScanJobResponse::from)
                .collect(Collectors.toList());

        return Response.ok(new ScanListResponse(items, total, page, size)).build();
    }

    // =========================================================================
    // GET /scan/url/{urlId}
    // =========================================================================

    /**
     * Latest consolidated result for a URL (Part III §2 GET /scan/url/{urlId}).
     *
     * <p>REPORTER may only view URLs for which they have submitted at least one scan job
     * (any historical job, including superseded). Unauthorized access returns 404
     * (ownership-hidden, anti-enumeration — never 403, per §A.2 and §4).
     *
     * @param urlId the scanned_url UUID
     * @return 200 with URL scan view
     */
    @GET
    @Path("url/{urlId}")
    public Response getUrlView(@PathParam("urlId") UUID urlId) {
        ScannedUrl scannedUrl = scannedUrlRepository.findById(urlId)
                .orElseThrow(() -> new ResourceNotFoundException("scanned_url", urlId));

        // REPORTER ownership check: 404 if REPORTER has never scanned this URL (§A.2).
        if (isReporter()) {
            UUID userId = resolveCurrentUserId();
            if (!scanJobRepository.existsByUrlIdAndSubmittedBy(urlId, userId)) {
                // Return 404 to conceal the URL's existence (anti-enumeration).
                throw new ResourceNotFoundException("scanned_url", urlId);
            }
        }

        Optional<ScanResult> latestResult = scanResultRepository.findLatestByUrlId(urlId);
        return Response.ok(UrlScanView.from(scannedUrl, latestResult.orElse(null))).build();
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Enforce ownership for a scan job: REPORTER may only see their own jobs.
     * Returns 404 on unauthorized access (anti-enumeration per §A.2).
     */
    private void enforceJobOwnership(ScanJob job) {
        if (isReporter()) {
            UUID userId = resolveCurrentUserId();
            // submittedBy may be null for legacy/anonymous jobs; treat as not-owned.
            if (job.getSubmittedBy() == null
                    || !userId.equals(job.getSubmittedBy().getId())) {
                // 404 not 403 — hides resource existence from unauthorized reporter.
                throw new ResourceNotFoundException("scan_job", job.getId());
            }
        }
        // ANALYST / ADMIN may see all jobs.
    }

    private boolean isReporter() {
        return securityContext.isUserInRole("REPORTER")
                && !securityContext.isUserInRole("ANALYST")
                && !securityContext.isUserInRole("ADMIN");
    }

    /**
     * Resolve the current user's UUID from their username (via UserRepository).
     * Throws ResourceNotFoundException if the principal is missing (shouldn't happen
     * because @RolesAllowed ensures authentication).
     */
    private UUID resolveCurrentUserId() {
        java.security.Principal principal = securityContext.getUserPrincipal();
        if (principal == null || principal.getName() == null) {
            throw new ResourceNotFoundException("current user principal not available");
        }
        return userRepository.findByUsername(principal.getName())
                .map(SecBretUser::getId)
                .orElseThrow(() -> new ResourceNotFoundException("user", principal.getName()));
    }

    private ScanDepth parseScanDepth(String depth) {
        if (depth == null || depth.isBlank()) {
            return ScanDepth.QUICK;
        }
        try {
            return ScanDepth.valueOf(depth.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new ValidationException("depth must be QUICK or DEEP");
        }
    }

    private ScanJobStatus parseStatusFilter(String status) {
        if (status == null || status.isBlank()) {
            return null;
        }
        try {
            return ScanJobStatus.valueOf(status.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new ValidationException("status must be one of: PENDING, RUNNING, COMPLETED, SUPERSEDED, FAILED");
        }
    }

    private ScanDepth parseDepthFilter(String depth) {
        if (depth == null || depth.isBlank()) {
            return null;
        }
        try {
            return ScanDepth.valueOf(depth.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new ValidationException("depth must be QUICK or DEEP");
        }
    }
}
