package com.secbret.controller;

import com.secbret.exception.ResourceNotFoundException;
import com.secbret.exception.ValidationException;
import com.secbret.model.entity.ScanJob;
import com.secbret.model.entity.ScanResult;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.enums.ScanDepth;
import com.secbret.model.enums.ScanJobStatus;
import com.secbret.repository.ScanJobRepository;
import com.secbret.repository.ScanResultRepository;
import com.secbret.repository.UserRepository;
import com.secbret.service.ScanExecutor;
import com.secbret.service.ScanPersistence;
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
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Jakarta MVC (Krazo) web controller for the scan UI (Part III §2 / Part II §3).
 *
 * <h2>Routes</h2>
 * <ul>
 *   <li>GET  /scan/new                     — submit form</li>
 *   <li>POST /scan/submit                  — create job + redirect to status page</li>
 *   <li>GET  /scan/status/{jobId}          — HTMX polling fragment (partial HTML)</li>
 *   <li>GET  /scan/{id}                    — full result page</li>
 * </ul>
 *
 * <h2>HTMX polling contract (Part II §3)</h2>
 * The status fragment is requested every 3 seconds by the status.jsp polling container.
 * When the job reaches a terminal state (COMPLETED or FAILED), the response includes
 * {@code HX-Trigger: stopPolling}; the client removes the polling element (Part V §1.2).
 */
@Controller
@RequestScoped
@Path("/scan")
@RolesAllowed({"REPORTER", "ANALYST", "ADMIN"})
public class ScanWebController {

    private static final Logger log = LoggerFactory.getLogger(ScanWebController.class);
    private static final String LAYOUT = "/WEB-INF/views/layout/default.jsp";

    @Inject
    private Models models;

    @Inject
    private ScanPersistence scanPersistence;

    @Inject
    private ScanExecutor scanExecutor;

    @Inject
    private ScanJobRepository scanJobRepository;

    @Inject
    private ScanResultRepository scanResultRepository;

    @Inject
    private UserRepository userRepository;

    @Context
    private jakarta.servlet.http.HttpServletRequest request;

    @Context
    private jakarta.servlet.http.HttpServletResponse httpResponse;

    // =========================================================================
    // GET /scan/new — scan submission form
    // =========================================================================

    @GET
    @Path("new")
    public String showNewScan() {
        models.put("pageTitle", "Submit URL | SecBret");
        models.put("contentView", "/WEB-INF/views/scan/new.jsp");
        return LAYOUT;
    }

    // =========================================================================
    // POST /scan/submit — create job, redirect to status page
    // =========================================================================

    @POST
    @Path("submit")
    public String submitScan(@FormParam("url") String url,
                              @FormParam("depth") String depth) {
        ScanDepth scanDepth = ScanDepth.QUICK;
        if (depth != null && !depth.isBlank()) {
            try {
                scanDepth = ScanDepth.valueOf(depth.toUpperCase());
            } catch (IllegalArgumentException e) {
                models.put("pageTitle", "Submit URL | SecBret");
                models.put("error", "Depth must be QUICK or DEEP.");
                models.put("formUrl", url);
                models.put("contentView", "/WEB-INF/views/scan/new.jsp");
                return LAYOUT;
            }
        }

        if (url == null || url.isBlank()) {
            models.put("pageTitle", "Submit URL | SecBret");
            models.put("error", "URL is required.");
            models.put("contentView", "/WEB-INF/views/scan/new.jsp");
            return LAYOUT;
        }

        UUID userId = resolveCurrentUserId();

        ScanJob job;
        try {
            job = scanPersistence.createJob(url, userId, scanDepth);
        } catch (ValidationException e) {
            models.put("pageTitle", "Submit URL | SecBret");
            models.put("error", e.getMessage());
            models.put("formUrl", url);
            models.put("contentView", "/WEB-INF/views/scan/new.jsp");
            return LAYOUT;
        } catch (Exception e) {
            log.error("Web scan submit failed for url={}", url, e);
            models.put("pageTitle", "Submit URL | SecBret");
            models.put("error", "Failed to create scan job: " + e.getMessage());
            models.put("formUrl", url);
            models.put("contentView", "/WEB-INF/views/scan/new.jsp");
            return LAYOUT;
        }

        scanExecutor.submit(job.getId());

        return "redirect:/scan/" + job.getId() + "?polling=true";
    }

    // =========================================================================
    // GET /scan/status/{jobId} — HTMX polling fragment
    // =========================================================================

    /**
     * Returns a partial HTML fragment for the HTMX polling container (Part II §3).
     *
     * <p>Terminal states (COMPLETED, FAILED, SUPERSEDED) cause the response header
     * {@code HX-Trigger: stopPolling} to be emitted; the client-side HTMX listener
     * in status.jsp removes the polling element on receiving it (Part V §1.2).
     *
     * @param jobId the scan job UUID
     * @return partial JSP fragment path
     */
    @GET
    @Path("status/{jobId}")
    public String statusFragment(@PathParam("jobId") UUID jobId) {
        ScanJob job = scanJobRepository.findByIdEager(jobId)
                .orElseThrow(() -> new ResourceNotFoundException("scan_job", jobId));

        enforceJobOwnership(job);

        ScanJobStatus status = job.getStatus();
        boolean isTerminal = status == ScanJobStatus.COMPLETED
                || status == ScanJobStatus.FAILED
                || status == ScanJobStatus.SUPERSEDED;

        if (isTerminal) {
            // Signal the HTMX client to stop polling (Part II §3 / Part V §1.2).
            httpResponse.setHeader("HX-Trigger", "stopPolling");
            // Full-page reload so result.jsp re-renders with the findings section,
            // which is only emitted server-side for terminal states.
            httpResponse.setHeader("HX-Refresh", "true");
        }

        models.put("job", job);
        models.put("status", status.name());
        models.put("isTerminal", isTerminal);

        if (status == ScanJobStatus.COMPLETED) {
            Optional<ScanResult> result = scanResultRepository.findByScanJobId(jobId);
            result.ifPresent(r -> models.put("result", r));
        }

        return "/WEB-INF/views/scan/status-fragment.jsp";
    }

    // =========================================================================
    // GET /scan — scan job list (own jobs for REPORTER, all for ANALYST/ADMIN)
    // =========================================================================

    @GET
    public String listScans() {
        UUID ownerId = isReporter() ? resolveCurrentUserId() : null;
        models.put("jobs", scanJobRepository.findPage(ownerId, null, null, 1, 50));
        models.put("pageTitle", "My Scans | SecBret");
        models.put("contentView", "/WEB-INF/views/scan/list.jsp");
        return LAYOUT;
    }

    // =========================================================================
    // GET /scan/{id} — full result page
    // =========================================================================

    @GET
    @Path("{id}")
    public String showResult(@PathParam("id") UUID id,
                              @jakarta.ws.rs.QueryParam("polling") String polling) {
        ScanJob job = scanJobRepository.findByIdEager(id)
                .orElseThrow(() -> new ResourceNotFoundException("scan_job", id));

        enforceJobOwnership(job);

        models.put("pageTitle", "Scan Result | SecBret");
        models.put("job", job);
        models.put("jobId", id.toString());
        models.put("polling", polling != null);
        models.put("isTerminal",
                job.getStatus() == ScanJobStatus.COMPLETED
                        || job.getStatus() == ScanJobStatus.FAILED
                        || job.getStatus() == ScanJobStatus.SUPERSEDED);

        if (job.getStatus() == ScanJobStatus.COMPLETED) {
            Optional<ScanResult> result = scanResultRepository.findByScanJobId(id);
            result.ifPresent(r -> {
                models.put("result", r);
                Map<String, Map<String, String>> tiers = new LinkedHashMap<>();
                tiers.put("Tier 1 — Passive reconnaissance", flattenJson(r.getTier1Findings()));
                if (r.getTier2Findings() != null) {
                    tiers.put("Tier 2 — Content analysis (deep scan)", flattenJson(r.getTier2Findings()));
                }
                if (r.getTier3Findings() != null) {
                    tiers.put("Tier 3 — Phishing kit detection (deep scan)", flattenJson(r.getTier3Findings()));
                }
                models.put("tierFindings", tiers);
            });
        }

        models.put("contentView", "/WEB-INF/views/scan/result.jsp");
        return LAYOUT;
    }

    // =========================================================================
    // Findings JSON → flat label/value map for JSP rendering
    // =========================================================================

    private static final ObjectMapper FINDINGS_MAPPER = new ObjectMapper();

    /**
     * Flattens a findings JSON document into an ordered {@code path → value} map
     * so the result view can render a definition table instead of a raw JSON dump.
     */
    static Map<String, String> flattenJson(String json) {
        Map<String, String> flat = new LinkedHashMap<>();
        if (json == null || json.isBlank()) {
            return flat;
        }
        try {
            flattenNode("", FINDINGS_MAPPER.readTree(json), flat);
        } catch (JsonProcessingException e) {
            // Unparseable stored findings: fall back to the raw string rather than hiding data.
            flat.put("raw", json);
        }
        return flat;
    }

    private static void flattenNode(String prefix, JsonNode node, Map<String, String> out) {
        if (node.isObject()) {
            node.fields().forEachRemaining(e -> flattenNode(
                    prefix.isEmpty() ? e.getKey() : prefix + "." + e.getKey(), e.getValue(), out));
        } else if (node.isArray()) {
            if (node.isEmpty()) {
                out.put(prefix, "none");
            } else {
                for (int i = 0; i < node.size(); i++) {
                    flattenNode(prefix + "[" + (i + 1) + "]", node.get(i), out);
                }
            }
        } else {
            out.put(prefix, node.asText());
        }
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private void enforceJobOwnership(ScanJob job) {
        if (isReporter()) {
            UUID userId = resolveCurrentUserId();
            if (job.getSubmittedBy() == null
                    || !userId.equals(job.getSubmittedBy().getId())) {
                throw new ResourceNotFoundException("scan_job", job.getId());
            }
        }
    }

    private boolean isReporter() {
        return request.isUserInRole("REPORTER")
                && !request.isUserInRole("ANALYST")
                && !request.isUserInRole("ADMIN");
    }

    private UUID resolveCurrentUserId() {
        java.security.Principal principal = request.getUserPrincipal();
        if (principal == null || principal.getName() == null) {
            throw new ResourceNotFoundException("current user principal not available");
        }
        return userRepository.findByUsername(principal.getName())
                .map(SecBretUser::getId)
                .orElseThrow(() -> new ResourceNotFoundException("user", principal.getName()));
    }
}
