package com.secbret.controller;

import com.secbret.exception.ResourceNotFoundException;
import com.secbret.exception.ValidationException;
import com.secbret.model.dto.ShareLinkListResponse;
import com.secbret.model.dto.ShareLinkRequest;
import com.secbret.model.dto.ShareLinkResponse;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.entity.ShareLink;
import com.secbret.repository.ReportJobRepository;
import com.secbret.repository.UserRepository;
import com.secbret.service.ReportGenerationService;
import com.secbret.service.ShareLinkService;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * REST resource for share links (Part III §5).
 *
 * <ul>
 *   <li>GET    /api/v1/share/{uuid}  — anonymous; JSON or PDF by Accept header; 410 expired/revoked</li>
 *   <li>DELETE /api/v1/share/{uuid}  — REPORTER own / ANALYST / ADMIN; 404-not-403 for not-yours</li>
 *   <li>POST   /api/v1/share         — REPORTER/ANALYST/ADMIN; creates share link for completed job</li>
 *   <li>GET    /api/v1/share         — REPORTER/ANALYST/ADMIN; paginated list of own links</li>
 * </ul>
 */
@Path("/share")
@RequestScoped
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class ShareLinkResource {

    private static final Logger log = LoggerFactory.getLogger(ShareLinkResource.class);
    private static final int DEFAULT_EXPIRY_DAYS = 30;
    private static final int MAX_EXPIRY_DAYS = 365;

    @Inject private ShareLinkService shareLinkService;
    @Inject private ReportGenerationService reportGenerationService;
    @Inject private ReportJobRepository reportJobRepository;
    @Inject private UserRepository userRepository;

    @Context private SecurityContext securityContext;
    @Context private HttpHeaders httpHeaders;

    // =========================================================================
    // GET /share/{uuid} — anonymous (PermitAll)
    // =========================================================================

    @GET
    @Path("{uuid}")
    @PermitAll
    @Produces({MediaType.APPLICATION_JSON, "application/pdf", MediaType.WILDCARD})
    public Response getSharedReport(@PathParam("uuid") String uuid,
                                    @QueryParam("format") String format) {
        Optional<ShareLink> linkOpt = shareLinkService.findByToken(uuid);

        if (linkOpt.isEmpty()) {
            // Not found at all → 404
            throw new ResourceNotFoundException("share_link", uuid);
        }

        ShareLink link = linkOpt.get();

        // Expired or revoked → 410 Gone
        if (!shareLinkService.isValid(link)) {
            return Response.status(Response.Status.GONE)
                    .entity("{\"error\":\"Share link has expired or been revoked\",\"status\":410}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        // Record access atomically
        shareLinkService.recordAccess(link.getId());

        // Respond by Accept header, or ?format=pdf for plain browser links
        // (an <a href> always sends Accept: text/html, so content negotiation
        // alone can never serve the PDF to a browser download link).
        List<String> accept = httpHeaders.getRequestHeader(HttpHeaders.ACCEPT);
        boolean wantPdf = "pdf".equalsIgnoreCase(format)
                || (accept != null && accept.stream()
                        .anyMatch(a -> a.contains("application/pdf")));

        if (wantPdf) {
            // PDF download
            byte[] pdfBytes = reportJobRepository.loadFileData(link.getReportJob().getId())
                    .orElse(null);
            if (pdfBytes == null || pdfBytes.length == 0) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("{\"error\":\"PDF not available\",\"status\":404}")
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }
            return Response.ok(pdfBytes, "application/pdf")
                    .header("Content-Disposition",
                            "attachment; filename=\"secbret-report-" + uuid + ".pdf\"")
                    .header("Content-Length", pdfBytes.length)
                    .build();
        }

        // JSON summary
        return Response.ok(buildJsonSummary(link)).build();
    }

    // =========================================================================
    // DELETE /share/{uuid} — REPORTER own / ANALYST / ADMIN
    // =========================================================================

    @DELETE
    @Path("{uuid}")
    @RolesAllowed({"REPORTER", "ANALYST", "ADMIN"})
    public Response revokeShareLink(@PathParam("uuid") String uuid) {
        UUID callerId = resolveCurrentUserId();
        boolean isReporter = isReporter();

        shareLinkService.revoke(uuid, callerId, isReporter);

        return Response.noContent().build();
    }

    // =========================================================================
    // POST /share — REPORTER/ANALYST/ADMIN
    // =========================================================================

    @POST
    @RolesAllowed({"REPORTER", "ANALYST", "ADMIN"})
    public Response createShareLink(@Valid ShareLinkRequest request) {
        if (request == null || request.getReportJobId() == null) {
            throw new ValidationException("reportJobId is required");
        }
        int expiryDays = request.getExpiryDays() != null ? request.getExpiryDays() : DEFAULT_EXPIRY_DAYS;
        if (expiryDays < 1 || expiryDays > MAX_EXPIRY_DAYS) {
            throw new ValidationException("expiryDays must be between 1 and 365");
        }

        UUID requesterId = resolveCurrentUserId();

        // REPORTER ownership check: may only create links for own completed jobs
        if (isReporter()) {
            var job = reportJobRepository.findByIdEager(request.getReportJobId())
                    .orElseThrow(() -> new ResourceNotFoundException("report_job", request.getReportJobId()));
            boolean isOwner = job.getRequestedBy() != null
                    && requesterId.equals(job.getRequestedBy().getId());
            if (!isOwner) {
                throw new ResourceNotFoundException("report_job", request.getReportJobId());
            }
        }

        ShareLink link = reportGenerationService.createShareLink(
                request.getReportJobId(), requesterId, expiryDays);

        return Response.status(Response.Status.CREATED)
                .entity(ShareLinkResponse.from(link))
                .build();
    }

    // =========================================================================
    // GET /share — paginated list of own links
    // =========================================================================

    @GET
    @RolesAllowed({"REPORTER", "ANALYST", "ADMIN"})
    public Response listShareLinks(
            @QueryParam("page") @DefaultValue("1") int page,
            @QueryParam("size") @DefaultValue("20") int size) {

        size = Math.min(Math.max(size, 1), 100);
        if (page < 1) page = 1;

        UUID userId = resolveCurrentUserId();
        List<ShareLink> links = shareLinkService.listOwn(userId, page, size);
        long total = shareLinkService.countOwn(userId);

        List<ShareLinkResponse> items = links.stream()
                .map(ShareLinkResponse::from)
                .collect(Collectors.toList());

        return Response.ok(new ShareLinkListResponse(items, total, page, size)).build();
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private java.util.Map<String, Object> buildJsonSummary(ShareLink link) {
        var m = new java.util.LinkedHashMap<String, Object>();
        m.put("shareUuid", link.getUuidToken());
        if (link.getReportJob() != null && link.getReportJob().getUrl() != null) {
            m.put("url", link.getReportJob().getUrl().getOriginalUrl());
        }
        if (link.getReportJob() != null) {
            m.put("generatedAt", link.getReportJob().getCompletedAt());
        }
        m.put("expiresAt", link.getExpiresAt());
        return m;
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
