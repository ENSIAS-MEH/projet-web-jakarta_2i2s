package com.secbret.controller;

import com.secbret.exception.ResourceNotFoundException;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.entity.ShareLink;
import com.secbret.repository.UserRepository;
import com.secbret.service.ShareLinkService;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.mvc.Controller;
import jakarta.mvc.Models;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Krazo MVC web controller for share link views (Part III §5).
 *
 * <h2>Routes</h2>
 * <ul>
 *   <li>GET /share/{uuid}  — anonymous HTML view of a shared report</li>
 *   <li>GET /shares        — authenticated share-links management page</li>
 * </ul>
 */
@Controller
@RequestScoped
@Path("/")
public class ShareWebController {

    private static final Logger log = LoggerFactory.getLogger(ShareWebController.class);
    private static final String LAYOUT = "/WEB-INF/views/layout/default.jsp";

    @Inject private Models models;
    @Inject private ShareLinkService shareLinkService;
    @Inject private UserRepository userRepository;

    @Context private jakarta.servlet.http.HttpServletRequest request;

    // =========================================================================
    // GET /share/{uuid} — anonymous HTML view
    // =========================================================================

    @GET
    @Path("share/{uuid}")
    @PermitAll
    public Response viewSharedReport(@PathParam("uuid") String uuid) {
        Optional<ShareLink> linkOpt = shareLinkService.findByToken(uuid);

        if (linkOpt.isEmpty()) {
            models.put("errorCode", 404);
            models.put("errorMessage", "Share link not found.");
            models.put("pageTitle", "Not Found | SecBret");
            models.put("contentView", "/WEB-INF/views/share/not-found.jsp");
            return Response.status(Response.Status.NOT_FOUND)
                    .entity(LAYOUT)
                    .build();
        }

        ShareLink link = linkOpt.get();

        if (!shareLinkService.isValid(link)) {
            models.put("errorCode", 410);
            models.put("errorMessage", "This share link has expired or been revoked.");
            models.put("pageTitle", "Link Expired | SecBret");
            models.put("contentView", "/WEB-INF/views/share/gone.jsp");
            return Response.status(Response.Status.GONE)
                    .entity(LAYOUT)
                    .build();
        }

        // Record access atomically
        shareLinkService.recordAccess(link.getId());

        models.put("link", link);
        models.put("job", link.getReportJob());
        models.put("pageTitle", "Shared Report | SecBret");
        models.put("contentView", "/WEB-INF/views/share/view.jsp");
        return Response.ok(LAYOUT).build();
    }

    // =========================================================================
    // GET /shares — authenticated share-links management page
    // =========================================================================

    @GET
    @Path("shares")
    @RolesAllowed({"REPORTER", "ANALYST", "ADMIN"})
    public Response manageShareLinks() {
        UUID userId = resolveCurrentUserId();
        List<ShareLink> links = shareLinkService.listOwn(userId, 1, 20);
        models.put("shareLinks", links);
        models.put("pageTitle", "My Share Links | SecBret");
        models.put("contentView", "/WEB-INF/views/share/list.jsp");
        return Response.ok(LAYOUT).build();
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
