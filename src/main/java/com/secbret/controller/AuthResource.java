package com.secbret.controller;

import com.secbret.exception.ResourceNotFoundException;
import com.secbret.exception.ValidationException;
import com.secbret.model.dto.GdprDeleteRequest;
import com.secbret.model.entity.SecBretUser;
import com.secbret.repository.UserRepository;
import com.secbret.service.AdminUserService;
import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;

/**
 * REST endpoint for {@code /auth/me} (Part III §1).
 *
 * <p>v1 serves only {@code DELETE /auth/me} (GDPR hard-delete). The {@code GET /auth/me}
 * endpoint is v2 pre-positioning only (openapi.yaml note: "NOT served in v1").
 *
 * <p>The openapi.yaml spec uses {@code /auth/me} without the {@code /api/v1} prefix in
 * its path section but all v1 REST endpoints are served under {@code /api/v1} (SecBretApplication
 * {@code @ApplicationPath("/api/v1")}), so this class correctly resolves to
 * {@code /api/v1/auth/me}.
 */
@Path("/auth/me")
@RequestScoped
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class AuthResource {

    @Inject
    AdminUserService adminUserService;

    @Inject
    UserRepository userRepository;

    @Context
    SecurityContext securityContext;

    @Context
    HttpServletRequest httpRequest;

    /**
     * GDPR hard-delete (Part III §1 DELETE /auth/me, openapi.yaml).
     *
     * <p>Validates {@code currentPassword}, invalidates all sessions, hard-deletes the
     * {@code secbret_user} row. The V20 BEFORE DELETE trigger writes the
     * {@code actor_username = 'deleted_{uuid}'} tombstone; application code does NOT
     * add a redundant UPDATE (spec C3 / HANDOFF known trap).
     *
     * <p>Wrong password → 422. Does NOT increment {@code failed_login_attempts} (spec note).
     */
    @DELETE
    @RolesAllowed({"REPORTER", "ANALYST", "ADMIN"})
    public Response deleteAccount(@Valid GdprDeleteRequest request) {
        if (request == null || request.getCurrentPassword() == null
                || request.getCurrentPassword().isBlank()) {
            throw new ValidationException("currentPassword is required");
        }

        SecBretUser caller = resolveCaller();
        adminUserService.deleteAccount(caller.getId(), request.getCurrentPassword());

        // Belt-and-braces: kill the calling session directly. SessionTracker already
        // invalidates registered sessions, but the caller's session may predate the
        // register() wiring (server restart, pre-existing session).
        invalidateCurrentSession();

        return Response.noContent().build(); // 204
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void invalidateCurrentSession() {
        if (httpRequest == null) return; // not in a servlet context (unit tests)
        HttpSession session = httpRequest.getSession(false);
        if (session == null) return;
        try {
            session.invalidate();
        } catch (IllegalStateException ignored) {
            // Already invalidated by SessionTracker — the desired end state.
        }
    }

    private SecBretUser resolveCaller() {
        java.security.Principal p = securityContext.getUserPrincipal();
        if (p == null || p.getName() == null) {
            throw new ResourceNotFoundException("current user principal not available");
        }
        return userRepository.findByUsername(p.getName())
                .orElseThrow(() -> new ResourceNotFoundException("user", p.getName()));
    }
}
