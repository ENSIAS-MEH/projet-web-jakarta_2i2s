package com.secbret.controller;

import com.secbret.exception.ResourceNotFoundException;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.enums.UserRole;
import com.secbret.repository.UserRepository;
import com.secbret.service.AdminUserService;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.UUID;

/**
 * Jakarta MVC (Krazo) web controller for user management (use case "Manage Users").
 *
 * <p>The navbar "Users" link previously pointed at {@code /admin/users} with no
 * web controller behind it — only the JSON API at {@code /api/v1/admin/users}
 * ({@link AdminUserResource}) existed, so the use case was unreachable in the
 * browser. This controller provides the server-rendered page.
 *
 * <h2>Routes</h2>
 * <ul>
 *   <li>GET  /admin/users                 — user list with role controls</li>
 *   <li>POST /admin/users/{userId}/role   — change a user's role (form submit)</li>
 * </ul>
 */
@Controller
@RequestScoped
@Path("/admin/users")
@RolesAllowed("ADMIN")
public class AdminUsersWebController {

    private static final Logger log = LoggerFactory.getLogger(AdminUsersWebController.class);
    private static final String LAYOUT = "/WEB-INF/views/layout/default.jsp";
    private static final int PAGE_SIZE = 50;

    @Inject
    private Models models;

    @Inject
    private AdminUserService adminUserService;

    @Inject
    private UserRepository userRepository;

    @Context
    private jakarta.servlet.http.HttpServletRequest request;

    // =========================================================================
    // GET /admin/users — user list
    // =========================================================================

    @GET
    public String listUsers() {
        renderList(null, null);
        return LAYOUT;
    }

    // =========================================================================
    // POST /admin/users/{userId}/role — change role, re-render list
    // =========================================================================

    @POST
    @Path("{userId}/role")
    public String changeRole(@PathParam("userId") UUID userId,
                             @FormParam("role") String roleParam) {
        UserRole newRole;
        try {
            newRole = UserRole.valueOf(roleParam == null ? "" : roleParam.toUpperCase());
        } catch (IllegalArgumentException e) {
            renderList("Invalid role: " + roleParam, "danger");
            return LAYOUT;
        }

        try {
            SecBretUser actor = resolveCurrentUser();
            SecBretUser updated = adminUserService.changeRole(userId, newRole, actor);
            renderList("Role of '" + updated.getUsername() + "' changed to " + newRole + ".", "success");
        } catch (Exception e) {
            log.warn("Web role change failed for user {}: {}", userId, e.getMessage());
            renderList("Role change failed: " + e.getMessage(), "danger");
        }
        return LAYOUT;
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private void renderList(String flashMessage, String flashType) {
        models.put("users", adminUserService.listUsers(null, null, 1, PAGE_SIZE));
        models.put("totalUsers", adminUserService.countUsers(null, null));
        models.put("roles", UserRole.values());
        models.put("pageTitle", "User Management | SecBret");
        models.put("contentView", "/WEB-INF/views/admin/users.jsp");
        if (flashMessage != null) {
            models.put("flashMessage", flashMessage);
            models.put("flashType", flashType);
        }
    }

    private SecBretUser resolveCurrentUser() {
        java.security.Principal p = request.getUserPrincipal();
        if (p == null || p.getName() == null) {
            throw new ResourceNotFoundException("current user principal not available");
        }
        return userRepository.findByUsername(p.getName())
                .orElseThrow(() -> new ResourceNotFoundException("user", p.getName()));
    }
}
