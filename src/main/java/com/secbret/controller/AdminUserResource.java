package com.secbret.controller;

import com.secbret.exception.ResourceNotFoundException;
import com.secbret.exception.ValidationException;
import com.secbret.model.dto.AdminUserDetailResponse;
import com.secbret.model.dto.ChangeRoleRequest;
import com.secbret.model.dto.ChangeStatusRequest;
import com.secbret.model.dto.UserListResponse;
import com.secbret.model.dto.UserSummaryResponse;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.enums.UserRole;
import com.secbret.repository.UserRepository;
import com.secbret.service.AdminUserService;
import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Admin user management REST endpoints (Part III §6, openapi.yaml /admin/users).
 *
 * <ul>
 *   <li>GET  /api/v1/admin/users              — list users (paginated, optional role/enabled filter)</li>
 *   <li>GET  /api/v1/admin/users/{userId}     — single user full profile</li>
 *   <li>PUT  /api/v1/admin/users/{userId}/role   — change role</li>
 *   <li>PUT  /api/v1/admin/users/{userId}/status — enable/disable (self-disable → 409)</li>
 *   <li>PUT  /api/v1/admin/users/{userId}/unlock — clear lockout</li>
 * </ul>
 *
 * All endpoints require {@code ADMIN} role.
 */
@Path("/admin/users")
@RequestScoped
@RolesAllowed("ADMIN")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class AdminUserResource {

    @Inject
    AdminUserService adminUserService;

    @Inject
    UserRepository userRepository;

    @Context
    SecurityContext securityContext;

    // ── GET /admin/users ──────────────────────────────────────────────────────

    @GET
    public Response listUsers(
            @QueryParam("role")    String roleParam,
            @QueryParam("enabled") Boolean enabled,
            @QueryParam("page")    @DefaultValue("1")  int page,
            @QueryParam("size")    @DefaultValue("20") int size) {

        size = Math.min(Math.max(size, 1), 100);
        if (page < 1) page = 1;

        UserRole role = null;
        if (roleParam != null && !roleParam.isBlank()) {
            try {
                role = UserRole.valueOf(roleParam.toUpperCase());
            } catch (IllegalArgumentException e) {
                throw new ValidationException("Invalid role filter: " + roleParam);
            }
        }

        List<SecBretUser> users = adminUserService.listUsers(role, enabled, page, size);
        long total = adminUserService.countUsers(role, enabled);

        List<AdminUserDetailResponse> dtos = users.stream()
                .map(AdminUserDetailResponse::from)
                .collect(Collectors.toList());

        return Response.ok(new UserListResponse(dtos, total, page, size)).build();
    }

    // ── GET /admin/users/{userId} ─────────────────────────────────────────────

    @GET
    @Path("{userId}")
    public Response getUser(@PathParam("userId") UUID userId) {
        SecBretUser user = adminUserService.getUser(userId);
        return Response.ok(AdminUserDetailResponse.from(user)).build();
    }

    // ── PUT /admin/users/{userId}/role ────────────────────────────────────────

    @PUT
    @Path("{userId}/role")
    public Response changeRole(@PathParam("userId") UUID userId,
                               @Valid ChangeRoleRequest request) {
        if (request == null || request.getRole() == null) {
            throw new ValidationException("role is required");
        }
        SecBretUser actor = resolveCurrentUser();
        SecBretUser updated = adminUserService.changeRole(userId, request.getRole(), actor);
        return Response.ok(UserSummaryResponse.from(updated)).build();
    }

    // ── PUT /admin/users/{userId}/status ──────────────────────────────────────

    @PUT
    @Path("{userId}/status")
    public Response changeStatus(@PathParam("userId") UUID userId,
                                 @Valid ChangeStatusRequest request) {
        if (request == null || request.getEnabled() == null) {
            throw new ValidationException("enabled is required");
        }
        SecBretUser actor = resolveCurrentUser();
        SecBretUser updated = adminUserService.changeStatus(userId, request.getEnabled(), actor);
        return Response.ok(UserSummaryResponse.from(updated)).build();
    }

    // ── PUT /admin/users/{userId}/unlock ──────────────────────────────────────

    @PUT
    @Path("{userId}/unlock")
    public Response unlockUser(@PathParam("userId") UUID userId) {
        SecBretUser actor = resolveCurrentUser();
        SecBretUser updated = adminUserService.unlockUser(userId, actor);
        return Response.ok(UserSummaryResponse.from(updated)).build();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private SecBretUser resolveCurrentUser() {
        java.security.Principal p = securityContext.getUserPrincipal();
        if (p == null || p.getName() == null) {
            throw new ResourceNotFoundException("current user principal not available");
        }
        return userRepository.findByUsername(p.getName())
                .orElseThrow(() -> new ResourceNotFoundException("user", p.getName()));
    }
}
