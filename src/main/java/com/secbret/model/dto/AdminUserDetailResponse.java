package com.secbret.model.dto;

import com.secbret.model.entity.SecBretUser;
import com.secbret.model.enums.UserRole;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Full user profile for GET /admin/users/{userId}.
 * Matches openapi.yaml#/components/schemas/AdminUserDetailResponse.
 */
public class AdminUserDetailResponse {

    private final UUID id;
    private final String username;
    private final String email;
    private final UserRole role;
    private final boolean enabled;
    private final int failedLoginAttempts;
    private final LocalDateTime lockedUntil;
    private final LocalDateTime createdAt;

    private AdminUserDetailResponse(UUID id, String username, String email, UserRole role,
                                    boolean enabled, int failedLoginAttempts,
                                    LocalDateTime lockedUntil, LocalDateTime createdAt) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.role = role;
        this.enabled = enabled;
        this.failedLoginAttempts = failedLoginAttempts;
        this.lockedUntil = lockedUntil;
        this.createdAt = createdAt;
    }

    public static AdminUserDetailResponse from(SecBretUser u) {
        return new AdminUserDetailResponse(
                u.getId(),
                u.getUsername(),
                u.getEmail(),
                u.getRole(),
                u.isEnabled(),
                u.getFailedLoginAttempts(),
                u.getLockedUntil(),
                u.getCreatedAt());
    }

    public UUID getId()                   { return id; }
    public String getUsername()           { return username; }
    public String getEmail()              { return email; }
    public UserRole getRole()             { return role; }
    public boolean isEnabled()            { return enabled; }
    public int getFailedLoginAttempts()   { return failedLoginAttempts; }
    public LocalDateTime getLockedUntil() { return lockedUntil; }
    public LocalDateTime getCreatedAt()   { return createdAt; }
}
