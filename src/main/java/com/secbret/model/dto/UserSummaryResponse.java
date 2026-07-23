package com.secbret.model.dto;

import com.secbret.model.entity.SecBretUser;
import com.secbret.model.enums.UserRole;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Slim user representation returned by PUT /admin/users/{userId}/role|status|unlock.
 * Matches openapi.yaml#/components/schemas/UserSummaryResponse.
 */
public class UserSummaryResponse {

    private final UUID id;
    private final String username;
    private final UserRole role;
    private final boolean enabled;
    private final LocalDateTime lockedUntil;
    private final int failedLoginAttempts;

    private UserSummaryResponse(UUID id, String username, UserRole role, boolean enabled,
                                LocalDateTime lockedUntil, int failedLoginAttempts) {
        this.id = id;
        this.username = username;
        this.role = role;
        this.enabled = enabled;
        this.lockedUntil = lockedUntil;
        this.failedLoginAttempts = failedLoginAttempts;
    }

    public static UserSummaryResponse from(SecBretUser u) {
        return new UserSummaryResponse(
                u.getId(),
                u.getUsername(),
                u.getRole(),
                u.isEnabled(),
                u.getLockedUntil(),
                u.getFailedLoginAttempts());
    }

    public UUID getId()                   { return id; }
    public String getUsername()           { return username; }
    public UserRole getRole()             { return role; }
    public boolean isEnabled()            { return enabled; }
    public LocalDateTime getLockedUntil() { return lockedUntil; }
    public int getFailedLoginAttempts()   { return failedLoginAttempts; }
}
