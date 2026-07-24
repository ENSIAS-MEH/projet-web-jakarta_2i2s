package com.secbret.model.dto;

import com.secbret.model.enums.UserRole;
import jakarta.validation.constraints.NotNull;

/** Request body for PUT /admin/users/{userId}/role. */
public class ChangeRoleRequest {

    @NotNull(message = "role is required")
    private UserRole role;

    public ChangeRoleRequest() {}

    public UserRole getRole() { return role; }
    public void setRole(UserRole role) { this.role = role; }
}
