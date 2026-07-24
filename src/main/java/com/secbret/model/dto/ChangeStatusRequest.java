package com.secbret.model.dto;

import jakarta.validation.constraints.NotNull;

/** Request body for PUT /admin/users/{userId}/status. */
public class ChangeStatusRequest {

    @NotNull(message = "enabled is required")
    private Boolean enabled;

    public ChangeStatusRequest() {}

    public Boolean getEnabled() { return enabled; }
    public void setEnabled(Boolean enabled) { this.enabled = enabled; }
}
