package com.secbret.model.dto;

import jakarta.validation.constraints.NotBlank;

/** Request body for DELETE /auth/me (GDPR hard-delete, Part III §1). */
public class GdprDeleteRequest {

    @NotBlank(message = "currentPassword is required")
    private String currentPassword;

    public GdprDeleteRequest() {}

    public String getCurrentPassword() { return currentPassword; }
    public void setCurrentPassword(String currentPassword) { this.currentPassword = currentPassword; }
}
