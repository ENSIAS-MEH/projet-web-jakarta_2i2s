package com.secbret.model.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Registration form bean (Part III §1 · §B Password Policy).
 *
 * <p>Server-side validation contract:
 * <ul>
 *   <li>{@code username}: 3–50 chars, {@code [A-Za-z0-9_]} only.</li>
 *   <li>{@code email}: valid email format.</li>
 *   <li>{@code password}: minimum 12 chars, <strong>no composition rules</strong>
 *       (spec §B is explicit: no mandatory special/digit/uppercase). HIBP breach
 *       check is Phase 5, not enforced here.</li>
 * </ul>
 *
 * <p>The web controller validates this bean and re-renders {@code register.jsp}
 * with field errors on failure; it does not surface a JSON envelope.
 */
public class RegisterForm {

    @NotBlank(message = "Username is required.")
    @Size(min = 3, max = 50, message = "Username must be 3–50 characters.")
    @Pattern(regexp = "^[A-Za-z0-9_]+$",
            message = "Username may contain only letters, digits, and underscores.")
    private String username;

    @NotBlank(message = "Email is required.")
    @Email(message = "Enter a valid email address.")
    @Size(max = 255, message = "Email must be at most 255 characters.")
    private String email;

    @NotBlank(message = "Password is required.")
    @Size(min = 12, max = 72, message = "Password must be 12–72 characters.")
    private String password;

    public RegisterForm() {
    }

    public RegisterForm(String username, String email, String password) {
        this.username = username;
        this.email = email;
        this.password = password;
    }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
}
