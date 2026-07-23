package com.secbret.controller;

import com.secbret.exception.ConflictException;
import com.secbret.exception.ValidationException;
import com.secbret.model.dto.RegisterForm;
import com.secbret.model.entity.SecBretUser;
import com.secbret.repository.UserRepository;
import com.secbret.service.PasswordResetService;
import com.secbret.service.SessionTracker;
import com.secbret.service.UserService;
import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.mvc.Controller;
import jakarta.mvc.Models;
import jakarta.security.enterprise.AuthenticationStatus;
import jakarta.security.enterprise.SecurityContext;
import jakarta.security.enterprise.authentication.mechanism.http.AuthenticationParameters;
import jakarta.security.enterprise.credential.UsernamePasswordCredential;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Jakarta MVC (Krazo) web-form controller for authentication (Part III §1).
 *
 * <p>Routes live at the ROOT ({@code /login}, {@code /register}, {@code /logout},
 * {@code /dashboard}) — server-rendered web forms served by Krazo, not
 * {@code /api/v1} REST endpoints. Every handler returns a JSP <em>view path</em>
 * (Krazo resolves it) or a {@code "redirect:/..."} instruction. The shared
 * {@code layout/default.jsp} is the view; each method sets a {@code contentView}
 * model attribute pointing at the page fragment, matching the layout's include
 * convention.
 *
 * <p>Login uses {@link SecurityContext#authenticate}, driving the Soteria
 * CustomForm mechanism. On success the session id is regenerated
 * ({@link HttpServletRequest#changeSessionId}) to defeat session fixation
 * (Part II §5). Failed logins re-render {@code login.jsp} with a single generic
 * message — no username enumeration.
 */
@Controller
@RequestScoped
@Path("/")
public class AuthWebController {

    private static final Logger log = LoggerFactory.getLogger(AuthWebController.class);
    private static final String LAYOUT = "/WEB-INF/views/layout/default.jsp";
    private static final String DEFAULT_TARGET = "/dashboard";
    private static final String GENERIC_LOGIN_ERROR = "Invalid username or password.";

    @Inject
    Models models;

    @Inject
    UserService userService;

    @Inject
    UserRepository userRepository;

    @Inject
    SessionTracker sessionTracker;

    @Inject
    PasswordResetService passwordResetService;

    @Inject
    Validator validator;

    @Inject
    SecurityContext securityContext;

    @Context
    HttpServletRequest request;

    @Context
    HttpServletResponse response;

    // ---------------------------------------------------------------- ROOT

    /**
     * GET / — post-logout landing and navbar brand target. Nothing mapped the
     * bare root before, so every sign-out ended on Payara's raw 404 page.
     */
    @GET
    public String root() {
        return securityContext.getCallerPrincipal() != null
                ? "redirect:" + DEFAULT_TARGET
                : "redirect:/login";
    }

    // ---------------------------------------------------------------- LOGIN

    @GET
    @Path("login")
    public String showLogin(@QueryParam("next") String next,
                            @QueryParam("registered") String registered,
                            @QueryParam("reset") String reset,
                            @QueryParam("error") String error) {
        models.put("pageTitle", "Sign in | SecBret");
        models.put("next", next);
        if (registered != null) {
            models.put("flashMessage", "Registration successful — please sign in.");
            models.put("flashType", "success");
        }
        if (reset != null) {
            models.put("flashMessage", "Your password has been reset. Please sign in with your new password.");
            models.put("flashType", "success");
        }
        if (error != null) {
            models.put("error", GENERIC_LOGIN_ERROR);
        }
        models.put("contentView", "/WEB-INF/views/auth/login.jsp");
        return LAYOUT;
    }

    @POST
    @Path("login")
    public String doLogin(@FormParam("username") String username,
                          @FormParam("password") String password,
                          @FormParam("next") String next) {
        String target = safeRedirect(next);

        AuthenticationStatus status = securityContext.authenticate(
                request, response,
                AuthenticationParameters.withParams()
                        .credential(new UsernamePasswordCredential(
                                username, password == null ? "" : password)));

        switch (status) {
            case SUCCESS:
                // Session fixation defence: regenerate the session id post-auth (Part II §5).
                if (request.getSession(false) != null) {
                    request.changeSessionId();
                    // Track the session for user-wide invalidation (Part II §15.5) —
                    // required by DELETE /auth/me (GDPR: "all sessions invalidated").
                    userRepository.findByUsername(username)
                            .map(SecBretUser::getId)
                            .ifPresent(id -> sessionTracker.register(id, request.getSession(false)));
                }
                return "redirect:" + target;
            case SEND_CONTINUE:
                // The mechanism committed its own redirect response; return null so
                // Krazo does not render a view over the already-committed response.
                return null;
            case SEND_FAILURE:
            case NOT_DONE:
            default:
                models.put("pageTitle", "Sign in | SecBret");
                models.put("error", GENERIC_LOGIN_ERROR);
                models.put("next", next);
                models.put("contentView", "/WEB-INF/views/auth/login.jsp");
                return LAYOUT;
        }
    }

    // ------------------------------------------------------------- REGISTER

    @GET
    @Path("register")
    public String showRegister() {
        models.put("pageTitle", "Create account | SecBret");
        models.put("contentView", "/WEB-INF/views/auth/register.jsp");
        return LAYOUT;
    }

    @POST
    @Path("register")
    public String doRegister(@FormParam("username") String username,
                             @FormParam("email") String email,
                             @FormParam("password") String password) {
        RegisterForm form = new RegisterForm(username, email, password);
        Set<ConstraintViolation<RegisterForm>> violations = validator.validate(form);

        if (!violations.isEmpty()) {
            return renderRegisterError(form, fieldErrors(violations), null);
        }

        try {
            userService.register(username, email, password);
        } catch (ConflictException conflict) {
            // Duplicate username/email — re-render with the conflict message.
            return renderRegisterError(form, Map.of(), conflict.getMessage());
        }

        return "redirect:/login?registered";
    }

    // --------------------------------------------------------------- LOGOUT

    @POST
    @Path("logout")
    public String doLogout() {
        if (request.getSession(false) != null) {
            request.getSession(false).invalidate();
        }
        return "redirect:/";
    }

    // ------------------------------------------------------------ DASHBOARD

    @GET
    @Path("dashboard")
    @RolesAllowed({"REPORTER", "ANALYST", "ADMIN"})
    public String dashboard() {
        String username = request.getUserPrincipal() != null
                ? request.getUserPrincipal().getName() : "";
        models.put("pageTitle", "Dashboard | SecBret");
        models.put("username", username);
        models.put("role", firstRole());
        models.put("contentView", "/WEB-INF/views/home.jsp");
        return LAYOUT;
    }

    // -------------------------------------------------------------- PROFILE

    /** GET /profile — account information page for the signed-in user. */
    @GET
    @Path("profile")
    @RolesAllowed({"REPORTER", "ANALYST", "ADMIN"})
    public String profile() {
        if (request.getUserPrincipal() == null) {
            return "redirect:/login";
        }
        String username = request.getUserPrincipal().getName();
        SecBretUser user = userRepository.findByUsername(username).orElse(null);
        if (user == null) {
            log.warn("Authenticated principal '{}' has no user record", username);
            return "redirect:/login";
        }
        models.put("user", user);
        models.put("pageTitle", "My Profile | SecBret");
        models.put("contentView", "/WEB-INF/views/profile.jsp");
        return LAYOUT;
    }

    // ------------------------------------------------ FORGOT PASSWORD

    private static final String FORGOT_PASSWORD_CONFIRMATION =
            "If an account with that email exists, a reset link has been sent.";

    @GET
    @Path("forgot-password")
    public String showForgotPassword() {
        models.put("pageTitle", "Reset password | SecBret");
        models.put("contentView", "/WEB-INF/views/auth/forgot-password.jsp");
        return LAYOUT;
    }

    @POST
    @Path("forgot-password")
    public String doForgotPassword(@FormParam("email") String email) {
        // Anti-enumeration: always show generic confirmation regardless of outcome.
        if (email != null && !email.isBlank()) {
            String baseUrl = request.getScheme() + "://" + request.getServerName()
                    + (request.getServerPort() == 80 || request.getServerPort() == 443 ? ""
                    : ":" + request.getServerPort())
                    + "/reset-password";
            try {
                passwordResetService.requestReset(email.trim(), baseUrl);
            } catch (Exception e) {
                // Swallow all exceptions to preserve anti-enumeration.
                log.warn("Error during password reset request (suppressed for anti-enumeration): {}",
                        e.getMessage());
            }
        }
        models.put("pageTitle", "Reset password | SecBret");
        models.put("flashMessage", FORGOT_PASSWORD_CONFIRMATION);
        models.put("flashType", "info");
        models.put("contentView", "/WEB-INF/views/auth/forgot-password.jsp");
        return LAYOUT;
    }

    // ------------------------------------------------ RESET PASSWORD

    @GET
    @Path("reset-password")
    public String showResetPassword(@QueryParam("token") String token) {
        models.put("pageTitle", "Set new password | SecBret");
        models.put("token", token != null ? token : "");
        models.put("contentView", "/WEB-INF/views/auth/reset-password.jsp");
        return LAYOUT;
    }

    @POST
    @Path("reset-password")
    public String doResetPassword(@FormParam("token") String token,
                                   @FormParam("newPassword") String newPassword) {
        if (token == null || token.isBlank()) {
            models.put("pageTitle", "Set new password | SecBret");
            models.put("error", "Invalid or missing reset token.");
            models.put("token", "");
            models.put("contentView", "/WEB-INF/views/auth/reset-password.jsp");
            return LAYOUT;
        }
        if (newPassword == null || newPassword.length() < 12 || newPassword.length() > 72) {
            models.put("pageTitle", "Set new password | SecBret");
            models.put("error", "Password must be 12–72 characters.");
            models.put("token", token);
            models.put("contentView", "/WEB-INF/views/auth/reset-password.jsp");
            return LAYOUT;
        }
        try {
            passwordResetService.consumeReset(token, newPassword);
        } catch (ValidationException e) {
            models.put("pageTitle", "Set new password | SecBret");
            models.put("error", e.getMessage());
            models.put("token", token);
            models.put("contentView", "/WEB-INF/views/auth/reset-password.jsp");
            return LAYOUT;
        }
        return "redirect:/login?reset";
    }

    // --------------------------------------------------------------- HELPERS

    private String firstRole() {
        for (String r : new String[]{"ADMIN", "ANALYST", "REPORTER"}) {
            if (request.isUserInRole(r)) {
                return r;
            }
        }
        return "";
    }

    private String renderRegisterError(RegisterForm form, Map<String, String> fieldErrors, String generalError) {
        models.put("pageTitle", "Create account | SecBret");
        models.put("form", form);
        // fieldErrors: Map<fieldName, message> for per-field inline rendering (Part V §2.6)
        models.put("fieldErrors", fieldErrors);
        // errors: flat set for backwards-compat summary list
        models.put("errors", new LinkedHashSet<>(fieldErrors.values()));
        if (generalError != null) {
            models.put("error", generalError);
        }
        models.put("contentView", "/WEB-INF/views/auth/register.jsp");
        return LAYOUT;
    }

    private static Map<String, String> fieldErrors(Set<ConstraintViolation<RegisterForm>> violations) {
        Map<String, String> map = new LinkedHashMap<>();
        for (ConstraintViolation<RegisterForm> v : violations) {
            // property path leaf is the field name (e.g. "username", "email", "password")
            String field = v.getPropertyPath().toString();
            int dot = field.lastIndexOf('.');
            if (dot >= 0) field = field.substring(dot + 1);
            map.putIfAbsent(field, v.getMessage());
        }
        return map;
    }

    /**
     * SafeRedirects allowlist (Part III §1): only accept a same-site relative path
     * ({@code /...} but not {@code //host} protocol-relative). Anything else falls
     * back to {@code /dashboard} to prevent open-redirect.
     */
    private static String safeRedirect(String next) {
        if (next == null || next.isBlank()) {
            return DEFAULT_TARGET;
        }
        if (next.startsWith("/") && !next.startsWith("//") && !next.contains("\\")) {
            return next;
        }
        return DEFAULT_TARGET;
    }
}
