package com.secbret.security;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.security.enterprise.authentication.mechanism.http.CustomFormAuthenticationMechanismDefinition;
import jakarta.security.enterprise.authentication.mechanism.http.LoginToContinue;

/**
 * Jakarta Security configuration (Part III §1).
 *
 * <p>Declares a {@link CustomFormAuthenticationMechanismDefinition}: authentication
 * is driven <em>programmatically</em> by the application (the login controller calls
 * {@code SecurityContext.authenticate(...)}), and the container coordinates the
 * login flow via {@link LoginToContinue} — pointing an unauthenticated request at
 * the {@code GET /login} page and preserving the originally-requested URL so the
 * post-login redirect can honour it.
 *
 * <ul>
 *   <li>{@code loginPage = "/login"} — where unauthenticated users are sent.</li>
 *   <li>{@code errorPage = ""} — no separate error page; the CustomForm mechanism
 *       returns to the login controller, which re-renders {@code login.jsp} with a
 *       generic error (no username enumeration, Part III §1).</li>
 *   <li>{@code useForwardToLogin = false} — issue a redirect (302) to
 *       {@code /login} rather than a server-side forward, so the browser URL is
 *       {@code /login} and the CustomForm state cookie is established cleanly.</li>
 * </ul>
 *
 * <p>Credentials are validated by {@link SecBretIdentityStore}. Session-fixation
 * defence (regenerating the session id on successful login) is handled explicitly
 * in the login controller per Part II §5.
 */
@CustomFormAuthenticationMechanismDefinition(
        loginToContinue = @LoginToContinue(
                loginPage = "/login",
                errorPage = "",
                useForwardToLogin = false
        )
)
@ApplicationScoped
public class SecurityConfig {
    // The annotation above activates the mechanism; this bean is its CDI anchor.
}
