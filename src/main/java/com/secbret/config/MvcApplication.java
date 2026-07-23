package com.secbret.config;

import com.secbret.controller.AdminUsersWebController;
import com.secbret.controller.AdminWebController;
import com.secbret.controller.AuthWebController;
import com.secbret.controller.IncidentWebController;
import com.secbret.controller.PublicDashboardWebController;
import com.secbret.controller.ReportWebController;
import com.secbret.controller.ScanWebController;
import com.secbret.controller.ShareWebController;
import jakarta.mvc.security.Csrf;
import jakarta.ws.rs.core.Application;

import java.util.Map;
import java.util.Set;

/**
 * JAX-RS {@link Application} that hosts the Jakarta MVC (Krazo) web controllers.
 *
 * <p><strong>CSRF (Phase 5 / Task 22):</strong> {@code @Csrf(CsrfOptions.IMPLICIT)}
 * enables Krazo CSRF globally for all MVC controllers in this application.
 * Krazo generates a per-session token, populates {@code _csrf} in the model for
 * every request (so {@code ${_csrf.token}} works in JSPs), and automatically
 * validates the token on all POST requests — enforcing Part II §5 / Part III
 * §Conventions for the web-form layer. The {@code CsrfJaxRsFilter} handles the
 * separate JAX-RS API layer ({@code X-CSRF-Token} header).
 *
 * <p><strong>Krazo coexistence decision.</strong> The REST API lives under
 * {@code @ApplicationPath("/api/v1")} ({@link SecBretApplication}). Krazo is a
 * JAX-RS extension, so its {@code @Controller} classes must be served by a JAX-RS
 * {@code Application}. Rather than mixing web forms and the versioned REST API in
 * one application (which would force the web forms under {@code /api/v1}), a
 * <em>second</em> {@code Application} is rooted at {@code "/"} so the web-form
 * routes keep the ROOT paths the spec mandates ({@code /login}, {@code /register},
 * {@code /logout}, {@code /dashboard} — Part III §1).
 *
 * <p>{@link #getClasses()} returns the web controllers <em>explicitly</em> so
 * Jersey does not classpath-scan {@code com.secbret.controller} — that package
 * also holds {@code HealthController} ({@code @Path("/health")}, part of the
 * {@code /api/v1} REST app), which must NOT be re-exposed at the root.
 *
 * <p><strong>Registered via {@code web.xml}</strong> as a Jersey <em>filter</em>
 * (not an {@code @ApplicationPath} servlet) with
 * {@code jersey.config.servlet.filter.forwardOn404=true}. That lets Krazo host
 * controllers at the ROOT while JSP view forwards ({@code /WEB-INF/views/**.jsp})
 * and {@code /static/*} that Krazo does not match fall THROUGH to the container's
 * JSP/default servlet. A servlet mapped to {@code /*} instead re-intercepts the
 * internal JSP forward and makes Krazo's response wrapper recurse
 * (StackOverflowError). The {@code @ApplicationPath} annotation is intentionally
 * omitted so only the {@code web.xml} filter registration is active.
 */
public class MvcApplication extends Application {

    @Override
    public Set<Class<?>> getClasses() {
        return Set.of(AuthWebController.class, ScanWebController.class,
                PublicDashboardWebController.class,
                IncidentWebController.class, AdminWebController.class,
                AdminUsersWebController.class,
                ReportWebController.class, ShareWebController.class);
    }

    /**
     * Enable Krazo CSRF in IMPLICIT mode (Phase 5 / Task 22, Part II §5).
     *
     * <p>IMPLICIT means Krazo generates a per-session CSRF token and injects it
     * into the MVC model as {@code _csrf} (a {@link Csrf} CDI bean) for every
     * request. JSPs use {@code ${_csrf.token}} and {@code ${_csrf.name}} in
     * hidden inputs. Krazo also validates the token on every POST submitted to
     * a {@code @Controller} method.
     *
     * <p>The property key {@code "jakarta.mvc.security.CsrfProtection"} matches
     * {@link Csrf#CSRF_PROTECTION}.
     */
    @Override
    public Map<String, Object> getProperties() {
        return Map.of(Csrf.CSRF_PROTECTION, Csrf.CsrfOptions.IMPLICIT);
    }
}
