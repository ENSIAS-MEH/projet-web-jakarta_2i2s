package com.secbret.filter;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * JAX-RS {@code ContainerRequestFilter} enforcing {@code X-CSRF-Token} on all
 * authenticated state-changing requests to the {@code /api/v1} REST API.
 *
 * <p>Required by Part II §5 / Part III §Conventions:
 * <blockquote>All POST, PUT, PATCH and DELETE endpoints require … a valid
 * {@code X-CSRF-Token} header.</blockquote>
 *
 * <h2>Token validation</h2>
 * The token is the Krazo CSRF session token.  Krazo stores it as the session
 * attribute {@code _csrf} (type {@code CsrfToken}); since this filter runs inside
 * Jersey (not the Krazo application) we read it directly from the servlet session
 * via the injected {@link jakarta.servlet.http.HttpServletRequest}.
 *
 * <p>The token carried by HTMX fragment requests is injected via hx-headers in the
 * JSP layout (see {@code default.jsp}).  Regular form submissions use the hidden
 * {@code _csrf} input managed by Krazo.
 *
 * <h2>Exempt endpoints (Part II §5)</h2>
 * <ul>
 *   <li>All GET/HEAD/OPTIONS/TRACE requests (safe methods — no side effects)</li>
 *   <li>Unauthenticated requests ({@code Principal} is null) — rate limited separately</li>
 *   <li>Health probes, public dashboard, share access (all @PermitAll GET only)</li>
 * </ul>
 *
 * <h2>In-container curl testing</h2>
 * The per-session token is rendered as the {@code _csrf} hidden field on any web
 * form; log in, scrape it (take the FIRST match — some pages render it twice),
 * then send it as the {@code X-CSRF-Token} header:
 * <pre>
 *   CSRF=$(curl -s -b cookies.txt http://localhost:8080/scan/new \
 *            | grep -io '_csrf" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//')
 *   curl -X POST -b cookies.txt -H "X-CSRF-Token: $CSRF" ...
 * </pre>
 */
@Provider
public class CsrfJaxRsFilter implements ContainerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(CsrfJaxRsFilter.class);

    static final String CSRF_HEADER = "X-CSRF-Token";

    /**
     * Session attribute under which Krazo's SessionCsrfTokenStrategy stores its
     * {@link org.eclipse.krazo.security.CsrfToken}: the strategy class name + ".TOKEN".
     * The value is a CsrfToken OBJECT (no toString override), so it must be
     * unwrapped via getValue() — comparing toString() output can never match.
     */
    private static final String KRAZO_CSRF_SESSION_ATTR =
            "org.eclipse.krazo.security.SessionCsrfTokenStrategy.TOKEN";

    @jakarta.ws.rs.core.Context
    jakarta.servlet.http.HttpServletRequest httpRequest;

    @Override
    public void filter(ContainerRequestContext ctx) throws IOException {
        String method = ctx.getMethod();

        // Safe methods are never subject to CSRF.
        if ("GET".equalsIgnoreCase(method) || "HEAD".equalsIgnoreCase(method)
                || "OPTIONS".equalsIgnoreCase(method) || "TRACE".equalsIgnoreCase(method)) {
            return;
        }

        // Unauthenticated requests cannot have a valid session token; exempt them
        // (they will be rejected at the @RolesAllowed gate instead).
        if (httpRequest.getUserPrincipal() == null) {
            return;
        }

        // Retrieve the session's CSRF token.
        jakarta.servlet.http.HttpSession session = httpRequest.getSession(false);
        if (session == null) {
            rejectCsrf(ctx, "No active session");
            return;
        }

        String sessionToken = resolveSessionToken(session);
        if (sessionToken == null) {
            // Session exists but no CSRF token yet — this is abnormal; reject.
            rejectCsrf(ctx, "No CSRF token in session");
            return;
        }

        String requestToken = ctx.getHeaderString(CSRF_HEADER);
        if (requestToken == null || requestToken.isBlank()) {
            rejectCsrf(ctx, "Missing X-CSRF-Token header");
            return;
        }

        if (!constantTimeEquals(sessionToken, requestToken.trim())) {
            log.warn("CSRF token mismatch for user={} path={}",
                    httpRequest.getUserPrincipal().getName(), httpRequest.getRequestURI());
            rejectCsrf(ctx, "Invalid CSRF token");
        }
    }

    // ---------------------------------------------------------------- helpers

    /**
     * Unwraps the token value from Krazo's session attribute. The attribute is a
     * {@link org.eclipse.krazo.security.CsrfToken}; a plain String is also accepted
     * in case a future Krazo version (or a test) stores the raw value.
     */
    private static String resolveSessionToken(jakarta.servlet.http.HttpSession session) {
        Object attr = session.getAttribute(KRAZO_CSRF_SESSION_ATTR);
        if (attr instanceof org.eclipse.krazo.security.CsrfToken token) {
            return token.getValue();
        }
        if (attr instanceof String s) {
            return s;
        }
        return null;
    }

    private static void rejectCsrf(ContainerRequestContext ctx, String reason) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status",    403);
        body.put("error",     "Forbidden");
        body.put("message",   reason);
        body.put("timestamp", Instant.now().toString());
        ctx.abortWith(Response.status(Response.Status.FORBIDDEN)
                .entity(body)
                .type("application/json")
                .build());
    }

    /** Constant-time string comparison to prevent timing side-channels. */
    private static boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) return false;
        int diff = 0;
        for (int i = 0; i < a.length(); i++) {
            diff |= a.charAt(i) ^ b.charAt(i);
        }
        return diff == 0;
    }
}
