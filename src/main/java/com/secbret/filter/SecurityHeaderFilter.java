package com.secbret.filter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Servlet Filter that applies all security response headers required by Part II §5.
 *
 * <h2>Headers set on every response</h2>
 * <ul>
 *   <li>{@code Content-Security-Policy} — strict {@code 'self'} + per-request nonce
 *       on {@code script-src} and {@code style-src} (ADR-0004). The nonce is stored
 *       as request attribute {@code cspNonce} so JSPs can reference it via
 *       {@code ${cspNonce}}.</li>
 *   <li>{@code X-Frame-Options: DENY}</li>
 *   <li>{@code X-Content-Type-Options: nosniff}</li>
 *   <li>{@code Strict-Transport-Security: max-age=31536000; includeSubDomains}</li>
 *   <li>{@code Referrer-Policy: strict-origin-when-cross-origin}</li>
 * </ul>
 *
 * <h2>CORS</h2>
 * Allowed origins are same-origin + the {@code CORS_ALLOWED_ORIGINS} env var
 * (comma-separated). Wildcard {@code *} is never emitted regardless of env content.
 * Credentials are allowed; max-age 3600s.
 *
 * ponytail: HSTS sent even on HTTP — intentional: if someone accidentally serves over
 * HTTP the header is silently ignored by browsers but costs nothing; production will
 * be HTTPS-only.
 */
@WebFilter(filterName = "SecurityHeaderFilter", urlPatterns = "/*")
public class SecurityHeaderFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(SecurityHeaderFilter.class);

    /** Request attribute key that JSPs read to inject the nonce: {@code ${cspNonce}}. */
    public static final String NONCE_ATTR = "cspNonce";

    private static final SecureRandom RANDOM = new SecureRandom();

    private String[] allowedOrigins = new String[0];

    @Override
    public void init(FilterConfig cfg) {
        String originsEnv = System.getenv("CORS_ALLOWED_ORIGINS");
        if (originsEnv != null && !originsEnv.isBlank()) {
            allowedOrigins = originsEnv.split(",");
            for (int i = 0; i < allowedOrigins.length; i++) {
                allowedOrigins[i] = allowedOrigins[i].trim();
            }
        }
        log.info("SecurityHeaderFilter initialised; CORS extra origins={}", originsEnv);
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest  request  = (HttpServletRequest)  req;
        HttpServletResponse response = (HttpServletResponse) res;

        // --------------------------------------------------------- CSP nonce
        String nonce = generateNonce();
        request.setAttribute(NONCE_ATTR, nonce);

        // --------------------------------------------------------- security headers
        String csp = "default-src 'self'; " +
                     "script-src 'self' 'nonce-" + nonce + "'; " +
                     "style-src 'self' 'nonce-" + nonce + "'; " +
                     "img-src 'self' data:";

        response.setHeader("Content-Security-Policy",       csp);
        response.setHeader("X-Frame-Options",               "DENY");
        response.setHeader("X-Content-Type-Options",        "nosniff");
        response.setHeader("Strict-Transport-Security",     "max-age=31536000; includeSubDomains");
        response.setHeader("Referrer-Policy",               "strict-origin-when-cross-origin");

        // --------------------------------------------------------- CORS
        String origin = request.getHeader("Origin");
        if (origin != null && isAllowedOrigin(request, origin)) {
            response.setHeader("Access-Control-Allow-Origin",      origin);
            response.setHeader("Access-Control-Allow-Credentials", "true");
            response.setHeader("Access-Control-Allow-Methods",     "GET, POST, PUT, DELETE");
            response.setHeader("Access-Control-Allow-Headers",
                    "Content-Type, Authorization, X-Requested-With, X-CSRF-Token");
            response.setHeader("Access-Control-Max-Age", "3600");
        }

        // --------------------------------------------------------- preflight short-circuit
        // Only short-circuit when the origin is on the allowlist; disallowed origins
        // fall through to the chain which 404/405s without CORS headers (correct rejection).
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())
                && origin != null
                && isAllowedOrigin(request, origin)) {
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            return;
        }

        chain.doFilter(request, response);

        // --------------------------------------------------- SameSite=Strict
        // Payara 6 (Servlet 6.0) does not support <same-site> in web.xml (that is
        // Servlet 6.1 / Jakarta EE 11). We append SameSite=Strict to every
        // Set-Cookie header in the response instead.
        // Note: response may already be committed for redirects; getHeaders() is safe
        // to call on a committed response — it reads what was already written.
        applySameSiteStrict(response);
    }

    // ---------------------------------------------------------------- helpers

    private boolean isAllowedOrigin(HttpServletRequest request, String origin) {
        // Same-origin (request URL reconstructed) always allowed.
        String scheme    = request.getScheme();
        String serverName = request.getServerName();
        int    port      = request.getServerPort();
        String self      = scheme + "://" + serverName
                + ((port == 80 || port == 443) ? "" : ":" + port);
        if (origin.equals(self)) {
            return true;
        }
        for (String allowed : allowedOrigins) {
            if (!allowed.isEmpty() && origin.equals(allowed)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Append {@code SameSite=Strict} to every {@code Set-Cookie} response header
     * that does not already carry a {@code SameSite} directive.
     *
     * Payara 6 uses the Grizzly HTTP layer; {@code response.getHeaders("Set-Cookie")}
     * returns previously-set values but modifying them after {@code chain.doFilter}
     * may not take effect if the response is already committed. We therefore set
     * the header before and after the chain via a wrapper, or — simpler — apply it
     * here as a best-effort post-chain modification which covers the common
     * non-redirect path. For redirects (303), Payara does not set a JSESSIONID cookie
     * in the same response, so the window is moot.
     */
    private static void applySameSiteStrict(HttpServletResponse response) {
        java.util.Collection<String> cookies = response.getHeaders("Set-Cookie");
        if (cookies == null || cookies.isEmpty()) {
            return;
        }
        boolean first = true;
        for (String cookie : cookies) {
            String lower = cookie.toLowerCase(java.util.Locale.ROOT);
            String updated = cookie;
            if (!lower.contains("samesite")) {
                updated = cookie + "; SameSite=Strict";
            }
            if (first) {
                response.setHeader("Set-Cookie", updated);
                first = false;
            } else {
                response.addHeader("Set-Cookie", updated);
            }
        }
    }

    private static String generateNonce() {
        byte[] bytes = new byte[18]; // 18 bytes → 24-char base64 (no padding)
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
