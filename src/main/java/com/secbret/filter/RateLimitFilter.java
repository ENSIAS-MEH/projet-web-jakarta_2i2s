package com.secbret.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.secbret.filter.RateLimiter.ConsumeResult;
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
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Servlet Filter implementing per-JVM rate limiting (Part II §5).
 *
 * <p>Runs BEFORE any security/auth check (filter order: registered in web.xml before
 * the Jersey MVC filter). This means even unauthenticated requests are throttled,
 * which prevents auth load during a DDoS.
 *
 * <h2>Keying matrix (Part II §5 / Part III §Rate Limits)</h2>
 * <table>
 *   <tr><th>Endpoint</th><th>Key</th><th>Capacity</th><th>Window</th></tr>
 *   <tr><td>POST /api/v1/scan</td><td>userId</td><td>RATE_LIMIT_SCAN (10)</td><td>1h</td></tr>
 *   <tr><td>POST /api/v1/incident</td><td>userId</td><td>RATE_LIMIT_REPORT (5)</td><td>1h</td></tr>
 *   <tr><td>POST /api/v1/report-jobs/*</td><td>userId</td><td>RATE_LIMIT_PDF_REPORT (3)</td><td>1h</td></tr>
 *   <tr><td>POST /api/v1/share</td><td>userId</td><td>RATE_LIMIT_SHARE (10)</td><td>1h</td></tr>
 *   <tr><td>POST /login|/register|/forgot-password|/reset-password (web form)</td>
 *       <td>clientIp</td><td>RATE_LIMIT_LOGIN/FORGOT/RESET (10/5/5)</td><td>15min</td></tr>
 *   <tr><td>GET /api/v1/dashboard/public</td><td>clientIp</td><td>RATE_LIMIT_PUBLIC (60)</td><td>1min</td></tr>
 *   <tr><td>Auth backstop: /auth/* + POST web-form auth endpoints</td>
 *       <td>clientIp</td><td>RATE_LIMIT_AUTH_BACKSTOP (100)</td><td>1h</td></tr>
 *   <tr><td>default</td><td>clientIp</td><td>RATE_LIMIT_DEFAULT (60)</td><td>1min</td></tr>
 * </table>
 *
 * <p>Rate-limit headers ({@code X-RateLimit-Limit/Remaining/Reset}) are appended to
 * every response, even non-limited ones.
 *
 * <p>On exhaustion: HTTP 429 + JSON error envelope matching Part II §E + Retry-After.
 */
@WebFilter(filterName = "RateLimitFilter", urlPatterns = "/*")
public class RateLimitFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(RateLimitFilter.class);

    // ------------------------------------------------------------------ config defaults
    private static final int DEFAULT_SCAN        = 10;
    private static final int DEFAULT_REPORT      = 5;
    private static final int DEFAULT_PDF         = 3;
    private static final int DEFAULT_SHARE       = 10;
    private static final int DEFAULT_LOGIN       = 10;
    private static final int DEFAULT_FORGOT      = 5;
    private static final int DEFAULT_RESET       = 5;
    private static final int DEFAULT_PUBLIC      = 60;
    private static final int DEFAULT_DEFAULT     = 60;
    private static final int DEFAULT_BACKSTOP    = 100;

    // window durations in milliseconds
    static final long WINDOW_HOUR   = 60 * 60 * 1000L;
    static final long WINDOW_15_MIN = 15 * 60 * 1000L;
    static final long WINDOW_MINUTE = 60 * 1000L;

    // The shared RateLimiter is package-accessible so the eviction timer can call evictExpired.
    static final RateLimiter LIMITER = new RateLimiter();

    // Comma-separated CIDRs of load balancers / reverse proxies allowed to set XFF.
    // Empty (default) => never trust XFF; use the socket peer. Set in prod when behind a proxy.
    // ponytail: IPv4 only; add IPv6 CIDR support if the LB topology requires it.
    private static final String TRUSTED_PROXY_CIDRS = System.getenv("TRUSTED_PROXY_CIDRS");

    private final ObjectMapper json = new ObjectMapper()
            .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);

    // resolved limits (read once from env at init)
    private int limitScan;
    private int limitReport;
    private int limitPdf;
    private int limitShare;
    private int limitLogin;
    private int limitForgot;
    private int limitReset;
    private int limitPublic;
    private int limitDefault;
    private int limitBackstop;

    @Override
    public void init(FilterConfig cfg) {
        limitScan     = envInt("RATE_LIMIT_SCAN",          DEFAULT_SCAN);
        limitReport   = envInt("RATE_LIMIT_REPORT",        DEFAULT_REPORT);
        limitPdf      = envInt("RATE_LIMIT_PDF_REPORT",    DEFAULT_PDF);
        limitShare    = envInt("RATE_LIMIT_SHARE",         DEFAULT_SHARE);
        limitLogin    = envInt("RATE_LIMIT_LOGIN",         DEFAULT_LOGIN);
        limitForgot   = envInt("RATE_LIMIT_FORGOT",        DEFAULT_FORGOT);
        limitReset    = envInt("RATE_LIMIT_RESET",         DEFAULT_RESET);
        limitPublic   = envInt("RATE_LIMIT_PUBLIC",        DEFAULT_PUBLIC);
        limitDefault  = envInt("RATE_LIMIT_DEFAULT",       DEFAULT_DEFAULT);
        limitBackstop = envInt("RATE_LIMIT_AUTH_BACKSTOP", DEFAULT_BACKSTOP);
        log.info("RateLimitFilter initialised: scan={} report={} pdf={} share={} " +
                 "login={} forgot={} reset={} public={} default={} backstop={}",
                 limitScan, limitReport, limitPdf, limitShare,
                 limitLogin, limitForgot, limitReset, limitPublic, limitDefault, limitBackstop);
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest  request  = (HttpServletRequest)  req;
        HttpServletResponse response = (HttpServletResponse) res;

        String method = request.getMethod();
        String path   = request.getRequestURI();
        long   now    = System.currentTimeMillis();

        // ---------------------------------------------------------------- backstop
        // Applied first on the auth surface (POST to web-form auth endpoints + /auth/*).
        // Either backstop OR fine-grained limit alone can reject.
        if (isAuthSurface(method, path)) {
            String backstopKey = "backstop:" + clientIp(request);
            ConsumeResult backstop = LIMITER.tryConsume(backstopKey, limitBackstop, WINDOW_HOUR, now);
            setRateLimitHeaders(response, backstop);
            if (!backstop.allowed) {
                reject(request, response, backstop, now);
                return;
            }
        }

        // ---------------------------------------------------------------- fine-grained
        BucketSpec spec = resolve(method, path, request);
        ConsumeResult result = LIMITER.tryConsume(spec.key, spec.capacity, spec.windowMillis, now);

        // Overwrite headers with the fine-grained rule (more informative for the caller).
        setRateLimitHeaders(response, result);

        if (!result.allowed) {
            reject(request, response, result, now);
            return;
        }

        chain.doFilter(request, response);
    }

    // ---------------------------------------------------------------- routing

    private BucketSpec resolve(String method, String path, HttpServletRequest request) {
        String userId = userId(request);
        String ip     = clientIp(request);

        // Authenticated user-keyed rules
        if ("POST".equalsIgnoreCase(method)) {
            if (path.equals("/api/v1/scan")) {
                return new BucketSpec(userId != null ? "scan:" + userId : "scan-ip:" + ip,
                        limitScan, WINDOW_HOUR);
            }
            if (path.equals("/api/v1/incident")) {
                return new BucketSpec(userId != null ? "incident:" + userId : "incident-ip:" + ip,
                        limitReport, WINDOW_HOUR);
            }
            if (path.startsWith("/api/v1/report-jobs/")) {
                return new BucketSpec(userId != null ? "pdf:" + userId : "pdf-ip:" + ip,
                        limitPdf, WINDOW_HOUR);
            }
            if (path.equals("/api/v1/share") || path.startsWith("/api/v1/share/")) {
                return new BucketSpec(userId != null ? "share:" + userId : "share-ip:" + ip,
                        limitShare, WINDOW_HOUR);
            }
            // Web-form auth endpoints (IP-keyed)
            if (path.equals("/login")) {
                return new BucketSpec("login:" + ip, limitLogin, WINDOW_15_MIN);
            }
            if (path.equals("/forgot-password")) {
                return new BucketSpec("forgot:" + ip, limitForgot, WINDOW_15_MIN);
            }
            if (path.equals("/reset-password")) {
                return new BucketSpec("reset:" + ip, limitReset, WINDOW_15_MIN);
            }
        }

        // Public dashboard (any method, but practically GET)
        if (path.equals("/api/v1/dashboard/public") || path.startsWith("/dashboard/public")) {
            return new BucketSpec("public:" + ip, limitPublic, WINDOW_MINUTE);
        }

        // Default: per-IP per-minute
        return new BucketSpec("default:" + ip + ":" + sanitisePath(path), limitDefault, WINDOW_MINUTE);
    }

    /** Auth surface: /auth/* REST prefix + POST to web-form auth endpoints. */
    private static boolean isAuthSurface(String method, String path) {
        if (path.startsWith("/auth/") || path.startsWith("/api/v1/auth/")) {
            return true;
        }
        if ("POST".equalsIgnoreCase(method)) {
            return path.equals("/login")
                    || path.equals("/register")
                    || path.equals("/forgot-password")
                    || path.equals("/reset-password");
        }
        return false;
    }

    // ---------------------------------------------------------------- helpers

    private static String userId(HttpServletRequest request) {
        java.security.Principal p = request.getUserPrincipal();
        return p != null ? p.getName() : null;
    }

    static String clientIp(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank() && isTrustedProxy(remoteAddr)) {
            int comma = xff.indexOf(',');
            return comma > 0 ? xff.substring(0, comma).trim() : xff.trim();
        }
        return remoteAddr;
    }

    private static boolean isTrustedProxy(String remoteAddr) {
        if (TRUSTED_PROXY_CIDRS == null || TRUSTED_PROXY_CIDRS.isBlank()) {
            return false;
        }
        return Arrays.stream(TRUSTED_PROXY_CIDRS.split(","))
                .map(String::trim)
                .anyMatch(cidr -> cidrContains(cidr, remoteAddr));
    }

    /**
     * Returns true if {@code ip} falls inside {@code cidr} (e.g. "10.0.0.0/8").
     * IPv4 only. Malformed CIDR or IP → false, never throws.
     */
    static boolean cidrContains(String cidr, String ip) {
        try {
            int slash = cidr.indexOf('/');
            if (slash < 0) {
                return InetAddress.getByName(cidr).getHostAddress().equals(
                        InetAddress.getByName(ip).getHostAddress());
            }
            int prefixLen = Integer.parseInt(cidr.substring(slash + 1));
            byte[] net = InetAddress.getByName(cidr.substring(0, slash)).getAddress();
            byte[] addr = InetAddress.getByName(ip).getAddress();
            if (net.length != 4 || addr.length != 4 || prefixLen < 0 || prefixLen > 32) {
                return false;
            }
            int mask = prefixLen == 0 ? 0 : (0xFFFFFFFF << (32 - prefixLen));
            int netInt  = ((net[0]  & 0xFF) << 24) | ((net[1]  & 0xFF) << 16) | ((net[2]  & 0xFF) << 8) | (net[3]  & 0xFF);
            int addrInt = ((addr[0] & 0xFF) << 24) | ((addr[1] & 0xFF) << 16) | ((addr[2] & 0xFF) << 8) | (addr[3] & 0xFF);
            return (netInt & mask) == (addrInt & mask);
        } catch (UnknownHostException | NumberFormatException e) {
            return false;
        }
    }

    private static String sanitisePath(String path) {
        // Collapse UUIDs/IDs so we don't create one bucket per resource.
        return path.replaceAll("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", ":id")
                   .replaceAll("/\\d+", "/:n");
    }

    private static void setRateLimitHeaders(HttpServletResponse response, ConsumeResult r) {
        response.setHeader("X-RateLimit-Limit",     String.valueOf(r.limit));
        response.setHeader("X-RateLimit-Remaining", String.valueOf(Math.max(0, r.remaining)));
        response.setHeader("X-RateLimit-Reset",     String.valueOf(r.resetEpochMillis / 1000));
    }

    private void reject(HttpServletRequest request, HttpServletResponse response,
                        ConsumeResult result, long nowMillis) throws IOException {
        long retryAfter = result.retryAfterSeconds(nowMillis);
        String resetInstant = Instant.ofEpochMilli(result.resetEpochMillis).toString();

        response.setStatus(429);
        response.setContentType("application/json;charset=UTF-8");
        response.setHeader("Retry-After", String.valueOf(retryAfter));

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status",    429);
        body.put("error",     "Too Many Requests");
        body.put("message",   "Rate limit exceeded. Retry after " + resetInstant + ".");
        body.put("timestamp", Instant.now().toString());
        body.put("path",      request.getRequestURI());

        json.writeValue(response.getOutputStream(), body);
    }

    private static int envInt(String name, int defaultValue) {
        String v = System.getenv(name);
        if (v == null || v.isBlank()) return defaultValue;
        try { return Integer.parseInt(v.trim()); }
        catch (NumberFormatException e) {
            log.warn("Invalid env var {}={}, using default {}", name, v, defaultValue);
            return defaultValue;
        }
    }

    // ---------------------------------------------------------------- inner type

    private static final class BucketSpec {
        final String key;
        final double capacity;
        final long   windowMillis;

        BucketSpec(String key, double capacity, long windowMillis) {
            this.key          = key;
            this.capacity     = capacity;
            this.windowMillis = windowMillis;
        }
    }
}
