package com.secbret.security;

import jakarta.enterprise.context.ApplicationScoped;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;

/**
 * HIBP k-anonymity password breach check (Part III §HIBP Password Check).
 *
 * <p>Sends only the 5-char SHA-1 prefix to api.pwnedpasswords.com/range/{prefix}.
 * Fail-open: any timeout / unreachable / non-200 response is logged WARN and
 * the check is skipped (registration allowed). The 3-second timeout is the
 * hard spec requirement.
 *
 * <p>Called from {@link com.secbret.service.UserService#register} and
 * from the password-reset flow.
 */
@ApplicationScoped
public class BreachCheckService {

    private static final Logger log = LoggerFactory.getLogger(BreachCheckService.class);

    private final String hibpBaseUrl;
    private final int timeoutMs;
    private final HttpClient httpClient;

    public BreachCheckService() {
        this.hibpBaseUrl = resolveEnv("HIBP_API_URL", "https://api.pwnedpasswords.com");
        this.timeoutMs = resolveInt("HIBP_TIMEOUT_MS", 3000);
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(timeoutMs))
                .build();
    }

    /** Test constructor — inject a pre-built client and override the base URL. */
    public BreachCheckService(String hibpBaseUrl, int timeoutMs, HttpClient httpClient) {
        this.hibpBaseUrl = hibpBaseUrl;
        this.timeoutMs = timeoutMs;
        this.httpClient = httpClient;
    }

    /**
     * Returns {@code true} if the password appears in a known breach dataset.
     * Returns {@code false} (fail-open) when HIBP is unreachable or times out.
     *
     * @param rawPassword the plaintext password to check
     * @return true → password is breached; false → not found OR check skipped (fail-open)
     */
    public boolean isBreached(String rawPassword) {
        if (rawPassword == null || rawPassword.isEmpty()) {
            return false;
        }
        try {
            String sha1 = sha1Hex(rawPassword).toUpperCase();
            String prefix = sha1.substring(0, 5);
            String suffix = sha1.substring(5);

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(hibpBaseUrl + "/range/" + prefix))
                    .timeout(Duration.ofMillis(timeoutMs))
                    .header("Add-Padding", "true")
                    // Forward correlation ID if present — spec §HIBP (see §Downstream)
                    .GET()
                    .build();

            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                log.warn("HIBP check returned HTTP {} — fail-open, allowing registration", resp.statusCode());
                return false;
            }
            // Response body: "SUFFIX:count\r\n..." lines (case-insensitive suffix comparison)
            for (String line : resp.body().split("\r?\n")) {
                int colon = line.indexOf(':');
                if (colon > 0 && line.substring(0, colon).equalsIgnoreCase(suffix)) {
                    return true; // password found in breach dataset
                }
            }
            return false;
        } catch (java.net.http.HttpTimeoutException timeout) {
            log.warn("HIBP check timed out after {}ms — fail-open, allowing registration", timeoutMs);
            return false;
        } catch (Exception e) {
            log.warn("HIBP check failed ({}: {}) — fail-open, allowing registration",
                    e.getClass().getSimpleName(), e.getMessage());
            return false;
        }
    }

    private static String sha1Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(40);
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-1 unavailable", e);
        }
    }

    private static String resolveEnv(String key, String defaultVal) {
        String v = System.getenv(key);
        return (v == null || v.isBlank()) ? defaultVal : v.trim();
    }

    private static int resolveInt(String key, int defaultVal) {
        String v = System.getenv(key);
        if (v == null || v.isBlank()) return defaultVal;
        try { return Integer.parseInt(v.trim()); } catch (NumberFormatException e) { return defaultVal; }
    }
}
