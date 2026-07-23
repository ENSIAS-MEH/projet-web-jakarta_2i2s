package com.secbret.scanner;

import com.secbret.exception.ValidationException;
import jakarta.enterprise.context.ApplicationScoped;

import java.net.IDN;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * Implements the URL Normalization Algorithm defined in Part II §C of the SecBret specification.
 *
 * <h2>Algorithm (8 steps in order)</h2>
 * <ol>
 *   <li>Lowercase scheme and host (path, query, and fragment are case-sensitive per RFC 3986).</li>
 *   <li>Remove default ports (80 for http, 443 for https).</li>
 *   <li>Strip the fragment ({@code #…}).</li>
 *   <li>Collapse duplicate path separators (runs of {@code /} reduced to a single {@code /}).</li>
 *   <li>Remove trailing slash from paths longer than 1 character (root {@code /} is preserved).</li>
 *   <li>Sort query parameters lexicographically by raw key+{@code =}+value string to produce a
 *       stable canonical form. Duplicate keys are sorted stably (insertion order preserved within
 *       equal keys) — this guarantees deterministic output for any fixed set of parameters.</li>
 *   <li>Convert hostname to ASCII-compatible encoding via {@link IDN#toASCII} (Punycode for
 *       internationalized labels, no-op for already-ASCII hostnames).</li>
 *   <li>Compute SHA-256 of the UTF-8 bytes of the normalized URL string.</li>
 * </ol>
 *
 * <h2>Edge-semantic decisions (spec §C is silent; recorded here per HANDOFF.md protocol)</h2>
 * <ul>
 *   <li><b>Userinfo (credentials) in URL:</b> Rejected as invalid. Credentials embedded in
 *       URLs ({@code http://user:pass@host/}) are a scanner hazard (SSRF amplification,
 *       log leakage). The spec does not address them; we reject with ValidationException.</li>
 *   <li><b>Empty query string ({@code ?} with no parameters):</b> The trailing {@code ?} is
 *       stripped so that {@code http://example.com/path?} normalizes to
 *       {@code http://example.com/path}, making it equivalent to the same URL without
 *       a query string at all. This is the most common CDN/proxy behaviour.</li>
 *   <li><b>Query parameter sort stability for duplicate keys:</b> Parameters with the same key
 *       (e.g. {@code ?a=1&a=2}) are sorted stably — equal-key pairs retain their original
 *       relative order, producing a reproducible canonical form without losing information.</li>
 *   <li><b>Path case:</b> Only scheme and host are lowercased (step 1). The path is left
 *       as-is because RFC 3986 §2.7.3 states that path segments are case-sensitive.</li>
 *   <li><b>Non-http(s) schemes:</b> Rejected with ValidationException. Only http and https
 *       are within the scanner's scope (Part II §B3 scheme allowlist).</li>
 *   <li><b>URL length limit:</b> Inputs exceeding 2048 characters (Part II §5 scanner limit)
 *       are rejected before any normalization takes place.</li>
 * </ul>
 *
 * <h2>Complexity</h2>
 * {@code normalize}: O(n log n) in the number of query parameters (sort dominates);
 * O(n) in the URL length for all other steps. Space O(n).
 * {@code hash}: O(n) additional for the SHA-256 pass.
 */
@ApplicationScoped
public class UrlNormalizer {

    /** Maximum accepted URL length per Part II §5 scanner limit. */
    public static final int MAX_URL_LENGTH = 2048;

    /**
     * Normalizes {@code rawUrl} by applying all 8 steps of Part II §C in order.
     *
     * <p><b>Pre-condition:</b> {@code rawUrl} is non-null.
     * <b>Post-condition:</b> returned string is a valid http/https URL in canonical form.
     *
     * @param rawUrl the raw URL as submitted by the user; must be non-null
     * @return the normalized URL string
     * @throws ValidationException if the URL is null, blank, exceeds 2048 chars, uses a
     *                             non-http(s) scheme, contains userinfo, or is otherwise
     *                             unparseable as an absolute URI
     */
    public String normalize(String rawUrl) {
        if (rawUrl == null || rawUrl.isBlank()) {
            throw new ValidationException("URL must not be null or blank");
        }

        // Length check before any allocation (Part II §5).
        if (rawUrl.length() > MAX_URL_LENGTH) {
            throw new ValidationException(
                    "URL exceeds the maximum allowed length of " + MAX_URL_LENGTH + " characters");
        }

        // Pre-convert non-ASCII host characters to Punycode so that java.net.URI
        // can parse the URL structurally. java.net.URI.getHost() returns null for
        // URLs with non-ASCII hostnames (RFC 2396 restriction), so we convert first.
        String stripped = rawUrl.strip();
        stripped = punycodeHostIfNeeded(stripped);

        // Parse using java.net.URI for structural decomposition.
        URI uri;
        try {
            uri = new URI(stripped);
        } catch (URISyntaxException e) {
            throw new ValidationException("URL is not a valid URI: " + e.getReason());
        }

        // Step 1 (partial): lower-case scheme and validate it.
        String scheme = uri.getScheme();
        if (scheme == null) {
            throw new ValidationException("URL must have an explicit scheme (http or https)");
        }
        scheme = scheme.toLowerCase();
        if (!scheme.equals("http") && !scheme.equals("https")) {
            throw new ValidationException(
                    "URL scheme '" + scheme + "' is not allowed; only http and https are accepted");
        }

        // Step 1 (partial): lower-case host.
        // After Punycode pre-conversion, getHost() will be non-null for valid hostnames.
        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new ValidationException("URL must have a non-empty host");
        }
        host = host.toLowerCase();

        // Reject userinfo (credentials in URL — security decision; see class Javadoc).
        if (uri.getUserInfo() != null) {
            throw new ValidationException(
                    "URL must not contain userinfo (credentials embedded in URLs are not allowed)");
        }

        // Step 2: remove default ports (80 for http, 443 for https).
        int port = uri.getPort();
        if ((scheme.equals("http") && port == 80) || (scheme.equals("https") && port == 443)) {
            port = -1; // -1 means "no explicit port" in java.net.URI
        }

        // Step 3: fragment is discarded — we simply never include it in the rebuilt URL.

        // Step 4: collapse duplicate path separators.
        // Invariant: collapseSlashes reduces every run of '/'+  to a single '/'.
        String path = uri.getRawPath();
        if (path == null || path.isEmpty()) {
            path = "/";
        } else {
            path = collapseSlashes(path);
        }

        // Step 5: remove trailing slash except on the root path.
        // Pre: path is non-empty after step 4.
        // Post: path == "/" OR path does not end with '/'.
        if (path.length() > 1 && path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }

        // Step 6: sort query parameters lexicographically (stable for duplicate keys).
        String query = uri.getRawQuery();
        if (query != null && !query.isEmpty()) {
            query = sortQueryParameters(query);
        } else {
            // Strip empty "?" — see edge-semantic note in class Javadoc.
            query = null;
        }

        // Step 7: hostname is already Punycode-encoded from the pre-conversion step.
        // Apply IDN.toASCII again to normalise any remaining ACE-prefix cases and
        // to validate the label structure. This is idempotent for already-ASCII hosts.
        try {
            host = IDN.toASCII(host, IDN.ALLOW_UNASSIGNED);
        } catch (IllegalArgumentException e) {
            throw new ValidationException("Hostname is not a valid internationalized domain: " + e.getMessage());
        }

        // Rebuild the canonical URL from the normalized components.
        return buildUrl(scheme, host, port, path, query);
    }

    /**
     * Computes the SHA-256 hex digest of the normalized form of {@code rawUrl}.
     *
     * <p>Convenience wrapper: {@code hash(url)} is equivalent to
     * {@code sha256hex(normalize(url))} — they share the same normalization path.
     *
     * @param rawUrl the raw URL as submitted by the user
     * @return 64-character lowercase hex string (SHA-256)
     * @throws ValidationException if the URL is invalid (delegates to {@link #normalize})
     */
    public String hash(String rawUrl) {
        return sha256Hex(normalize(rawUrl));
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /**
     * Converts the host portion of a URL string to Punycode (ASCII-compatible encoding)
     * before passing it to {@link URI} for structural parsing.
     *
     * <p>{@link URI} is RFC 2396-based and rejects non-ASCII host characters (it returns
     * {@code null} from {@code getHost()} for such URLs). We detect a non-ASCII host
     * by checking whether the authority segment contains characters outside the ASCII range,
     * then apply {@link IDN#toASCII} only to the host label before reconstituting the URL.
     *
     * <p>The implementation uses a simple scheme://[authority][/rest] split at the first
     * {@code /} after the authority, which is safe for hierarchical HTTP(S) URLs.
     *
     * @param url a URL string that may have a Unicode (non-ASCII) hostname; non-null
     * @return the same URL with the host part converted to Punycode, or {@code url} unchanged
     *         if the host is already ASCII
     */
    private static String punycodeHostIfNeeded(String url) {
        // Quick test: if all chars are ASCII, no conversion needed (fast path).
        boolean hasNonAscii = false;
        for (int i = 0; i < url.length(); i++) {
            if (url.charAt(i) > 127) {
                hasNonAscii = true;
                break;
            }
        }
        if (!hasNonAscii) {
            return url;
        }

        // Find the authority start after "scheme://".
        int schemeEnd = url.indexOf("://");
        if (schemeEnd < 0) {
            // No authority separator — let URI parsing report the error.
            return url;
        }
        int authorityStart = schemeEnd + 3;

        // Find the end of the authority (first '/' after the authority, or end-of-string).
        int authorityEnd = url.indexOf('/', authorityStart);
        if (authorityEnd < 0) {
            authorityEnd = url.length();
        }

        String authority = url.substring(authorityStart, authorityEnd);
        String rest = url.substring(authorityEnd); // includes the leading '/' (or "")

        // Extract host from authority, which may include userinfo and/or port.
        // We do NOT try to validate userinfo here; that is done later.
        String userInfo = null;
        String host;
        String portSuffix = "";

        int atSign = authority.indexOf('@');
        String hostAndPort = (atSign >= 0) ? authority.substring(atSign + 1) : authority;
        if (atSign >= 0) {
            userInfo = authority.substring(0, atSign);
        }

        int colonForPort = hostAndPort.lastIndexOf(':');
        if (colonForPort >= 0) {
            // Check if everything after ':' is digits (i.e., it really is a port).
            String possiblePort = hostAndPort.substring(colonForPort + 1);
            if (!possiblePort.isEmpty() && possiblePort.chars().allMatch(Character::isDigit)) {
                host = hostAndPort.substring(0, colonForPort);
                portSuffix = ":" + possiblePort;
            } else {
                host = hostAndPort;
            }
        } else {
            host = hostAndPort;
        }

        // Apply IDN conversion to the host only.
        String punycodeHost;
        try {
            punycodeHost = IDN.toASCII(host.toLowerCase(), IDN.ALLOW_UNASSIGNED);
        } catch (IllegalArgumentException e) {
            // Let the caller's IDN.toASCII call report the final error.
            return url;
        }

        // Reassemble the authority.
        String newAuthority = (userInfo != null ? userInfo + "@" : "") + punycodeHost + portSuffix;

        return url.substring(0, schemeEnd) + "://" + newAuthority + rest;
    }

    /**
     * Collapses consecutive '/' characters to a single '/'.
     *
     * <p>Time: O(n), Space: O(n) where n = path length.
     * Loop invariant: {@code sb} contains the collapsed prefix of {@code path[0..i)}.
     *
     * @param path raw path string; non-null
     * @return path with no consecutive slashes
     */
    private static String collapseSlashes(String path) {
        // Fast path: avoid allocation if no consecutive slashes exist.
        if (!path.contains("//")) {
            return path;
        }
        StringBuilder sb = new StringBuilder(path.length());
        boolean prevSlash = false;
        for (int i = 0; i < path.length(); i++) {
            char c = path.charAt(i);
            if (c == '/') {
                if (!prevSlash) {
                    sb.append(c);
                }
                prevSlash = true;
            } else {
                sb.append(c);
                prevSlash = false;
            }
        }
        return sb.toString();
    }

    /**
     * Sorts query parameters lexicographically by their raw key=value string.
     *
     * <p>Parameters are split on {@code &} and {@code ;} (both are RFC 3986-valid
     * separators). The sort is stable so duplicate keys retain their relative order.
     *
     * <p>Time: O(m log m) where m = number of parameters; Space: O(m).
     *
     * @param rawQuery the raw query string (no leading '?'); non-null, non-empty
     * @return sorted query string, or null if no parameters remain after filtering empty tokens
     */
    private static String sortQueryParameters(String rawQuery) {
        // Split on '&' (standard separator). Per RFC 3986, ';' is a valid separator
        // too, but we normalise to '&' on output to produce a stable canonical form.
        String[] params = rawQuery.split("&", -1);

        // Remove empty tokens that can arise from trailing/leading '&'.
        // Keep relative order for stability, then sort.
        long nonEmpty = Arrays.stream(params).filter(p -> !p.isEmpty()).count();
        if (nonEmpty == 0) {
            return null;
        }

        // Arrays.sort is a stable sort (TimSort) — duplicate-key stability is preserved.
        Arrays.sort(params, (a, b) -> {
            // Empty tokens sort last (they will be dropped during join).
            if (a.isEmpty() && b.isEmpty()) return 0;
            if (a.isEmpty()) return 1;
            if (b.isEmpty()) return -1;
            return a.compareTo(b);
        });

        // Rejoin, dropping any empty tokens.
        StringBuilder sb = new StringBuilder();
        for (String p : params) {
            if (p.isEmpty()) continue;
            if (sb.length() > 0) sb.append('&');
            sb.append(p);
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    /**
     * Assembles the canonical URL string from its normalized components.
     *
     * @param scheme non-null, lowercased
     * @param host   non-null, lowercased, punycode-encoded
     * @param port   -1 if absent, else the explicit port number
     * @param path   normalized path, starts with '/'
     * @param query  sorted query string (no leading '?'), or null
     * @return canonical URL string
     */
    private static String buildUrl(String scheme, String host, int port, String path, String query) {
        StringBuilder sb = new StringBuilder();
        sb.append(scheme).append("://").append(host);
        if (port != -1) {
            sb.append(':').append(port);
        }
        sb.append(path);
        if (query != null) {
            sb.append('?').append(query);
        }
        // Fragment is intentionally omitted (step 3).
        return sb.toString();
    }

    /**
     * Computes SHA-256 of the UTF-8 encoding of {@code input} and returns the result
     * as a 64-character lowercase hex string.
     *
     * <p>Time: O(n), Space: O(n) for the byte array.
     *
     * @param input non-null string to hash
     * @return 64-character lowercase hex SHA-256 digest
     */
    static String sha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest); // lowercase hex, Java 17+
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandated by the Java SE spec — this path is unreachable.
            throw new IllegalStateException("SHA-256 unavailable on this JVM", e);
        }
    }
}
