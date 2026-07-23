package com.secbret.scanner;

import java.security.cert.Certificate;
import java.util.List;
import java.util.Map;

/**
 * Result of a pin-and-connect fetch by {@link PinnedHttpConnector}.
 *
 * @param statusCode    HTTP status of the final response
 * @param headers       response headers, keys lower-cased, first-value-wins
 * @param body          decoded response body (UTF-8), capped at 5 MB
 * @param peerCerts     TLS peer certificate chain for https, else {@code null}
 * @param redirectChain the full URL chain observed (index 0 = original), immutable
 * @param hopCount      number of redirect hops taken (0 = no redirect)
 */
public record PinnedResponse(
        int statusCode,
        Map<String, String> headers,
        String body,
        Certificate[] peerCerts,
        List<String> redirectChain,
        int hopCount) {

    /** The {@code Location} header, or {@code null} if absent. */
    public String location() {
        return headers.get("location");
    }

    /** Case-insensitive header lookup (keys are already lower-cased). */
    public String header(String name) {
        return headers.get(name.toLowerCase(java.util.Locale.ROOT));
    }

    /** Return a copy with the redirect chain + hop count filled in. */
    PinnedResponse withChain(List<String> chain, int hops) {
        return new PinnedResponse(statusCode, headers, body, peerCerts, List.copyOf(chain), hops);
    }
}
