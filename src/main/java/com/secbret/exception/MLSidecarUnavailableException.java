package com.secbret.exception;

/**
 * Thrown when the ML sidecar is unreachable or the circuit breaker is OPEN.
 * The caller falls back to rules-only scoring — this is the spec-conformant degraded
 * behavior (Part II §7, §15).
 *
 * <p>This exception triggers a graceful fallback, not an HTTP error response.
 * It is listed in the hierarchy for completeness per Part II §9.
 */
public class MLSidecarUnavailableException extends SecBretException {

    public MLSidecarUnavailableException(String message) {
        super(message);
    }

    public MLSidecarUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
