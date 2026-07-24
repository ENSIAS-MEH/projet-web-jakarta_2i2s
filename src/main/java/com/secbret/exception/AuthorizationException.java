package com.secbret.exception;

/**
 * Thrown when an authenticated caller's role does not permit the requested action.
 *
 * <p>Mapped to HTTP 403 Forbidden by {@code AuthorizationExceptionMapper}.
 *
 * <p>Note: ownership failures (resource exists but belongs to another user) MUST
 * raise {@link ResourceNotFoundException} (→ 404), not this exception, per
 * Part II §A.2 (anti-enumeration rule).
 */
public class AuthorizationException extends SecBretException {

    public AuthorizationException(String message) {
        super(message);
    }
}
