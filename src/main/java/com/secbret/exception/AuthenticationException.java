package com.secbret.exception;

/**
 * Thrown when a request lacks a valid session (unauthenticated caller).
 *
 * <p>Mapped to HTTP 401 Unauthorized by {@code AuthenticationExceptionMapper}.
 */
public class AuthenticationException extends SecBretException {

    public AuthenticationException(String message) {
        super(message);
    }
}
