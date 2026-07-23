package com.secbret.exception;

/**
 * Thrown when an operation conflicts with the current state of a resource
 * (e.g., creating a duplicate, self-disable of the last admin account).
 *
 * <p>Mapped to HTTP 409 Conflict by {@code ConflictExceptionMapper}.
 */
public class ConflictException extends SecBretException {

    public ConflictException(String message) {
        super(message);
    }
}
