package com.secbret.exception;

/**
 * Thrown when business-logic validation fails (as opposed to Bean Validation constraint
 * violations, which are handled by the ConstraintViolationExceptionMapper).
 *
 * <p>Mapped to HTTP 400 Bad Request by {@code ValidationExceptionMapper}.
 */
public class ValidationException extends SecBretException {

    public ValidationException(String message) {
        super(message);
    }
}
