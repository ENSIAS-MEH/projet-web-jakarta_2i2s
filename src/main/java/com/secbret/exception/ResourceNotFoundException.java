package com.secbret.exception;

/**
 * Thrown when a requested resource does not exist, OR when the caller is not authorized
 * to know it exists (anti-enumeration 404, per Part II §A.2).
 *
 * <p>Mapped to HTTP 404 Not Found by {@code ResourceNotFoundExceptionMapper}.
 */
public class ResourceNotFoundException extends SecBretException {

    public ResourceNotFoundException(String message) {
        super(message);
    }

    public ResourceNotFoundException(String resourceType, Object id) {
        super(resourceType + " not found: " + id);
    }
}
