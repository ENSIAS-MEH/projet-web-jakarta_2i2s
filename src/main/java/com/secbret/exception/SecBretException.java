package com.secbret.exception;

/**
 * Base unchecked exception for all SecBret domain errors.
 *
 * <p>Hierarchy per Part II §9 Custom Exception Hierarchy:
 * <pre>
 * SecBretException (base)
 * ├── ResourceNotFoundException  → 404
 * ├── ValidationException        → 400
 * ├── AuthorizationException     → 403
 * ├── AuthenticationException    → 401
 * ├── ConflictException          → 409
 * ├── ScanFailedException        → maps to ScanJob.status=FAILED
 * ├── ReportGenerationException  → maps to ReportJob.status=FAILED
 * └── MLSidecarUnavailableException → graceful fallback to rules only
 * </pre>
 */
public class SecBretException extends RuntimeException {

    public SecBretException(String message) {
        super(message);
    }

    public SecBretException(String message, Throwable cause) {
        super(message, cause);
    }
}
