package com.secbret.exception;

/**
 * Thrown by the scanner when a scan cannot complete (network error, timeout, SSRF
 * violation, etc.). The handler marks {@code ScanJob.status = FAILED} and stores
 * the message in {@code error_message}. No retry is attempted (Part II decision #17).
 *
 * <p>This exception does NOT produce an HTTP error response directly — it is caught
 * within the async scanner task and written to the database. It is listed in the
 * hierarchy for completeness per Part II §9.
 */
public class ScanFailedException extends SecBretException {

    public ScanFailedException(String message) {
        super(message);
    }

    public ScanFailedException(String message, Throwable cause) {
        super(message, cause);
    }
}
