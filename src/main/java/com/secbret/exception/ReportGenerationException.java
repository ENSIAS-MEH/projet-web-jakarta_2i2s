package com.secbret.exception;

/**
 * Thrown by the report generator when a PDF report cannot be produced.
 * The handler marks {@code ReportJob.status = FAILED} with an {@code error_message}.
 *
 * <p>This exception does NOT produce an HTTP error response directly — it is caught
 * within the async report task and written to the database. It is listed in the
 * hierarchy for completeness per Part II §9.
 */
public class ReportGenerationException extends SecBretException {

    public ReportGenerationException(String message) {
        super(message);
    }

    public ReportGenerationException(String message, Throwable cause) {
        super(message, cause);
    }
}
