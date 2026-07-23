package com.secbret.model.dto;

import java.time.Instant;
import java.util.List;

/**
 * Uniform error envelope used by all JAX-RS ExceptionMappers.
 *
 * <p>Field names match Part II §E and openapi.yaml {@code ErrorResponse} schema exactly:
 * {@code status}, {@code error}, {@code message}, {@code timestamp}, {@code path},
 * {@code correlationId}, and optional {@code errors} list for validation failures.
 *
 * <p>Timestamp is always ISO-8601 UTC with Z suffix (e.g. 2026-06-17T10:00:00Z).
 * The {@code errors} field is {@code null} (omitted from JSON) for non-validation errors.
 */
public class ErrorResponse {

    private final int status;
    private final String error;
    private final String message;
    private final String timestamp;
    private final String path;
    private final String correlationId;
    private final List<FieldError> errors;

    private ErrorResponse(Builder builder) {
        this.status        = builder.status;
        this.error         = builder.error;
        this.message       = builder.message;
        this.timestamp     = builder.timestamp;
        this.path          = builder.path;
        this.correlationId = builder.correlationId;
        this.errors        = builder.errors;
    }

    public int getStatus()            { return status; }
    public String getError()          { return error; }
    public String getMessage()        { return message; }
    public String getTimestamp()      { return timestamp; }
    public String getPath()           { return path; }
    public String getCorrelationId()  { return correlationId; }
    /** Null when there are no field-level validation errors (omitted by Jackson). */
    public List<FieldError> getErrors() { return errors; }

    // -----------------------------------------------------------------------
    // Nested value type: one entry per failed field in validation errors
    // -----------------------------------------------------------------------

    /**
     * Per-field validation error entry.
     * Field names {@code field} and {@code message} match the openapi.yaml schema.
     */
    public static final class FieldError {
        private final String field;
        private final String message;

        public FieldError(String field, String message) {
            this.field   = field;
            this.message = message;
        }

        public String getField()   { return field; }
        public String getMessage() { return message; }
    }

    // -----------------------------------------------------------------------
    // Builder
    // -----------------------------------------------------------------------

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private int status;
        private String error;
        private String message;
        private String timestamp = Instant.now().toString(); // ISO-8601 UTC with Z
        private String path;
        private String correlationId;
        private List<FieldError> errors;  // null unless validation failure

        private Builder() {}

        public Builder status(int status)               { this.status = status;               return this; }
        public Builder error(String error)              { this.error = error;                 return this; }
        public Builder message(String message)          { this.message = message;             return this; }
        public Builder timestamp(String timestamp)      { this.timestamp = timestamp;         return this; }
        public Builder path(String path)                { this.path = path;                   return this; }
        public Builder correlationId(String cid)        { this.correlationId = cid;           return this; }
        public Builder errors(List<FieldError> errors)  { this.errors = errors;               return this; }

        public ErrorResponse build() {
            return new ErrorResponse(this);
        }
    }
}
