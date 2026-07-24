package com.secbret.filter;

import jakarta.enterprise.context.RequestScoped;

import java.util.UUID;

/**
 * CDI {@code @RequestScoped} bean that carries the correlation ID for the current
 * HTTP request thread, per Part II §9.5.
 *
 * <p>Lifecycle:
 * <ol>
 *   <li>{@link CorrelationIdFilter} reads {@code X-Correlation-Id} from the
 *       incoming request (or generates a new UUID) and calls {@link #set(UUID)}.</li>
 *   <li>ExceptionMappers call {@link #getAsString()} to fill the {@code correlationId}
 *       field of the {@link com.secbret.model.dto.ErrorResponse} envelope.</li>
 *   <li>The SLF4J MDC key {@code correlationId} is managed by the filter so every
 *       log line is tagged automatically.</li>
 * </ol>
 */
@RequestScoped
public class CorrelationContext {

    private UUID correlationId;

    /** Called once per request by {@link CorrelationIdFilter} before the chain runs. */
    public void set(UUID correlationId) {
        this.correlationId = correlationId;
    }

    /** Returns the correlation UUID for this request, or {@code null} if not yet set. */
    public UUID get() {
        return correlationId;
    }

    /**
     * Returns the correlation ID as a string (UUID canonical form), or an empty string
     * if no ID has been set (should not happen in production request scope).
     */
    public String getAsString() {
        return correlationId != null ? correlationId.toString() : "";
    }
}
