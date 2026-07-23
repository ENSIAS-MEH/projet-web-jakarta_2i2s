package com.secbret.mapper;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Catch-all JAX-RS ExceptionMapper that intercepts any unhandled {@link Throwable}
 * and returns HTTP 500 with the standard error envelope.
 *
 * <p>Security contract (Part II §9, Part II §E):
 * <ul>
 *   <li>The response body contains ONLY a generic message — never the exception class,
 *       message, stack trace, or any internal state (prevents information leakage).</li>
 *   <li>The full exception, including correlation ID, is logged at ERROR level
 *       server-side so support staff can investigate via the {@code correlationId}.</li>
 * </ul>
 *
 * <p>This mapper has the widest type ({@code Throwable}) so it is the lowest-priority
 * fallback; more specific mappers registered elsewhere take precedence.
 */
@Provider
public class ThrowableExceptionMapper extends AbstractExceptionMapper
        implements ExceptionMapper<Throwable> {

    private static final Logger LOG = LoggerFactory.getLogger(ThrowableExceptionMapper.class);

    @Override
    public Response toResponse(Throwable ex) {
        String cid = correlationContext != null ? correlationContext.getAsString() : "";
        // Log full detail server-side; NEVER include stack trace or ex.getMessage() in the body.
        LOG.error("Unhandled exception [correlationId={}]: {}", cid, ex.toString(), ex);

        return buildResponse(
                Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(),
                "Internal Server Error",
                "An unexpected error occurred. Reference: " + cid,
                null);
    }
}
