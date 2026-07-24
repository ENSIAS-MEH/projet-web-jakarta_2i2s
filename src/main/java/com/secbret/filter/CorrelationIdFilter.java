package com.secbret.filter;

import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.ext.Provider;
import org.slf4j.MDC;

import java.io.IOException;
import java.util.UUID;

/**
 * JAX-RS {@code @Provider} filter that implements the {@code X-Correlation-Id}
 * protocol defined in Part II §9.5.
 *
 * <p>Request phase (priority AUTHENTICATION - 1 so it runs first):
 * <ol>
 *   <li>Reads {@code X-Correlation-Id} from the incoming request header.</li>
 *   <li>If absent or not a valid UUID, generates a new {@link UUID}.</li>
 *   <li>Stores the ID in {@link CorrelationContext} (CDI {@code @RequestScoped}).</li>
 *   <li>Puts the ID in SLF4J MDC under key {@code correlationId} so every log line
 *       in this request thread is tagged automatically.</li>
 * </ol>
 *
 * <p>Response phase:
 * <ol>
 *   <li>Echoes the correlation ID in the {@code X-Correlation-Id} response header.</li>
 *   <li>Removes the MDC key to avoid leaking into thread pool reuse.</li>
 * </ol>
 */
@Provider
public class CorrelationIdFilter implements ContainerRequestFilter, ContainerResponseFilter {

    static final String HEADER_NAME = "X-Correlation-Id";
    static final String MDC_KEY     = "correlationId";

    @Inject
    CorrelationContext correlationContext;

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        String header = requestContext.getHeaderString(HEADER_NAME);
        UUID correlationId = parseOrGenerate(header);
        correlationContext.set(correlationId);
        MDC.put(MDC_KEY, correlationId.toString());
        // Store on the request context property so mappers can access it even when
        // CDI scope has not yet been fully populated (e.g. early filter failures).
        requestContext.setProperty(HEADER_NAME, correlationId.toString());
    }

    @Override
    public void filter(ContainerRequestContext requestContext,
                       ContainerResponseContext responseContext) throws IOException {
        String cid = correlationContext.getAsString();
        if (cid != null && !cid.isEmpty()) {
            responseContext.getHeaders().putSingle(HEADER_NAME, cid);
        }
        MDC.remove(MDC_KEY);
    }

    private UUID parseOrGenerate(String header) {
        if (header != null && !header.isBlank()) {
            try {
                return UUID.fromString(header.trim());
            } catch (IllegalArgumentException ignored) {
                // Fall through: malformed header treated as absent
            }
        }
        return UUID.randomUUID();
    }
}
