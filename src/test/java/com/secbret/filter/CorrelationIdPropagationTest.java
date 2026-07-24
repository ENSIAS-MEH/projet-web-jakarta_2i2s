package com.secbret.filter;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Verifies that {@link CorrelationIdFilter} reads {@code X-Correlation-Id} from the
 * request header and stores it in {@link CorrelationContext}, and echoes it on the
 * response header, per Part II §9.5.
 */
@ExtendWith(MockitoExtension.class)
class CorrelationIdPropagationTest {

    private static final String SUPPLIED_CID = "deadbeef-dead-beef-dead-beefdeadbeef";

    private CorrelationContext correlationContext;
    private CorrelationIdFilter filter;

    @BeforeEach
    void setUp() {
        correlationContext = new CorrelationContext();
        filter = new CorrelationIdFilter();
        filter.correlationContext = correlationContext;  // package-private injection
    }

    @Test
    @DisplayName("correlation ID from X-Correlation-Id request header is stored in CorrelationContext")
    void filter_suppliedHeader_storedInContext() throws IOException {
        ContainerRequestContext requestContext = mockRequestContext(SUPPLIED_CID);
        filter.filter(requestContext);

        assertThat(correlationContext.getAsString()).isEqualTo(SUPPLIED_CID);
    }

    @Test
    @DisplayName("UUID is generated and stored when X-Correlation-Id header is absent")
    void filter_absentHeader_generatesUuid() throws IOException {
        ContainerRequestContext requestContext = mockRequestContext(null);
        filter.filter(requestContext);

        String cid = correlationContext.getAsString();
        assertThat(cid)
                .isNotNull()
                .isNotEmpty()
                .matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    }

    @Test
    @DisplayName("malformed X-Correlation-Id header falls back to a generated UUID")
    void filter_malformedHeader_generatesUuid() throws IOException {
        ContainerRequestContext requestContext = mockRequestContext("not-a-valid-uuid!!!");
        filter.filter(requestContext);

        String cid = correlationContext.getAsString();
        assertThat(cid)
                .matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
        assertThat(cid).doesNotContain("not-a-valid-uuid");
    }

    @Test
    @DisplayName("correlation ID is echoed in X-Correlation-Id response header")
    void filter_response_echoesCorrelationId() throws IOException {
        // First do the request phase
        ContainerRequestContext requestContext = mockRequestContext(SUPPLIED_CID);
        filter.filter(requestContext);

        // Then do the response phase
        ContainerResponseContext responseContext = mock(ContainerResponseContext.class);
        MultivaluedMap<String, Object> responseHeaders = new MultivaluedHashMap<>();
        when(responseContext.getHeaders()).thenReturn(responseHeaders);

        filter.filter(requestContext, responseContext);

        assertThat(responseHeaders.getFirst(CorrelationIdFilter.HEADER_NAME))
                .isEqualTo(SUPPLIED_CID);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private ContainerRequestContext mockRequestContext(String correlationIdHeader) {
        ContainerRequestContext ctx = mock(ContainerRequestContext.class);
        when(ctx.getHeaderString(CorrelationIdFilter.HEADER_NAME)).thenReturn(correlationIdHeader);
        doNothing().when(ctx).setProperty(any(), any());
        return ctx;
    }
}
