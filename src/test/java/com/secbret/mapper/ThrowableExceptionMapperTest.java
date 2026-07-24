package com.secbret.mapper;

import com.secbret.filter.CorrelationContext;
import com.secbret.model.dto.ErrorResponse;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.URI;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ThrowableExceptionMapper}.
 *
 * <p>Key requirement: the response body MUST NOT expose internal exception details
 * (stack traces, class names, internal messages). Only a generic message is allowed.
 */
@ExtendWith(MockitoExtension.class)
class ThrowableExceptionMapperTest {

    private ThrowableExceptionMapper mapper;
    private CorrelationContext correlationContext;
    private UriInfo uriInfo;

    @BeforeEach
    void setUp() throws Exception {
        mapper = new ThrowableExceptionMapper();

        correlationContext = new CorrelationContext();
        UUID cid = UUID.fromString("a1b2c3d4-e5f6-7890-abcd-ef1234567890");
        correlationContext.set(cid);

        uriInfo = mock(UriInfo.class);
        when(uriInfo.getRequestUri()).thenReturn(URI.create("http://localhost/api/v1/scan"));

        // Inject via package-private fields (same package — com.secbret.mapper)
        mapper.correlationContext = correlationContext;
        mapper.uriInfo = uriInfo;
    }

    @Test
    @DisplayName("catch-all mapper returns HTTP 500 for any unhandled exception")
    void toResponse_anyThrowable_returns500() {
        RuntimeException ex = new RuntimeException("sensitive internal detail");

        Response response = mapper.toResponse(ex);

        assertThat(response.getStatus()).isEqualTo(500);
    }

    @Test
    @DisplayName("catch-all mapper body does not leak the exception message or stack trace")
    void toResponse_bodyDoesNotLeakInternalDetails() {
        RuntimeException ex = new RuntimeException("SECRET internal db password error");

        Response response = mapper.toResponse(ex);
        ErrorResponse body = (ErrorResponse) response.getEntity();

        assertThat(body.getMessage())
                .as("response body must not contain the internal exception message")
                .doesNotContain("SECRET");
        assertThat(body.getMessage())
                .as("response body must not contain the exception class name")
                .doesNotContain("RuntimeException");
    }

    @Test
    @DisplayName("catch-all mapper body has correct status and error fields")
    void toResponse_bodyHasCorrectStatusAndError() {
        Response response = mapper.toResponse(new NullPointerException("oops"));
        ErrorResponse body = (ErrorResponse) response.getEntity();

        assertThat(body.getStatus()).isEqualTo(500);
        assertThat(body.getError()).isEqualTo("Internal Server Error");
    }

    @Test
    @DisplayName("catch-all mapper includes correlation ID in response envelope")
    void toResponse_includesCorrelationId() {
        Response response = mapper.toResponse(new IllegalStateException("boom"));
        ErrorResponse body = (ErrorResponse) response.getEntity();

        assertThat(body.getCorrelationId())
                .isEqualTo("a1b2c3d4-e5f6-7890-abcd-ef1234567890");
    }

    @Test
    @DisplayName("catch-all mapper sets the request path in response envelope")
    void toResponse_includesRequestPath() {
        Response response = mapper.toResponse(new IllegalArgumentException("bad arg"));
        ErrorResponse body = (ErrorResponse) response.getEntity();

        assertThat(body.getPath()).isEqualTo("/api/v1/scan");
    }

    @Test
    @DisplayName("catch-all mapper timestamp is non-null and uses ISO-8601 UTC Z suffix")
    void toResponse_timestampIsIso8601Utc() {
        Response response = mapper.toResponse(new RuntimeException("ts test"));
        ErrorResponse body = (ErrorResponse) response.getEntity();

        assertThat(body.getTimestamp())
                .isNotNull()
                .endsWith("Z");
    }

    @Test
    @DisplayName("catch-all mapper does not include errors[] list for non-validation errors")
    void toResponse_noErrorsList() {
        Response response = mapper.toResponse(new RuntimeException("any"));
        ErrorResponse body = (ErrorResponse) response.getEntity();

        assertThat(body.getErrors()).isNull();
    }
}
