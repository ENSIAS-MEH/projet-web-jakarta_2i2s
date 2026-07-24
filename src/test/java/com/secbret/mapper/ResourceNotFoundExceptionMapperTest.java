package com.secbret.mapper;

import com.secbret.exception.ResourceNotFoundException;
import com.secbret.filter.CorrelationContext;
import com.secbret.model.dto.ErrorResponse;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.net.URI;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ResourceNotFoundExceptionMapper}.
 *
 * <p>LENIENT strictness is used because one test ({@code twoArgConstructor_formatsMessage})
 * tests only the exception constructor and never calls through the mapper — the
 * {@code uriInfo} stub set up in {@code @BeforeEach} is unused in that test.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ResourceNotFoundExceptionMapperTest {

    private ResourceNotFoundExceptionMapper mapper;
    private static final String CORRELATION_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";

    @BeforeEach
    void setUp() {
        mapper = new ResourceNotFoundExceptionMapper();

        CorrelationContext correlationContext = new CorrelationContext();
        correlationContext.set(UUID.fromString(CORRELATION_ID));

        UriInfo uriInfo = mock(UriInfo.class);
        when(uriInfo.getRequestUri()).thenReturn(URI.create("http://localhost/api/v1/scan/42"));

        mapper.correlationContext = correlationContext;
        mapper.uriInfo = uriInfo;
    }

    @Test
    @DisplayName("ResourceNotFoundException maps to HTTP 404")
    void toResponse_returns404() {
        Response response = mapper.toResponse(new ResourceNotFoundException("Scan job not found: 42"));

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    @DisplayName("404 envelope has correct error field and message")
    void toResponse_envelopeFields() {
        Response response = mapper.toResponse(new ResourceNotFoundException("Scan job not found: 42"));
        ErrorResponse body = (ErrorResponse) response.getEntity();

        assertThat(body.getStatus()).isEqualTo(404);
        assertThat(body.getError()).isEqualTo("Not Found");
        assertThat(body.getMessage()).isEqualTo("Scan job not found: 42");
    }

    @Test
    @DisplayName("404 envelope includes correlation ID from request")
    void toResponse_includesCorrelationId() {
        Response response = mapper.toResponse(new ResourceNotFoundException("not found"));
        ErrorResponse body = (ErrorResponse) response.getEntity();

        assertThat(body.getCorrelationId()).isEqualTo(CORRELATION_ID);
    }

    @Test
    @DisplayName("404 envelope has no errors[] list")
    void toResponse_noErrorsList() {
        Response response = mapper.toResponse(new ResourceNotFoundException("not found"));
        ErrorResponse body = (ErrorResponse) response.getEntity();

        assertThat(body.getErrors()).isNull();
    }

    @Test
    @DisplayName("two-arg constructor formats message as 'Type not found: id'")
    void twoArgConstructor_formatsMessage() {
        ResourceNotFoundException ex = new ResourceNotFoundException("ScanJob", 99L);

        assertThat(ex.getMessage()).isEqualTo("ScanJob not found: 99");
    }
}
