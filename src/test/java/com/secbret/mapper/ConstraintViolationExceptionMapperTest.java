package com.secbret.mapper;

import com.secbret.filter.CorrelationContext;
import com.secbret.model.dto.ErrorResponse;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Path;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.URI;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ConstraintViolationExceptionMapper}.
 *
 * <p>Verifies that Bean Validation failures produce HTTP 400 with the {@code errors[]}
 * list populated per Part II §E.
 */
@ExtendWith(MockitoExtension.class)
class ConstraintViolationExceptionMapperTest {

    private ConstraintViolationExceptionMapper mapper;

    @BeforeEach
    void setUp() throws Exception {
        mapper = new ConstraintViolationExceptionMapper();

        CorrelationContext correlationContext = new CorrelationContext();
        correlationContext.set(UUID.fromString("a1b2c3d4-e5f6-7890-abcd-ef1234567890"));

        UriInfo uriInfo = mock(UriInfo.class);
        when(uriInfo.getRequestUri()).thenReturn(URI.create("http://localhost/api/v1/scan"));

        mapper.correlationContext = correlationContext;
        mapper.uriInfo = uriInfo;
    }

    @Test
    @DisplayName("constraint violation maps to HTTP 400")
    void toResponse_returns400() {
        ConstraintViolationException ex = buildException("url", "must not be null");

        Response response = mapper.toResponse(ex);

        assertThat(response.getStatus()).isEqualTo(400);
    }

    @Test
    @DisplayName("constraint violation produces errors[] with per-field entries")
    void toResponse_producesFieldErrors() {
        ConstraintViolationException ex = buildException("url", "URL is not valid");

        Response response = mapper.toResponse(ex);
        ErrorResponse body = (ErrorResponse) response.getEntity();

        assertThat(body.getErrors())
                .isNotNull()
                .hasSize(1);
        assertThat(body.getErrors().get(0).getField()).isEqualTo("url");
        assertThat(body.getErrors().get(0).getMessage()).isEqualTo("URL is not valid");
    }

    @Test
    @DisplayName("constraint violation has 'Validation failed' as top-level message")
    void toResponse_hasValidationFailedMessage() {
        ConstraintViolationException ex = buildException("scanDepth", "must not be null");

        Response response = mapper.toResponse(ex);
        ErrorResponse body = (ErrorResponse) response.getEntity();

        assertThat(body.getMessage()).isEqualTo("Validation failed");
    }

    @Test
    @DisplayName("dotted property path is trimmed to leaf field name")
    void toResponse_trimmsDottedPath() {
        // Simulate JAX-RS constraint path like "createScan.submitRequest.url"
        ConstraintViolationException ex = buildException("createScan.submitRequest.url",
                "URL is not valid");

        Response response = mapper.toResponse(ex);
        ErrorResponse body = (ErrorResponse) response.getEntity();

        assertThat(body.getErrors().get(0).getField()).isEqualTo("url");
    }

    @Test
    @DisplayName("multiple violations all appear in errors[]")
    void toResponse_multipleViolations() {
        ConstraintViolation<?> cv1 = makeViolation("url", "must not be blank");
        ConstraintViolation<?> cv2 = makeViolation("scanDepth", "must not be null");
        ConstraintViolationException ex = new ConstraintViolationException(Set.of(cv1, cv2));

        Response response = mapper.toResponse(ex);
        ErrorResponse body = (ErrorResponse) response.getEntity();

        assertThat(body.getErrors()).hasSize(2);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private ConstraintViolationException buildException(String propertyPath, String message) {
        ConstraintViolation<?> cv = makeViolation(propertyPath, message);
        return new ConstraintViolationException(Set.of(cv));
    }

    @SuppressWarnings("unchecked")
    private ConstraintViolation<?> makeViolation(String propertyPath, String message) {
        ConstraintViolation<?> cv = mock(ConstraintViolation.class);
        Path path = mock(Path.class);
        when(path.toString()).thenReturn(propertyPath);
        when(cv.getPropertyPath()).thenReturn(path);
        when(cv.getMessage()).thenReturn(message);
        return cv;
    }
}
