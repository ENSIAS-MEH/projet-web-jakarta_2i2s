package com.secbret.mapper;

import com.secbret.exception.ValidationException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

/**
 * Maps {@link ValidationException} → HTTP 400 Bad Request.
 *
 * <p>This handles service-layer business validation failures. Bean Validation constraint
 * violations from DTOs are handled separately by
 * {@link ConstraintViolationExceptionMapper}.
 */
@Provider
public class ValidationExceptionMapper extends AbstractExceptionMapper
        implements ExceptionMapper<ValidationException> {

    @Override
    public Response toResponse(ValidationException ex) {
        return buildResponse(
                Response.Status.BAD_REQUEST.getStatusCode(),
                "Bad Request",
                ex.getMessage(),
                null);
    }
}
