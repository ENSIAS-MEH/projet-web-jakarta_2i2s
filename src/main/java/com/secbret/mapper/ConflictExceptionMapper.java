package com.secbret.mapper;

import com.secbret.exception.ConflictException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

/**
 * Maps {@link ConflictException} → HTTP 409 Conflict.
 */
@Provider
public class ConflictExceptionMapper extends AbstractExceptionMapper
        implements ExceptionMapper<ConflictException> {

    @Override
    public Response toResponse(ConflictException ex) {
        return buildResponse(
                Response.Status.CONFLICT.getStatusCode(),
                "Conflict",
                ex.getMessage(),
                null);
    }
}
