package com.secbret.mapper;

import com.secbret.exception.ResourceNotFoundException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

/**
 * Maps {@link ResourceNotFoundException} → HTTP 404 Not Found.
 *
 * <p>Used for both "resource does not exist" and "resource exists but belongs to another
 * user" cases (anti-enumeration, Part II §A.2).
 */
@Provider
public class ResourceNotFoundExceptionMapper extends AbstractExceptionMapper
        implements ExceptionMapper<ResourceNotFoundException> {

    @Override
    public Response toResponse(ResourceNotFoundException ex) {
        return buildResponse(
                Response.Status.NOT_FOUND.getStatusCode(),
                "Not Found",
                ex.getMessage(),
                null);
    }
}
