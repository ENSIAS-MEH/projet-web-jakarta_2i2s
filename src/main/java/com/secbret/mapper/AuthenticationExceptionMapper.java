package com.secbret.mapper;

import com.secbret.exception.AuthenticationException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

/**
 * Maps {@link AuthenticationException} → HTTP 401 Unauthorized.
 *
 * <p>Raised when the caller lacks a valid session. The caller must authenticate first.
 */
@Provider
public class AuthenticationExceptionMapper extends AbstractExceptionMapper
        implements ExceptionMapper<AuthenticationException> {

    @Override
    public Response toResponse(AuthenticationException ex) {
        return buildResponse(
                Response.Status.UNAUTHORIZED.getStatusCode(),
                "Unauthorized",
                ex.getMessage(),
                null);
    }
}
