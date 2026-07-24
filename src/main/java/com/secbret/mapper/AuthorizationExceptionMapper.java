package com.secbret.mapper;

import com.secbret.exception.AuthorizationException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

/**
 * Maps {@link AuthorizationException} → HTTP 403 Forbidden.
 *
 * <p>Only raised when the caller's role does not permit an action (role-based).
 * Resource ownership failures MUST use {@link com.secbret.exception.ResourceNotFoundException}
 * (→ 404) per Part II §A.2 anti-enumeration rule.
 */
@Provider
public class AuthorizationExceptionMapper extends AbstractExceptionMapper
        implements ExceptionMapper<AuthorizationException> {

    @Override
    public Response toResponse(AuthorizationException ex) {
        return buildResponse(
                Response.Status.FORBIDDEN.getStatusCode(),
                "Forbidden",
                ex.getMessage(),
                null);
    }
}
