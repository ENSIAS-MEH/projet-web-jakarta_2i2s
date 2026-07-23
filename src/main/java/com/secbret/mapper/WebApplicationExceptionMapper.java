package com.secbret.mapper;

import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

/**
 * Passes through {@link WebApplicationException} with its original HTTP status code
 * while wrapping the body in the standard {@link com.secbret.model.dto.ErrorResponse}
 * envelope.
 *
 * <p>JAX-RS throws {@code WebApplicationException} (and subclasses such as
 * {@code NotFoundException}, {@code NotAuthorizedException}) internally. This mapper
 * intercepts them so every error — including framework-generated ones — uses the
 * single uniform envelope defined in Part II §E.
 */
@Provider
public class WebApplicationExceptionMapper extends AbstractExceptionMapper
        implements ExceptionMapper<WebApplicationException> {

    @Override
    public Response toResponse(WebApplicationException ex) {
        Response original = ex.getResponse();
        int status = original.getStatus();
        String reason = reasonPhrase(status);
        String message = ex.getMessage() != null ? ex.getMessage() : reason;

        return buildResponse(status, reason, message, null);
    }

    /** Returns the canonical HTTP reason phrase for common status codes. */
    private String reasonPhrase(int status) {
        try {
            Response.Status s = Response.Status.fromStatusCode(status);
            return s != null ? s.getReasonPhrase() : "HTTP Error";
        } catch (Exception e) {
            return "HTTP Error";
        }
    }
}
