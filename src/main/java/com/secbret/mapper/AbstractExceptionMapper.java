package com.secbret.mapper;

import com.secbret.filter.CorrelationContext;
import com.secbret.model.dto.ErrorResponse;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import java.util.List;

/**
 * Shared utility base for all JAX-RS ExceptionMappers.
 *
 * <p>Builds a {@link ErrorResponse} envelope with the correct status, HTTP reason phrase,
 * request path, and correlation ID, then wraps it in a {@link Response}.
 *
 * <p>This is NOT itself a {@code @Provider} — subclasses register the appropriate
 * exception type.
 */
abstract class AbstractExceptionMapper {

    @Inject
    CorrelationContext correlationContext;

    @Context
    UriInfo uriInfo;

    /**
     * Builds a JSON {@link Response} using the standard error envelope.
     *
     * @param status     HTTP status code
     * @param error      HTTP reason phrase (e.g. "Not Found")
     * @param message    Human-readable detail message (never internal state)
     * @param fieldErrors per-field validation errors, or {@code null}
     */
    Response buildResponse(int status, String error, String message,
                           List<ErrorResponse.FieldError> fieldErrors) {
        String path = uriInfo != null ? uriInfo.getRequestUri().getPath() : "";
        String cid  = correlationContext != null ? correlationContext.getAsString() : "";

        ErrorResponse body = ErrorResponse.builder()
                .status(status)
                .error(error)
                .message(message)
                .path(path)
                .correlationId(cid)
                .errors(fieldErrors)
                .build();

        return Response.status(status)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .entity(body)
                .build();
    }
}
