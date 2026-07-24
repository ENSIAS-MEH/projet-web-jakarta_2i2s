package com.secbret.mapper;

import com.secbret.model.dto.ErrorResponse;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Maps {@link ConstraintViolationException} → HTTP 400 Bad Request with a populated
 * {@code errors[]} list, one entry per violated constraint.
 *
 * <p>Each entry in {@code errors[]} has:
 * <ul>
 *   <li>{@code field} — the property path (e.g. {@code "url"}, {@code "submitRequest.url"})</li>
 *   <li>{@code message} — the constraint message (e.g. {@code "URL is not valid"})</li>
 * </ul>
 *
 * <p>Per Part II §E and openapi.yaml {@code ErrorResponse} schema.
 */
@Provider
public class ConstraintViolationExceptionMapper extends AbstractExceptionMapper
        implements ExceptionMapper<ConstraintViolationException> {

    @Override
    public Response toResponse(ConstraintViolationException ex) {
        List<ErrorResponse.FieldError> fieldErrors = ex.getConstraintViolations()
                .stream()
                .map(this::toFieldError)
                .collect(Collectors.toList());

        return buildResponse(
                Response.Status.BAD_REQUEST.getStatusCode(),
                "Bad Request",
                "Validation failed",
                fieldErrors);
    }

    private ErrorResponse.FieldError toFieldError(ConstraintViolation<?> cv) {
        // The property path may be prefixed with the method/class name (e.g.
        // "createScan.submitRequest.url") — strip everything up to the last segment
        // to return just the field name (e.g. "url"), which matches the JSON DTO field.
        String fullPath   = cv.getPropertyPath().toString();
        String fieldName  = extractLeafName(fullPath);
        return new ErrorResponse.FieldError(fieldName, cv.getMessage());
    }

    /**
     * Extracts the leaf property name from a dotted path.
     * e.g. "createScan.submitRequest.url" → "url"
     *      "url"                           → "url"
     */
    private String extractLeafName(String path) {
        if (path == null || path.isEmpty()) {
            return "";
        }
        int lastDot = path.lastIndexOf('.');
        return lastDot >= 0 ? path.substring(lastDot + 1) : path;
    }
}
