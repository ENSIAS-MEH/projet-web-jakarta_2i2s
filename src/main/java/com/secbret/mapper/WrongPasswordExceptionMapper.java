package com.secbret.mapper;

import com.secbret.exception.WrongPasswordException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

/**
 * Maps {@link WrongPasswordException} → HTTP 422 Unprocessable Entity.
 *
 * <p>Used exclusively for password-confirmation failures (e.g. DELETE /auth/me
 * where the currently-authenticated user supplies an incorrect currentPassword).
 * Must NOT map to 401 (the caller IS authenticated) and must NOT use 400 (the
 * field is present and syntactically valid — it is semantically wrong).
 */
@Provider
public class WrongPasswordExceptionMapper extends AbstractExceptionMapper
        implements ExceptionMapper<WrongPasswordException> {

    @Override
    public Response toResponse(WrongPasswordException ex) {
        return buildResponse(
                422,
                "Unprocessable Entity",
                ex.getMessage(),
                null);
    }
}
