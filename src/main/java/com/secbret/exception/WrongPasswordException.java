package com.secbret.exception;

/**
 * Thrown when a supplied password does not match the stored BCrypt hash
 * (e.g. DELETE /auth/me wrong currentPassword).
 *
 * <p>Mapped to HTTP 422 Unprocessable Entity by {@link com.secbret.mapper.WrongPasswordExceptionMapper}.
 * Intentionally distinct from AuthenticationException (401) because the caller IS
 * authenticated — the supplied confirmation password is simply incorrect.
 *
 * <p>Wrong-password attempts on DELETE /auth/me must NOT increment
 * {@code failed_login_attempts} nor trigger lockout (Part III §2.3 / DELETE /auth/me spec).
 */
public class WrongPasswordException extends SecBretException {

    public WrongPasswordException(String message) {
        super(message);
    }
}
