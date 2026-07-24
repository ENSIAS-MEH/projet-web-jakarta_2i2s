package com.secbret.security;

import com.secbret.model.entity.SecBretUser;
import com.secbret.repository.UserRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.security.enterprise.credential.Credential;
import jakarta.security.enterprise.credential.Password;
import jakarta.security.enterprise.credential.UsernamePasswordCredential;
import jakarta.security.enterprise.identitystore.CredentialValidationResult;
import jakarta.security.enterprise.identitystore.IdentityStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Soteria {@link IdentityStore} that validates {@code username + password}
 * against {@code secbret_user} (Part II §4). On success it returns a
 * {@code CallerPrincipal} (the username) and the user's single role group.
 *
 * <p>Rejection cases — all mapped to {@code INVALID_RESULT} so the CustomForm
 * mechanism re-presents a <em>generic</em> error and never leaks which condition
 * failed (no username enumeration, Part III §1):
 * <ul>
 *   <li>unknown username</li>
 *   <li>bad password (increments failed_login_attempts; 5th → locked_until=+15min)</li>
 *   <li>{@code enabled = false}</li>
 *   <li>{@code locked_until} in the future</li>
 * </ul>
 *
 * <p>Lockout write path (Phase 5, Part III §Account Lockout):
 * <ul>
 *   <li>Wrong password → {@link UserRepository#incrementFailedLoginAttempts}</li>
 *   <li>Correct password / successful auth → {@link UserRepository#resetFailedLoginAttempts}</li>
 *   <li>Unknown user, disabled, or already-locked → no counter change (no enumeration side-channel)</li>
 * </ul>
 */
@ApplicationScoped
public class SecBretIdentityStore implements IdentityStore {

    private static final Logger log = LoggerFactory.getLogger(SecBretIdentityStore.class);

    @Inject
    UserRepository userRepository;

    @Inject
    PasswordHasher passwordHasher;

    public SecBretIdentityStore() {
    }

    /** Test constructor. */
    public SecBretIdentityStore(UserRepository userRepository, PasswordHasher passwordHasher) {
        this.userRepository = userRepository;
        this.passwordHasher = passwordHasher;
    }

    @Override
    public CredentialValidationResult validate(Credential credential) {
        if (!(credential instanceof UsernamePasswordCredential upc)) {
            return CredentialValidationResult.NOT_VALIDATED_RESULT;
        }
        return validate(upc);
    }

    /** Threshold from env (default 5) — Part III §Account Lockout. */
    private static final int LOCKOUT_THRESHOLD = resolveThreshold();

    private static int resolveThreshold() {
        String v = System.getenv("ACCOUNT_LOCKOUT_ATTEMPTS");
        if (v == null || v.isBlank()) return 5;
        try { return Integer.parseInt(v.trim()); } catch (NumberFormatException e) { return 5; }
    }

    /**
     * Overload matching Soteria's convention; the container invokes
     * {@link #validate(Credential)} which delegates here.
     */
    public CredentialValidationResult validate(UsernamePasswordCredential credential) {
        String username = credential.getCaller();
        Password password = credential.getPassword();

        Optional<SecBretUser> maybeUser = userRepository.findByUsername(username);
        if (maybeUser.isEmpty()) {
            // Unknown user — do not reveal this distinct from a bad password.
            // No counter increment: incrementing would allow username enumeration
            // via timing (DB write on miss vs. no write on hit).
            return CredentialValidationResult.INVALID_RESULT;
        }
        SecBretUser user = maybeUser.get();

        if (!user.isEnabled()) {
            log.info("Login rejected: account disabled (username={})", username);
            return CredentialValidationResult.INVALID_RESULT;
        }

        LocalDateTime lockedUntil = user.getLockedUntil();
        if (lockedUntil != null && lockedUntil.isAfter(LocalDateTime.now())) {
            log.info("Login rejected: account locked until {} (username={})", lockedUntil, username);
            return CredentialValidationResult.INVALID_RESULT;
        }

        if (!passwordHasher.verify(password.getValue() == null ? null : new String(password.getValue()),
                user.getPasswordHash())) {
            log.info("Login rejected: bad password (username={})", username);
            // Increment attempt counter; the repository atomically locks if threshold reached.
            UUID userId = user.getId();
            if (userId != null) {
                int attempts = userRepository.incrementFailedLoginAttempts(userId, LOCKOUT_THRESHOLD);
                if (attempts >= LOCKOUT_THRESHOLD) {
                    log.warn("Account locked after {} failed attempts (username={})", attempts, username);
                }
            }
            return CredentialValidationResult.INVALID_RESULT;
        }

        // Successful auth — reset the lockout counter.
        if (user.getId() != null && user.getFailedLoginAttempts() > 0) {
            userRepository.resetFailedLoginAttempts(user.getId());
        }

        Set<String> groups = Set.of(user.getRole().name());
        return new CredentialValidationResult(user.getUsername(), groups);
    }

    @Override
    public Set<ValidationType> validationTypes() {
        return java.util.EnumSet.of(ValidationType.VALIDATE, ValidationType.PROVIDE_GROUPS);
    }
}
