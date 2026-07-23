package com.secbret.service;

import com.secbret.email.EmailService;
import com.secbret.exception.ValidationException;
import com.secbret.model.entity.PasswordResetToken;
import com.secbret.model.entity.SecBretUser;
import com.secbret.repository.PasswordResetTokenRepository;
import com.secbret.repository.UserRepository;
import com.secbret.security.BreachCheckService;
import com.secbret.security.PasswordHasher;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Optional;

/**
 * Password reset token lifecycle (Part III §GET/POST /forgot-password + /reset-password).
 *
 * <p>Anti-enumeration guarantee: {@link #requestReset} ALWAYS returns without error —
 * unknown email, disabled account, or SMTP outage all produce the same void return.
 * The caller must render a generic confirmation regardless.
 *
 * <p>Token properties (Part III §POST /reset-password):
 * <ul>
 *   <li>Single-use: marked used_at on consumption</li>
 *   <li>1h TTL</li>
 *   <li>Only SHA-256 hash stored; plaintext travels in the email link only</li>
 *   <li>Successful reset invalidates ALL user's outstanding tokens</li>
 * </ul>
 */
@ApplicationScoped
public class PasswordResetService {

    private static final Logger log = LoggerFactory.getLogger(PasswordResetService.class);
    private static final int TOKEN_BYTES = 32; // 256 bits of entropy

    @Inject
    UserRepository userRepository;

    @Inject
    PasswordResetTokenRepository tokenRepository;

    @Inject
    PasswordHasher passwordHasher;

    @Inject
    BreachCheckService breachCheckService;

    @Inject
    EmailService emailService;

    public PasswordResetService() {
    }

    /** Test constructor. */
    public PasswordResetService(UserRepository userRepository,
                                 PasswordResetTokenRepository tokenRepository,
                                 PasswordHasher passwordHasher,
                                 BreachCheckService breachCheckService,
                                 EmailService emailService) {
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.passwordHasher = passwordHasher;
        this.breachCheckService = breachCheckService;
        this.emailService = emailService;
    }

    /**
     * Issues a password-reset token and fires the email asynchronously AFTER commit.
     * Anti-enumeration: silently returns for unknown / disabled users; SMTP failure
     * does not roll back the token row.
     *
     * @param email        the email address submitted by the user
     * @param baseResetUrl the base URL for the reset link (e.g. "https://app/reset-password")
     */
    public void requestReset(String email, String baseResetUrl) {
        Optional<SecBretUser> maybeUser = userRepository.findByEmail(email);
        if (maybeUser.isEmpty()) {
            // Anti-enumeration: unknown email → same silent return as a known one.
            log.debug("Password reset requested for unknown email (anti-enumeration, not logging address)");
            return;
        }
        SecBretUser user = maybeUser.get();
        if (!user.isEnabled()) {
            log.debug("Password reset for disabled account {} — suppressed (anti-enumeration)", user.getId());
            return;
        }

        // Generate token, persist hash, then fire email after commit.
        String plaintext = generateToken();
        String hash = sha256Hex(plaintext);

        persistTokenAndFireEmail(user, hash, plaintext, baseResetUrl);
    }

    /**
     * Persists the token in a transaction, then fires the email AFTER the transaction
     * commits (fire-and-forget post-commit pattern to avoid PENDING-forever and
     * SMTP-failure-rolls-back-token traps).
     */
    @Transactional
    public void persistTokenAndFireEmail(SecBretUser user, String tokenHash,
                                          String plaintextToken, String baseResetUrl) {
        PasswordResetToken token = new PasswordResetToken();
        token.setUser(user);
        token.setTokenHash(tokenHash);
        token.setExpiresAt(LocalDateTime.now().plusHours(1));
        tokenRepository.persist(token);
        // Transaction commits here; email fires after.
        String resetUrl = baseResetUrl + "?token=" + plaintextToken;
        emailService.sendPasswordResetAsync(user.getEmail(), resetUrl);
    }

    /**
     * Validates and consumes a reset token, then updates the password.
     *
     * @param plaintextToken the token from the URL parameter
     * @param newPassword    the new plaintext password
     * @throws ValidationException if the token is invalid, expired, or already used,
     *                             or if the new password fails policy (HIBP).
     */
    @Transactional
    public void consumeReset(String plaintextToken, String newPassword) {
        String hash = sha256Hex(plaintextToken);
        PasswordResetToken token = tokenRepository.findValidByHash(hash)
                .orElseThrow(() -> new ValidationException(
                        "This reset link is invalid, expired, or has already been used."));

        // HIBP check on new password (fail-open: timeout → allow)
        if (breachCheckService.isBreached(newPassword)) {
            throw new ValidationException(
                    "This password has appeared in a known data breach. Please choose a different password.");
        }

        SecBretUser user = token.getUser();

        // Invalidate ALL outstanding tokens (single-use + "all invalidated on success")
        tokenRepository.invalidateAllForUser(user.getId());

        // Update password hash
        user.setPasswordHash(passwordHasher.hash(newPassword));
        userRepository.merge(user);
        log.info("Password reset completed for userId={}", user.getId());
    }

    // ---------------------------------------------------------------- helpers

    private static String generateToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static String sha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(64);
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
