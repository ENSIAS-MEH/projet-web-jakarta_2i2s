package com.secbret.service;

import com.secbret.exception.ConflictException;
import com.secbret.exception.ValidationException;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.enums.UserRole;
import com.secbret.repository.UserRepository;
import com.secbret.security.BreachCheckService;
import com.secbret.security.PasswordHasher;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * User account operations (Part III §1, Part II §6).
 *
 * <p>Registration hashes the raw password with BCrypt (cost 12) via
 * {@link PasswordHasher}; plaintext is never persisted (spec §B). New public
 * registrations receive role {@link UserRole#REPORTER} (RBAC default, Part II §4).
 * Duplicate username/email is a {@link ConflictException} (409) — the web
 * controller catches it and re-renders the form with an error.
 *
 * <p>Admin bootstrap ({@code seedAdminIfEmpty}) is driven by {@link AdminSeeder}
 * at startup; it delegates to {@link #createUser} here so the hashing/persist path
 * is identical to normal registration.
 */
@ApplicationScoped
public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    @Inject
    UserRepository userRepository;

    @Inject
    PasswordHasher passwordHasher;

    @Inject
    BreachCheckService breachCheckService;

    public UserService() {
    }

    /** Test constructor (without HIBP check — existing tests). */
    public UserService(UserRepository userRepository, PasswordHasher passwordHasher) {
        this.userRepository = userRepository;
        this.passwordHasher = passwordHasher;
        this.breachCheckService = new BreachCheckService();
    }

    /** Test constructor with explicit breach check service. */
    public UserService(UserRepository userRepository, PasswordHasher passwordHasher,
                       BreachCheckService breachCheckService) {
        this.userRepository = userRepository;
        this.passwordHasher = passwordHasher;
        this.breachCheckService = breachCheckService;
    }

    /**
     * Registers a new public user with role {@link UserRole#REPORTER}.
     * Performs HIBP k-anonymity check (fail-open: breach check failure → allowed).
     *
     * @throws ConflictException   if the username or email is already taken.
     * @throws ValidationException if the password appears in a known breach dataset.
     */
    @Transactional
    public SecBretUser register(String username, String email, String rawPassword) {
        if (breachCheckService.isBreached(rawPassword)) {
            throw new ValidationException("This password has appeared in a known data breach. Please choose a different password.");
        }
        return createUser(username, email, rawPassword, UserRole.REPORTER);
    }

    /**
     * Creates a user with an explicit role. Enforces username/email uniqueness at
     * the application boundary (the DB unique constraints are the ultimate guard).
     *
     * @throws ConflictException if the username or email is already taken.
     */
    @Transactional
    public SecBretUser createUser(String username, String email, String rawPassword, UserRole role) {
        if (userRepository.findByUsername(username).isPresent()) {
            throw new ConflictException("Username is already taken.");
        }
        if (userRepository.findByEmail(email).isPresent()) {
            throw new ConflictException("Email is already registered.");
        }

        SecBretUser user = new SecBretUser();
        user.setUsername(username);
        user.setEmail(email);
        user.setPasswordHash(passwordHasher.hash(rawPassword));
        user.setRole(role);
        user.setEnabled(true);

        SecBretUser saved = userRepository.persist(user);
        log.info("Created user username={} role={}", username, role);
        return saved;
    }

    /**
     * First-run admin bootstrap (Part II §6). Idempotent: creates one ADMIN only
     * when {@code SEED_ADMIN_*} env vars are all set AND the user table is empty.
     * On any subsequent boot the count is non-zero and this is a no-op.
     *
     * <p>Reads env directly so it is self-contained and testable via the
     * three-arg overload below.
     */
    public void seedAdminIfEmpty() {
        seedAdminIfEmpty(
                System.getenv("SEED_ADMIN_USERNAME"),
                System.getenv("SEED_ADMIN_EMAIL"),
                System.getenv("SEED_ADMIN_PASSWORD"));
    }

    /**
     * Testable core of {@link #seedAdminIfEmpty()}.
     *
     * <p>Guard order matters: the env-var check comes first so that when the
     * variables are unset we never touch the DB; then {@code count() == 0} is the
     * idempotency guard (Part II §6: {@code SELECT COUNT(*) FROM secbret_user}).
     */
    @Transactional
    public void seedAdminIfEmpty(String username, String email, String rawPassword) {
        if (isBlank(username) || isBlank(email) || isBlank(rawPassword)) {
            log.warn("Admin seed skipped: SEED_ADMIN_* not fully configured.");
            return;
        }
        if (userRepository.count() != 0) {
            log.info("Admin seed skipped: secbret_user is not empty (idempotent).");
            return;
        }
        createUser(username, email, rawPassword, UserRole.ADMIN);
        log.info("Seeded first-run ADMIN account username={}", username);
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}
