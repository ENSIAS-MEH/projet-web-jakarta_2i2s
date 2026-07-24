package com.secbret.service;

import com.secbret.exception.ConflictException;
import com.secbret.exception.ResourceNotFoundException;
import com.secbret.exception.ValidationException;
import com.secbret.exception.WrongPasswordException;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.enums.UserRole;
import com.secbret.repository.UserRepository;
import com.secbret.security.PasswordHasher;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.UUID;

/**
 * Admin user management operations (Part III §6) and GDPR hard-delete (Part III §1 DELETE /auth/me).
 *
 * <p>Mutation methods follow the *InTx pattern established in the codebase:
 * each transactional mutation is delegated to the repository's own {@code @Transactional}
 * method to avoid Weld self-invocation bypass issues.
 */
@ApplicationScoped
public class AdminUserService {

    private static final Logger log = LoggerFactory.getLogger(AdminUserService.class);

    @Inject
    UserRepository userRepository;

    @Inject
    PasswordHasher passwordHasher;

    @Inject
    AuditLogService auditLogService;

    @Inject
    SessionTracker sessionTracker;

    protected AdminUserService() {}

    @Inject
    public AdminUserService(UserRepository userRepository, PasswordHasher passwordHasher,
                            AuditLogService auditLogService, SessionTracker sessionTracker) {
        this.userRepository = userRepository;
        this.passwordHasher = passwordHasher;
        this.auditLogService = auditLogService;
        this.sessionTracker = sessionTracker;
    }

    // ── List ──────────────────────────────────────────────────────────────────

    public List<SecBretUser> listUsers(UserRole role, Boolean enabled, int page, int size) {
        int offset = (Math.max(page, 1) - 1) * size;
        return userRepository.findPage(role, enabled, offset, size);
    }

    public long countUsers(UserRole role, Boolean enabled) {
        return userRepository.countFiltered(role, enabled);
    }

    // ── Get single ────────────────────────────────────────────────────────────

    public SecBretUser getUser(UUID userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("user", userId));
    }

    // ── Change role ───────────────────────────────────────────────────────────

    @Transactional
    public SecBretUser changeRole(UUID userId, UserRole newRole, SecBretUser actor) {
        if (newRole == null) {
            throw new ValidationException("role must not be null");
        }
        SecBretUser target = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("user", userId));

        target.setRole(newRole);
        SecBretUser saved = userRepository.merge(target);
        sessionTracker.invalidateByUserId(userId); // force re-auth so the new role takes effect immediately

        auditLogService.log(actor, "ADMIN_USER_ROLE_CHANGED", "secbret_user", userId,
                "{\"newRole\":\"" + newRole + "\"}");
        log.info("Admin {} changed user {} role to {}", actor.getUsername(), userId, newRole);
        return saved;
    }

    // ── Change status (enable/disable) ────────────────────────────────────────

    @Transactional
    public SecBretUser changeStatus(UUID userId, boolean enabled, SecBretUser actor) {
        // Self-disable guard: ADMIN may not disable their own account (spec §6, 409)
        if (!enabled && userId.equals(actor.getId())) {
            throw new ConflictException("Admins cannot disable their own account.");
        }

        SecBretUser target = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("user", userId));

        target.setEnabled(enabled);
        SecBretUser saved = userRepository.merge(target);

        auditLogService.log(actor, enabled ? "ADMIN_USER_ENABLED" : "ADMIN_USER_DISABLED",
                "secbret_user", userId, "{\"enabled\":" + enabled + "}");
        log.info("Admin {} set user {} enabled={}", actor.getUsername(), userId, enabled);
        return saved;
    }

    // ── Unlock ────────────────────────────────────────────────────────────────

    @Transactional
    public SecBretUser unlockUser(UUID userId, SecBretUser actor) {
        SecBretUser target = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("user", userId));

        target.setFailedLoginAttempts(0);
        target.setLockedUntil(null);
        SecBretUser saved = userRepository.merge(target);

        auditLogService.log(actor, "ADMIN_USER_UNLOCKED", "secbret_user", userId, null);
        log.info("Admin {} unlocked user {}", actor.getUsername(), userId);
        return saved;
    }

    // ── GDPR hard-delete ──────────────────────────────────────────────────────

    /**
     * Hard-delete the caller's own account (DELETE /auth/me).
     *
     * <ol>
     *   <li>Verify {@code currentPassword} against the stored BCrypt hash.
     *       Wrong password → {@link WrongPasswordException} (422).
     *       Does NOT increment {@code failed_login_attempts} (spec note below DELETE /auth/me).</li>
     *   <li>Invalidate all sessions for this user via {@link SessionTracker}.</li>
     *   <li>Hard-delete the {@code secbret_user} row. The V20 BEFORE DELETE trigger
     *       {@code tombstone_audit_before_delete} writes {@code actor_username = 'deleted_{uuid}'}
     *       on all {@code audit_log} rows before the ON DELETE SET NULL cascade fires.
     *       Application code must NOT add a redundant UPDATE (spec C3).</li>
     * </ol>
     */
    @Transactional
    public void deleteAccount(UUID userId, String currentPassword) {
        SecBretUser user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("user", userId));

        // Step 1: Validate password — do NOT increment failed_login_attempts on failure.
        if (!passwordHasher.verify(currentPassword, user.getPasswordHash())) {
            throw new WrongPasswordException("Current password is incorrect.");
        }

        // Step 2: Invalidate all sessions before the DB row disappears.
        sessionTracker.invalidateByUserId(userId);

        // Step 3: Hard-delete. V20 trigger tombstones audit_log.actor_username automatically.
        // Application code must NOT add a tombstone UPDATE here (spec C3 / HANDOFF trap).
        userRepository.delete(user);

        log.info("GDPR hard-delete: user {} deleted; V20 trigger tombstones audit_log rows", userId);
    }
}
