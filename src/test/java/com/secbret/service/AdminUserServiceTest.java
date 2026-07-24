package com.secbret.service;

import com.secbret.exception.ConflictException;
import com.secbret.exception.ResourceNotFoundException;
import com.secbret.exception.WrongPasswordException;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.enums.UserRole;
import com.secbret.repository.UserRepository;
import com.secbret.security.PasswordHasher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for AdminUserService (Part III §6 + DELETE /auth/me).
 */
@ExtendWith(MockitoExtension.class)
class AdminUserServiceTest {

    @Mock UserRepository userRepository;
    @Mock AuditLogService auditLogService;
    @Mock SessionTracker sessionTracker;

    // Low-cost hasher for fast tests
    private final PasswordHasher passwordHasher = new PasswordHasher(4);

    private AdminUserService service;

    @BeforeEach
    void setUp() {
        service = new AdminUserService(userRepository, passwordHasher, auditLogService, sessionTracker);
    }

    // ── Role change ───────────────────────────────────────────────────────────

    @Nested
    @DisplayName("changeRole")
    class ChangeRole {

        @Test
        @DisplayName("changes role and writes audit log")
        void changeRole_happyPath() {
            SecBretUser actor = adminUser();
            SecBretUser target = reporterUser();
            when(userRepository.findById(target.getId())).thenReturn(Optional.of(target));
            when(userRepository.merge(any())).thenAnswer(inv -> inv.getArgument(0));

            SecBretUser result = service.changeRole(target.getId(), UserRole.ANALYST, actor);

            assertThat(result.getRole()).isEqualTo(UserRole.ANALYST);
            verify(auditLogService).log(actor, "ADMIN_USER_ROLE_CHANGED", "secbret_user",
                    target.getId(), "{\"newRole\":\"ANALYST\"}");
        }

        @Test
        @DisplayName("returns 404 when user not found")
        void changeRole_userNotFound_404() {
            UUID missing = UUID.randomUUID();
            when(userRepository.findById(missing)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.changeRole(missing, UserRole.ANALYST, adminUser()))
                    .isInstanceOf(ResourceNotFoundException.class);
        }
    }

    // ── Status change ─────────────────────────────────────────────────────────

    @Nested
    @DisplayName("changeStatus")
    class ChangeStatus {

        @Test
        @DisplayName("enables a disabled user and writes audit log")
        void changeStatus_enable_happyPath() {
            SecBretUser actor = adminUser();
            SecBretUser target = reporterUser();
            target.setEnabled(false);
            when(userRepository.findById(target.getId())).thenReturn(Optional.of(target));
            when(userRepository.merge(any())).thenAnswer(inv -> inv.getArgument(0));

            SecBretUser result = service.changeStatus(target.getId(), true, actor);

            assertThat(result.isEnabled()).isTrue();
            verify(auditLogService).log(actor, "ADMIN_USER_ENABLED", "secbret_user",
                    target.getId(), "{\"enabled\":true}");
        }

        @Test
        @DisplayName("disabling another user succeeds")
        void changeStatus_disableOther_happyPath() {
            SecBretUser actor = adminUser();
            SecBretUser target = reporterUser(); // different UUID
            when(userRepository.findById(target.getId())).thenReturn(Optional.of(target));
            when(userRepository.merge(any())).thenAnswer(inv -> inv.getArgument(0));

            SecBretUser result = service.changeStatus(target.getId(), false, actor);

            assertThat(result.isEnabled()).isFalse();
        }

        @Test
        @DisplayName("self-disable → 409 Conflict before DB lookup")
        void changeStatus_selfDisable_409() {
            SecBretUser actor = adminUser();

            // Must throw ConflictException without ever hitting the DB
            assertThatThrownBy(() -> service.changeStatus(actor.getId(), false, actor))
                    .isInstanceOf(ConflictException.class)
                    .hasMessageContaining("own account");

            verify(userRepository, never()).findById(any());
        }

        @Test
        @DisplayName("returns 404 when user not found")
        void changeStatus_userNotFound_404() {
            UUID missing = UUID.randomUUID();
            SecBretUser actor = adminUser();
            when(userRepository.findById(missing)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.changeStatus(missing, false, actor))
                    .isInstanceOf(ResourceNotFoundException.class);
        }
    }

    // ── Unlock ────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("unlockUser")
    class UnlockUser {

        @Test
        @DisplayName("resets failedLoginAttempts and lockedUntil, writes audit log")
        void unlock_happyPath() {
            SecBretUser actor = adminUser();
            SecBretUser target = reporterUser();
            target.setFailedLoginAttempts(5);
            target.setLockedUntil(java.time.LocalDateTime.now().plusMinutes(10));
            when(userRepository.findById(target.getId())).thenReturn(Optional.of(target));
            when(userRepository.merge(any())).thenAnswer(inv -> inv.getArgument(0));

            SecBretUser result = service.unlockUser(target.getId(), actor);

            assertThat(result.getFailedLoginAttempts()).isEqualTo(0);
            assertThat(result.getLockedUntil()).isNull();
            verify(auditLogService).log(actor, "ADMIN_USER_UNLOCKED", "secbret_user",
                    target.getId(), null);
        }

        @Test
        @DisplayName("returns 404 when user not found")
        void unlock_userNotFound_404() {
            UUID missing = UUID.randomUUID();
            SecBretUser actor = adminUser();
            when(userRepository.findById(missing)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.unlockUser(missing, actor))
                    .isInstanceOf(ResourceNotFoundException.class);
        }
    }

    // ── GDPR delete ───────────────────────────────────────────────────────────

    @Nested
    @DisplayName("deleteAccount (DELETE /auth/me)")
    class DeleteAccount {

        @Test
        @DisplayName("correct password: invalidates sessions, deletes user, no tombstone UPDATE")
        void deleteAccount_correctPassword_deletesUser() {
            String rawPw = "correct-password-42!";
            SecBretUser user = reporterUser();
            user.setPasswordHash(passwordHasher.hash(rawPw));
            when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));

            service.deleteAccount(user.getId(), rawPw);

            verify(sessionTracker).invalidateByUserId(user.getId());
            verify(userRepository).delete(user);
            // Ensure NO tombstone UPDATE is written by app code (trigger owns it)
            verify(auditLogService, never()).log(any(), any(), any(), any(), any());
        }

        @Test
        @DisplayName("wrong password → WrongPasswordException (422), NO lockout increment")
        void deleteAccount_wrongPassword_422_noLockoutIncrement() {
            SecBretUser user = reporterUser();
            user.setPasswordHash(passwordHasher.hash("the-real-password-99"));
            user.setFailedLoginAttempts(0);
            when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));

            assertThatThrownBy(() -> service.deleteAccount(user.getId(), "wrong-pw"))
                    .isInstanceOf(WrongPasswordException.class);

            // failed_login_attempts must NOT be incremented
            assertThat(user.getFailedLoginAttempts()).isEqualTo(0);
            // Sessions must NOT be invalidated (delete never reached)
            verify(sessionTracker, never()).invalidateByUserId(any());
            // User row must NOT be deleted
            verify(userRepository, never()).delete(any());
        }

        @Test
        @DisplayName("user not found → ResourceNotFoundException")
        void deleteAccount_userNotFound_404() {
            UUID missing = UUID.randomUUID();
            when(userRepository.findById(missing)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.deleteAccount(missing, "any-pw"))
                    .isInstanceOf(ResourceNotFoundException.class);

            verify(sessionTracker, never()).invalidateByUserId(any());
            verify(userRepository, never()).delete(any());
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private SecBretUser adminUser() {
        SecBretUser u = new SecBretUser();
        // Set a stable UUID via reflection to keep tests deterministic
        try {
            var f = SecBretUser.class.getDeclaredField("id");
            f.setAccessible(true);
            f.set(u, UUID.fromString("00000000-0000-0000-0000-000000000001"));
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
        u.setUsername("admin");
        u.setEmail("admin@test.example");
        u.setPasswordHash("$2a$04$placeholder");
        u.setRole(UserRole.ADMIN);
        u.setEnabled(true);
        return u;
    }

    private SecBretUser reporterUser() {
        SecBretUser u = new SecBretUser();
        try {
            var f = SecBretUser.class.getDeclaredField("id");
            f.setAccessible(true);
            f.set(u, UUID.fromString("00000000-0000-0000-0000-000000000002"));
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
        u.setUsername("reporter");
        u.setEmail("reporter@test.example");
        u.setPasswordHash("$2a$04$placeholder");
        u.setRole(UserRole.REPORTER);
        u.setEnabled(true);
        return u;
    }
}
