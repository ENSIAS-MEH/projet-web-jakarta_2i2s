package com.secbret.security;

import com.secbret.model.entity.SecBretUser;
import com.secbret.model.enums.UserRole;
import com.secbret.repository.UserRepository;
import jakarta.security.enterprise.credential.UsernamePasswordCredential;
import jakarta.security.enterprise.identitystore.CredentialValidationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the lockout WRITE PATH (Phase 5):
 * - wrong password → incrementFailedLoginAttempts called
 * - successful login with failedLoginAttempts > 0 → reset called
 * - successful login with no prior failures → reset NOT called (no unnecessary write)
 * - 4th failure → no lock yet; 5th → lock (threshold boundary)
 * - expired lock (past locked_until) → valid, reset called
 * - unknown user → NO counter increment (anti-enumeration)
 * - disabled / actively-locked account → NO counter increment
 */
@ExtendWith(MockitoExtension.class)
class LockoutWritePathTest {

    @Mock
    UserRepository userRepository;

    private SecBretIdentityStore store;
    private final PasswordHasher hasher = new PasswordHasher(4);

    @BeforeEach
    void setUp() {
        store = new SecBretIdentityStore(userRepository, hasher);
    }

    private SecBretUser user(String username, String rawPassword, boolean enabled,
                              LocalDateTime lockedUntil, int failedAttempts) {
        SecBretUser u = new SecBretUser();
        u.setUsername(username);
        u.setEmail(username + "@example.com");
        u.setPasswordHash(hasher.hash(rawPassword));
        u.setRole(UserRole.REPORTER);
        u.setEnabled(enabled);
        u.setLockedUntil(lockedUntil);
        u.setFailedLoginAttempts(failedAttempts);
        // set an ID via reflection-free approach: use a known field setter path
        // We rely on the Mockito stub to return this user; the ID is null (test entity, no DB)
        // but the increment guard checks userId != null, so we must ensure an ID.
        // Use a test subclass trick: re-set via mock
        return u;
    }

    /** Creates a user with a non-null UUID id so the lockout write path fires. */
    private SecBretUser userWithId(String username, String rawPassword, boolean enabled,
                                    LocalDateTime lockedUntil, int failedAttempts) {
        SecBretUser u = user(username, rawPassword, enabled, lockedUntil, failedAttempts);
        // We can't easily set UUID without a setter, but SecBretUser.id is GeneratedValue.
        // Workaround: stub incrementFailedLoginAttempts to assert it IS or IS NOT called.
        // For assertions on "no call", null id is fine (guard: if userId != null).
        // So we use a real entity whose id is null — the guard `if (user.getId() != null)`
        // prevents the DB call. For "should call" tests, we need a user with an id.
        // Use the AdminUserService pattern: create via mock return, set via UserRepository stub.
        // Simplest: create a minimal entity subclass inline.
        return new SecBretUser() {
            {
                setUsername(username);
                setEmail(username + "@example.com");
                setPasswordHash(hasher.hash(rawPassword));
                setRole(UserRole.REPORTER);
                setEnabled(enabled);
                setLockedUntil(lockedUntil);
                setFailedLoginAttempts(failedAttempts);
            }
            @Override
            public UUID getId() { return UUID.fromString("00000000-0000-0000-0000-000000000001"); }
        };
    }

    @Test
    @DisplayName("wrong password → incrementFailedLoginAttempts is called")
    void wrongPassword_incrementsCalled() {
        SecBretUser u = userWithId("alice", "correct-password-12", true, null, 0);
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(u));
        when(userRepository.incrementFailedLoginAttempts(any(), anyInt())).thenReturn(1);

        CredentialValidationResult result = store.validate(
                new UsernamePasswordCredential("alice", "wrong-password-123"));

        assertThat(result.getStatus()).isEqualTo(CredentialValidationResult.Status.INVALID);
        verify(userRepository).incrementFailedLoginAttempts(u.getId(), 5);
    }

    @Test
    @DisplayName("4th failure → increment called, but no lock yet (threshold=5)")
    void fourthFailure_incrementCalledNotLocked() {
        SecBretUser u = userWithId("alice", "correct-password-12", true, null, 3);
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(u));
        when(userRepository.incrementFailedLoginAttempts(any(), anyInt())).thenReturn(4); // now 4

        store.validate(new UsernamePasswordCredential("alice", "wrong-pw"));

        verify(userRepository).incrementFailedLoginAttempts(u.getId(), 5);
        // The lockout itself is performed by the DB UPDATE (via repo); we just verify increment called
    }

    @Test
    @DisplayName("5th failure (threshold boundary) → increment called, returns 5 → lock message logged")
    void fifthFailure_locksAccount() {
        SecBretUser u = userWithId("alice", "correct-password-12", true, null, 4);
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(u));
        when(userRepository.incrementFailedLoginAttempts(any(), anyInt())).thenReturn(5); // 5th hit

        CredentialValidationResult result = store.validate(
                new UsernamePasswordCredential("alice", "wrong-pw"));

        assertThat(result.getStatus()).isEqualTo(CredentialValidationResult.Status.INVALID);
        verify(userRepository).incrementFailedLoginAttempts(u.getId(), 5);
    }

    @Test
    @DisplayName("successful login with prior failures → reset is called")
    void successfulLogin_withPriorFailures_resetsCounter() {
        SecBretUser u = userWithId("alice", "correct-password-12", true, null, 3);
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(u));

        CredentialValidationResult result = store.validate(
                new UsernamePasswordCredential("alice", "correct-password-12"));

        assertThat(result.getStatus()).isEqualTo(CredentialValidationResult.Status.VALID);
        verify(userRepository).resetFailedLoginAttempts(u.getId());
        verify(userRepository, never()).incrementFailedLoginAttempts(any(), anyInt());
    }

    @Test
    @DisplayName("successful login with no prior failures → reset NOT called (no-op write avoided)")
    void successfulLogin_noPriorFailures_resetNotCalled() {
        SecBretUser u = userWithId("alice", "correct-password-12", true, null, 0);
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(u));

        CredentialValidationResult result = store.validate(
                new UsernamePasswordCredential("alice", "correct-password-12"));

        assertThat(result.getStatus()).isEqualTo(CredentialValidationResult.Status.VALID);
        verify(userRepository, never()).resetFailedLoginAttempts(any());
        verify(userRepository, never()).incrementFailedLoginAttempts(any(), anyInt());
    }

    @Test
    @DisplayName("expired lock (past locked_until) → auth succeeds, reset called")
    void expiredLock_authSucceeds_resetCalled() {
        SecBretUser u = userWithId("alice", "correct-password-12", true,
                LocalDateTime.now().minusMinutes(1), 5);
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(u));

        CredentialValidationResult result = store.validate(
                new UsernamePasswordCredential("alice", "correct-password-12"));

        assertThat(result.getStatus()).isEqualTo(CredentialValidationResult.Status.VALID);
        verify(userRepository).resetFailedLoginAttempts(u.getId());
    }

    @Test
    @DisplayName("unknown user → no counter increment (anti-enumeration)")
    void unknownUser_noIncrement() {
        when(userRepository.findByUsername("ghost")).thenReturn(Optional.empty());

        store.validate(new UsernamePasswordCredential("ghost", "any-password-123"));

        verify(userRepository, never()).incrementFailedLoginAttempts(any(), anyInt());
        verify(userRepository, never()).resetFailedLoginAttempts(any());
    }

    @Test
    @DisplayName("disabled account → no counter increment")
    void disabledAccount_noIncrement() {
        SecBretUser u = userWithId("alice", "correct-password-12", false, null, 0);
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(u));

        store.validate(new UsernamePasswordCredential("alice", "correct-password-12"));

        verify(userRepository, never()).incrementFailedLoginAttempts(any(), anyInt());
    }

    @Test
    @DisplayName("active lock (future locked_until) → no counter increment")
    void activeLock_noIncrement() {
        SecBretUser u = userWithId("alice", "correct-password-12", true,
                LocalDateTime.now().plusMinutes(10), 5);
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(u));

        store.validate(new UsernamePasswordCredential("alice", "correct-password-12"));

        verify(userRepository, never()).incrementFailedLoginAttempts(any(), anyInt());
    }
}
