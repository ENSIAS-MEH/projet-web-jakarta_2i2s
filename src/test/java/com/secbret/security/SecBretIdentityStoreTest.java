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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SecBretIdentityStoreTest {

    @Mock
    UserRepository userRepository;

    private SecBretIdentityStore store;
    private final PasswordHasher hasher = new PasswordHasher(4);

    @BeforeEach
    void setUp() {
        store = new SecBretIdentityStore(userRepository, hasher);
    }

    private SecBretUser user(String username, String rawPassword, UserRole role,
                             boolean enabled, LocalDateTime lockedUntil) {
        SecBretUser u = new SecBretUser();
        u.setUsername(username);
        u.setEmail(username + "@example.com");
        u.setPasswordHash(hasher.hash(rawPassword));
        u.setRole(role);
        u.setEnabled(enabled);
        u.setLockedUntil(lockedUntil);
        return u;
    }

    @Test
    @DisplayName("valid credentials → VALID with caller name and role group")
    void validate_validCredentials_returnsValidWithRole() {
        when(userRepository.findByUsername("alice"))
                .thenReturn(Optional.of(user("alice", "good-password-1", UserRole.ANALYST, true, null)));

        CredentialValidationResult result = store.validate(
                new UsernamePasswordCredential("alice", "good-password-1"));

        assertThat(result.getStatus()).isEqualTo(CredentialValidationResult.Status.VALID);
        assertThat(result.getCallerPrincipal().getName()).isEqualTo("alice");
        assertThat(result.getCallerGroups()).containsExactly("ANALYST");
    }

    @Test
    @DisplayName("wrong password → INVALID")
    void validate_wrongPassword_returnsInvalid() {
        when(userRepository.findByUsername("alice"))
                .thenReturn(Optional.of(user("alice", "good-password-1", UserRole.REPORTER, true, null)));

        CredentialValidationResult result = store.validate(
                new UsernamePasswordCredential("alice", "wrong-password-1"));

        assertThat(result.getStatus()).isEqualTo(CredentialValidationResult.Status.INVALID);
    }

    @Test
    @DisplayName("unknown username → INVALID (no enumeration)")
    void validate_unknownUser_returnsInvalid() {
        when(userRepository.findByUsername("ghost")).thenReturn(Optional.empty());

        CredentialValidationResult result = store.validate(
                new UsernamePasswordCredential("ghost", "any-password-123"));

        assertThat(result.getStatus()).isEqualTo(CredentialValidationResult.Status.INVALID);
    }

    @Test
    @DisplayName("disabled account → INVALID even with correct password")
    void validate_disabledAccount_returnsInvalid() {
        when(userRepository.findByUsername("alice"))
                .thenReturn(Optional.of(user("alice", "good-password-1", UserRole.REPORTER, false, null)));

        CredentialValidationResult result = store.validate(
                new UsernamePasswordCredential("alice", "good-password-1"));

        assertThat(result.getStatus()).isEqualTo(CredentialValidationResult.Status.INVALID);
    }

    @Test
    @DisplayName("account locked in the future → INVALID even with correct password")
    void validate_lockedAccount_returnsInvalid() {
        when(userRepository.findByUsername("alice"))
                .thenReturn(Optional.of(user("alice", "good-password-1", UserRole.REPORTER, true,
                        LocalDateTime.now().plusMinutes(10))));

        CredentialValidationResult result = store.validate(
                new UsernamePasswordCredential("alice", "good-password-1"));

        assertThat(result.getStatus()).isEqualTo(CredentialValidationResult.Status.INVALID);
    }

    @Test
    @DisplayName("expired lock (past locked_until) → VALID with correct password")
    void validate_expiredLock_returnsValid() {
        when(userRepository.findByUsername("alice"))
                .thenReturn(Optional.of(user("alice", "good-password-1", UserRole.REPORTER, true,
                        LocalDateTime.now().minusMinutes(1))));

        CredentialValidationResult result = store.validate(
                new UsernamePasswordCredential("alice", "good-password-1"));

        assertThat(result.getStatus()).isEqualTo(CredentialValidationResult.Status.VALID);
    }
}
