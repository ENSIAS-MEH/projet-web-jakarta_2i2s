package com.secbret.service;

import com.secbret.email.EmailService;
import com.secbret.exception.ValidationException;
import com.secbret.model.entity.PasswordResetToken;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.enums.UserRole;
import com.secbret.repository.PasswordResetTokenRepository;
import com.secbret.repository.UserRepository;
import com.secbret.security.BreachCheckService;
import com.secbret.security.PasswordHasher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PasswordResetServiceTest {

    @Mock UserRepository userRepository;
    @Mock PasswordResetTokenRepository tokenRepository;
    @Mock BreachCheckService breachCheckService;
    @Mock EmailService emailService;

    private PasswordResetService service;
    private final PasswordHasher hasher = new PasswordHasher(4);

    @BeforeEach
    void setUp() {
        service = new PasswordResetService(userRepository, tokenRepository, hasher,
                breachCheckService, emailService);
    }

    private SecBretUser enabledUser(String email) {
        SecBretUser u = new SecBretUser();
        u.setUsername("alice");
        u.setEmail(email);
        u.setPasswordHash(hasher.hash("oldpassword123"));
        u.setRole(UserRole.REPORTER);
        u.setEnabled(true);
        return u;
    }

    // ---------------------------------------------------------------- requestReset

    @Test
    @DisplayName("unknown email → no token persisted, no email sent (anti-enumeration)")
    void requestReset_unknownEmail_noop() {
        when(userRepository.findByEmail("ghost@example.com")).thenReturn(Optional.empty());

        service.requestReset("ghost@example.com", "https://app/reset-password");

        verify(tokenRepository, never()).persist(any());
        verify(emailService, never()).sendPasswordResetAsync(anyString(), anyString());
    }

    @Test
    @DisplayName("disabled account → no token persisted (anti-enumeration)")
    void requestReset_disabledAccount_noop() {
        SecBretUser u = enabledUser("alice@example.com");
        u.setEnabled(false);
        when(userRepository.findByEmail("alice@example.com")).thenReturn(Optional.of(u));

        service.requestReset("alice@example.com", "https://app/reset-password");

        verify(tokenRepository, never()).persist(any());
        verify(emailService, never()).sendPasswordResetAsync(anyString(), anyString());
    }

    @Test
    @DisplayName("valid email → token persisted with 1h TTL, email fired asynchronously")
    void requestReset_validEmail_tokenPersistedEmailFired() {
        SecBretUser u = enabledUser("alice@example.com");
        when(tokenRepository.persist(any())).thenAnswer(inv -> inv.getArgument(0));

        service.persistTokenAndFireEmail(u, "somehash", "plaintexttoken", "https://app/reset-password");

        ArgumentCaptor<PasswordResetToken> captor = ArgumentCaptor.forClass(PasswordResetToken.class);
        verify(tokenRepository).persist(captor.capture());
        PasswordResetToken token = captor.getValue();
        assertThat(token.getTokenHash()).isEqualTo("somehash");
        assertThat(token.getUser()).isSameAs(u);
        assertThat(token.getExpiresAt()).isAfter(LocalDateTime.now());
        assertThat(token.getExpiresAt()).isBefore(LocalDateTime.now().plusHours(2));

        verify(emailService).sendPasswordResetAsync(eq("alice@example.com"), anyString());
    }

    // ---------------------------------------------------------------- consumeReset

    @Test
    @DisplayName("invalid / expired token → ValidationException")
    void consumeReset_invalidToken_throws() {
        when(tokenRepository.findValidByHash(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.consumeReset("badtoken", "newpassword123valid"))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("invalid");
    }

    @Test
    @DisplayName("breached new password → ValidationException, token NOT consumed")
    void consumeReset_breachedPassword_throws() {
        SecBretUser u = enabledUser("alice@example.com");
        PasswordResetToken tok = tokenWithUser(u);
        when(tokenRepository.findValidByHash(anyString())).thenReturn(Optional.of(tok));
        when(breachCheckService.isBreached("breached-password-1")).thenReturn(true);

        assertThatThrownBy(() -> service.consumeReset("anytoken", "breached-password-1"))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("breach");

        verify(tokenRepository, never()).invalidateAllForUser(any());
        verify(userRepository, never()).merge(any());
    }

    @Test
    @DisplayName("valid token + clean password → password changed, all tokens invalidated")
    void consumeReset_validToken_passwordChangedAllTokensInvalidated() {
        SecBretUser u = enabledUser("alice@example.com");
        PasswordResetToken tok = tokenWithUser(u);
        when(tokenRepository.findValidByHash(anyString())).thenReturn(Optional.of(tok));
        when(breachCheckService.isBreached("newcleanpassword123")).thenReturn(false);
        when(userRepository.merge(any())).thenAnswer(inv -> inv.getArgument(0));

        service.consumeReset("plaintoken", "newcleanpassword123");

        // All tokens invalidated
        verify(tokenRepository).invalidateAllForUser(u.getId());
        // Password hash updated
        ArgumentCaptor<SecBretUser> captor = ArgumentCaptor.forClass(SecBretUser.class);
        verify(userRepository).merge(captor.capture());
        String newHash = captor.getValue().getPasswordHash();
        assertThat(hasher.verify("newcleanpassword123", newHash)).isTrue();
    }

    @Test
    @DisplayName("sha256Hex is deterministic and hex-encoded")
    void sha256Hex_deterministic() {
        String h1 = PasswordResetService.sha256Hex("hello");
        String h2 = PasswordResetService.sha256Hex("hello");
        assertThat(h1).isEqualTo(h2);
        assertThat(h1).hasSize(64).matches("[0-9a-f]+");
        assertThat(h1).isNotEqualTo(PasswordResetService.sha256Hex("world"));
    }

    // ---------------------------------------------------------------- helpers

    private PasswordResetToken tokenWithUser(SecBretUser user) {
        PasswordResetToken t = new PasswordResetToken();
        t.setUser(user);
        t.setTokenHash("dummyhash");
        t.setExpiresAt(LocalDateTime.now().plusHours(1));
        return t;
    }
}
