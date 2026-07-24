package com.secbret.service;

import com.secbret.exception.ConflictException;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.enums.UserRole;
import com.secbret.repository.UserRepository;
import com.secbret.security.PasswordHasher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    UserRepository userRepository;

    private UserService userService;
    private final PasswordHasher hasher = new PasswordHasher(4); // low cost = fast tests

    @BeforeEach
    void setUp() {
        userService = new UserService(userRepository, hasher);
    }

    @Test
    @DisplayName("register hashes password, assigns REPORTER, and persists")
    void register_happyPath_persistsReporterWithHashedPassword() {
        when(userRepository.findByUsername("alice")).thenReturn(Optional.empty());
        when(userRepository.findByEmail("alice@example.com")).thenReturn(Optional.empty());
        when(userRepository.persist(any())).thenAnswer(inv -> inv.getArgument(0));

        userService.register("alice", "alice@example.com", "a-good-password-1");

        ArgumentCaptor<SecBretUser> captor = ArgumentCaptor.forClass(SecBretUser.class);
        verify(userRepository).persist(captor.capture());
        SecBretUser saved = captor.getValue();

        assertThat(saved.getUsername()).isEqualTo("alice");
        assertThat(saved.getEmail()).isEqualTo("alice@example.com");
        assertThat(saved.getRole()).isEqualTo(UserRole.REPORTER);
        assertThat(saved.isEnabled()).isTrue();
        assertThat(saved.getPasswordHash()).isNotEqualTo("a-good-password-1");
        assertThat(hasher.verify("a-good-password-1", saved.getPasswordHash())).isTrue();
    }

    @Test
    @DisplayName("register rejects a duplicate username with ConflictException")
    void register_duplicateUsername_throwsConflict() {
        when(userRepository.findByUsername("bob")).thenReturn(Optional.of(new SecBretUser()));

        assertThatThrownBy(() -> userService.register("bob", "bob@example.com", "some-password-12"))
                .isInstanceOf(ConflictException.class)
                .hasMessageContaining("Username");

        verify(userRepository, never()).persist(any());
    }

    @Test
    @DisplayName("register rejects a duplicate email with ConflictException")
    void register_duplicateEmail_throwsConflict() {
        when(userRepository.findByUsername("carol")).thenReturn(Optional.empty());
        when(userRepository.findByEmail("carol@example.com")).thenReturn(Optional.of(new SecBretUser()));

        assertThatThrownBy(() -> userService.register("carol", "carol@example.com", "some-password-12"))
                .isInstanceOf(ConflictException.class)
                .hasMessageContaining("Email");

        verify(userRepository, never()).persist(any());
    }

    @Test
    @DisplayName("seedAdminIfEmpty creates one ADMIN when table is empty and env set")
    void seedAdmin_emptyTable_createsAdmin() {
        when(userRepository.count()).thenReturn(0L);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.empty());
        when(userRepository.findByEmail("admin@secbret.internal")).thenReturn(Optional.empty());
        when(userRepository.persist(any())).thenAnswer(inv -> inv.getArgument(0));

        userService.seedAdminIfEmpty("admin", "admin@secbret.internal", "localdev-admin-password");

        ArgumentCaptor<SecBretUser> captor = ArgumentCaptor.forClass(SecBretUser.class);
        verify(userRepository).persist(captor.capture());
        assertThat(captor.getValue().getRole()).isEqualTo(UserRole.ADMIN);
        assertThat(hasher.verify("localdev-admin-password", captor.getValue().getPasswordHash())).isTrue();
    }

    @Test
    @DisplayName("seedAdminIfEmpty is a no-op (idempotent) when the table is not empty")
    void seedAdmin_nonEmptyTable_isNoOp() {
        when(userRepository.count()).thenReturn(1L);

        userService.seedAdminIfEmpty("admin", "admin@secbret.internal", "localdev-admin-password");

        verify(userRepository, never()).persist(any());
    }

    @Test
    @DisplayName("seedAdminIfEmpty skips (never touches DB) when env vars are missing")
    void seedAdmin_missingEnv_skipsWithoutDbAccess() {
        userService.seedAdminIfEmpty(null, "admin@secbret.internal", "localdev-admin-password");

        verify(userRepository, never()).count();
        verify(userRepository, never()).persist(any());
    }
}
