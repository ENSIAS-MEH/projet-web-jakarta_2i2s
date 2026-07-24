package com.secbret.controller;

import com.secbret.exception.WrongPasswordException;
import com.secbret.model.dto.GdprDeleteRequest;
import com.secbret.model.entity.SecBretUser;
import com.secbret.repository.UserRepository;
import com.secbret.service.AdminUserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.Principal;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * DELETE /auth/me must leave the caller's HTTP session dead (spec step 4:
 * "Invalidate all sessions for this user"). The resource kills the calling
 * session directly as belt-and-braces on top of SessionTracker.
 */
@ExtendWith(MockitoExtension.class)
class AuthResourceSessionInvalidationTest {

    @Mock AdminUserService adminUserService;
    @Mock UserRepository userRepository;
    @Mock SecurityContext securityContext;
    @Mock HttpServletRequest httpRequest;
    @Mock HttpSession session;
    @Mock Principal principal;

    private AuthResource resource;
    private SecBretUser caller;

    @BeforeEach
    void setUp() {
        resource = new AuthResource();
        resource.adminUserService = adminUserService;
        resource.userRepository = userRepository;
        resource.securityContext = securityContext;
        resource.httpRequest = httpRequest;

        caller = new SecBretUser();
        caller.setUsername("victim");
        when(securityContext.getUserPrincipal()).thenReturn(principal);
        when(principal.getName()).thenReturn("victim");
        when(userRepository.findByUsername("victim")).thenReturn(Optional.of(caller));
    }

    @Test
    @DisplayName("successful delete invalidates the caller's session and returns 204")
    void deleteAccount_success_invalidatesCallerSession() {
        when(httpRequest.getSession(false)).thenReturn(session);

        Response response = resource.deleteAccount(req("correct-pw"));

        assertThat(response.getStatus()).isEqualTo(204);
        verify(session).invalidate();
    }

    @Test
    @DisplayName("session already invalidated by SessionTracker: IllegalStateException swallowed, still 204")
    void deleteAccount_sessionAlreadyDead_still204() {
        when(httpRequest.getSession(false)).thenReturn(session);
        doThrow(new IllegalStateException("already invalidated")).when(session).invalidate();

        Response response = resource.deleteAccount(req("correct-pw"));

        assertThat(response.getStatus()).isEqualTo(204);
    }

    @Test
    @DisplayName("no live session: delete still succeeds with 204")
    void deleteAccount_noSession_still204() {
        when(httpRequest.getSession(false)).thenReturn(null);

        Response response = resource.deleteAccount(req("correct-pw"));

        assertThat(response.getStatus()).isEqualTo(204);
    }

    @Test
    @DisplayName("wrong password (422): the caller's session is NOT invalidated")
    void deleteAccount_wrongPassword_sessionSurvives() {
        doThrow(new WrongPasswordException("Current password is incorrect."))
                .when(adminUserService).deleteAccount(any(), anyString());

        assertThatThrownBy(() -> resource.deleteAccount(req("wrong-pw")))
                .isInstanceOf(WrongPasswordException.class);

        verify(session, never()).invalidate();
    }

    private static GdprDeleteRequest req(String pw) {
        GdprDeleteRequest r = new GdprDeleteRequest();
        r.setCurrentPassword(pw);
        return r;
    }
}
