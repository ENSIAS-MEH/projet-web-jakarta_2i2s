package com.secbret.service;

import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * SessionTracker register → invalidateByUserId round-trip (Part II §15.5):
 * the mechanism behind DELETE /auth/me "all sessions invalidated".
 */
@ExtendWith(MockitoExtension.class)
class SessionTrackerTest {

    private final SessionTracker tracker = new SessionTracker();

    @Test
    @DisplayName("register + invalidateByUserId invalidates every registered session for that user")
    void registerThenInvalidate_invalidatesAllUserSessions() {
        UUID userId = UUID.randomUUID();
        HttpSession s1 = mock(HttpSession.class);
        HttpSession s2 = mock(HttpSession.class);

        tracker.register(userId, s1);
        tracker.register(userId, s2);

        tracker.invalidateByUserId(userId);

        verify(s1).invalidate();
        verify(s2).invalidate();
    }

    @Test
    @DisplayName("sessions of OTHER users are untouched")
    void invalidate_leavesOtherUsersAlone() {
        UUID victim = UUID.randomUUID();
        UUID bystander = UUID.randomUUID();
        HttpSession victimSession = mock(HttpSession.class);
        HttpSession bystanderSession = mock(HttpSession.class);

        tracker.register(victim, victimSession);
        tracker.register(bystander, bystanderSession);

        tracker.invalidateByUserId(victim);

        verify(victimSession).invalidate();
        verify(bystanderSession, never()).invalidate();
    }

    @Test
    @DisplayName("already-invalidated session (IllegalStateException) does not abort the sweep")
    void invalidate_alreadyDeadSession_doesNotThrow() {
        UUID userId = UUID.randomUUID();
        HttpSession dead = mock(HttpSession.class);
        HttpSession alive = mock(HttpSession.class);
        doThrow(new IllegalStateException("already invalidated")).when(dead).invalidate();

        tracker.register(userId, dead);
        tracker.register(userId, alive);

        assertThatCode(() -> tracker.invalidateByUserId(userId)).doesNotThrowAnyException();
        verify(alive).invalidate();
    }

    @Test
    @DisplayName("sessionDestroyed removes the session: no double-invalidate on later sweep")
    void sessionDestroyed_removesFromTracking() {
        UUID userId = UUID.randomUUID();
        HttpSession session = mock(HttpSession.class);
        tracker.register(userId, session);

        tracker.sessionDestroyed(new HttpSessionEvent(session));
        tracker.invalidateByUserId(userId);

        verify(session, never()).invalidate();
    }

    @Test
    @DisplayName("invalidateByUserId for an unknown user is a safe no-op")
    void invalidate_unknownUser_noOp() {
        assertThatCode(() -> tracker.invalidateByUserId(UUID.randomUUID()))
                .doesNotThrowAnyException();
    }
}
