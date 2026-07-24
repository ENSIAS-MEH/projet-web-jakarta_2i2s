package com.secbret.service;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tracks active HTTP sessions per user for bulk invalidation (Part II §15.5).
 *
 * <p>Required by {@code DELETE /auth/me} (GDPR hard-delete): the spec mandates that
 * <em>all</em> active sessions for the deleted user are invalidated before the
 * {@code secbret_user} row is removed from the database.
 *
 * <p>Sessions are registered via the {@link HttpSessionListener} contract
 * ({@code @WebListener}). On {@code invalidateByUserId} the tracker iterates
 * the stored session references and calls {@code invalidate()} on those that
 * are still live.
 *
 * <p>Scope limitation: in-JVM only (single-instance Payara). A shared session
 * store (Redis / PostgreSQL) would be required before horizontal scaling
 * (Part II §15.5 Known Limitation, Gap #16).
 *
 * <p>Usage: call {@link #register(UUID, HttpSession)} from the post-login path
 * (after {@code request.changeSessionId()}) to associate the session with a user.
 *
 * ponytail: global ConcurrentHashMap — sufficient for single-JVM Payara v1.
 * Replace with Redis-backed store when horizontal scaling is needed (Gap #16).
 */
@ApplicationScoped
public class SessionTracker implements HttpSessionListener {
    // NOT @WebListener: Payara rejects a servlet listener that also carries a CDI
    // scope ("annotated with an invalid scope"). SessionTrackerCleanupListener is
    // the @WebListener and delegates sessionDestroyed here.

    private static final Logger log = LoggerFactory.getLogger(SessionTracker.class);

    /** userId → live HttpSession references. Values are concurrent sets. */
    // ponytail: holds strong session refs — Payara invalidation removes them via sessionDestroyed.
    private final Map<UUID, Set<HttpSession>> userSessions = new ConcurrentHashMap<>();

    public SessionTracker() {}

    /**
     * Associate an authenticated session with its user.
     * Call this immediately after a successful login / session-id regeneration.
     */
    public void register(UUID userId, HttpSession session) {
        userSessions
                .computeIfAbsent(userId, k -> Collections.newSetFromMap(new ConcurrentHashMap<>()))
                .add(session);
    }

    /**
     * Invalidate every known session for the given user.
     * Used by DELETE /auth/me before the hard-delete executes.
     */
    public void invalidateByUserId(UUID userId) {
        Set<HttpSession> sessions = userSessions.remove(userId);
        if (sessions == null) return;
        for (HttpSession session : sessions) {
            try {
                session.invalidate();
            } catch (IllegalStateException ignored) {
                // Already invalidated — safe to ignore.
            }
        }
        log.info("Invalidated {} session(s) for user {}", sessions.size(), userId);
    }

    // ── HttpSessionListener ────────────────────────────────────────────────────

    @Override
    public void sessionDestroyed(HttpSessionEvent se) {
        // Clean up stale entries when a session is destroyed by any path
        // (timeout, explicit invalidate, container shutdown).
        HttpSession session = se.getSession();
        userSessions.values().forEach(set -> set.remove(session));
    }
}
