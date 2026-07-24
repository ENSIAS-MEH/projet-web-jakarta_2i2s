package com.secbret.service;

import jakarta.inject.Inject;
import jakarta.servlet.annotation.WebListener;
import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionListener;

/**
 * Servlet-container hook for {@link SessionTracker} cleanup.
 *
 * <p>Deliberately unscoped: Payara rejects a {@code @WebListener} class that also
 * carries a CDI scope annotation ("annotated with an invalid scope"), so the
 * {@code @ApplicationScoped} tracker cannot be the listener itself. CDI injection
 * into servlet listeners is supported, so this thin delegate forwards
 * {@code sessionDestroyed} to the shared tracker instance.
 */
@WebListener
public class SessionTrackerCleanupListener implements HttpSessionListener {

    @Inject
    SessionTracker sessionTracker;

    @Override
    public void sessionDestroyed(HttpSessionEvent se) {
        sessionTracker.sessionDestroyed(se);
    }
}
