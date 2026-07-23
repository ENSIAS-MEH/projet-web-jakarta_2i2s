package com.secbret.service;

import com.secbret.config.FlywayMigrationBean;
import jakarta.annotation.PostConstruct;
import jakarta.ejb.DependsOn;
import jakarta.ejb.Schedule;
import jakarta.ejb.Singleton;
import jakarta.ejb.Startup;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 24-hour maintenance batch timer (decision #21a, Part III §Conventions).
 *
 * <p>This is a SEPARATE bean from the §5 rate-limit eviction sweep (Task 22).
 * Runs once at startup via {@link #onStartup()}, then on a fixed daily schedule
 * via {@link #runDaily()}.
 *
 * <p>Purges:
 * <ol>
 *   <li>{@code idempotency_key} rows past their 24h TTL ({@code expires_at < NOW()})</li>
 *   <li>Expired {@code share_link} rows ({@code expires_at < NOW() AND is_revoked = false})
 *       per §21a "purges expired share_link rows".</li>
 * </ol>
 *
 * <p>ponytail: EJB @Schedule fixed-cron is the simplest in-process 24h timer on
 * Payara/EJB without an external scheduler; no framework needed.
 */
@Singleton
@Startup
@DependsOn("FlywayMigrationBean")
public class MaintenanceBatchTimer {

    private static final Logger log = LoggerFactory.getLogger(MaintenanceBatchTimer.class);

    @PersistenceContext(unitName = "SecBretPU")
    /* package */ EntityManager em; // package-visible for Testcontainers IT injection

    @PostConstruct
    public void onStartup() {
        log.info("MaintenanceBatchTimer: running startup maintenance sweep");
        runMaintenance(em);
    }

    /** Runs every 24 hours (at midnight UTC). Separate from the rate-limit sweep. */
    @Schedule(hour = "0", minute = "0", second = "0", persistent = false)
    @Transactional
    public void runDaily() {
        log.info("MaintenanceBatchTimer: running scheduled 24h maintenance sweep");
        runMaintenance(em);
    }

    /**
     * Maintenance logic extracted so it is testable with an injected EntityManager
     * (RESOURCE_LOCAL, no EJB container needed in tests).
     */
    @Transactional
    public void runMaintenance(EntityManager entityManager) {
        int purgedKeys = entityManager.createNativeQuery(
                "DELETE FROM idempotency_key WHERE expires_at < NOW()")
                .executeUpdate();

        int purgedLinks = entityManager.createNativeQuery(
                "DELETE FROM share_link WHERE expires_at < NOW()")
                .executeUpdate();

        if (purgedKeys > 0 || purgedLinks > 0) {
            log.info("MaintenanceBatchTimer: purged {} expired idempotency_key rows, "
                    + "{} expired share_link rows", purgedKeys, purgedLinks);
        } else {
            log.debug("MaintenanceBatchTimer: nothing to purge");
        }
    }
}
