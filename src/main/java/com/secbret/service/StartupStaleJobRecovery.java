package com.secbret.service;

import com.secbret.config.FlywayMigrationBean;
import jakarta.annotation.PostConstruct;
import jakarta.ejb.DependsOn;
import jakarta.ejb.Singleton;
import jakarta.ejb.Startup;
import jakarta.inject.Inject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Eager startup trigger for stale-job recovery (Part II §10.4).
 *
 * <p>{@code @DependsOn("FlywayMigrationBean")} guarantees the schema (V1–V20) exists
 * before the recovery UPDATEs run, so the native statements never hit missing tables.
 * {@code @Startup} makes it run at deploy time, not on first request — the exact
 * moment orphaned rows from a prior crash need clearing.
 *
 * <p>Mirrors {@link AdminSeeder}'s pattern: the real work lives in
 * {@link StaleJobRecovery#recover()} so it is testable without an EJB container.
 */
@Singleton
@Startup
@DependsOn("FlywayMigrationBean")
public class StartupStaleJobRecovery {

    private static final Logger log = LoggerFactory.getLogger(StartupStaleJobRecovery.class);

    @Inject
    StaleJobRecovery staleJobRecovery;

    @PostConstruct
    public void onStartup() {
        log.info("Running stale-job recovery at startup…");
        staleJobRecovery.recover();
    }
}
