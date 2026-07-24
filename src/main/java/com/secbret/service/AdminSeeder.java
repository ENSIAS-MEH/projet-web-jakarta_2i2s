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
 * First-run admin bootstrap trigger (Part II §6).
 *
 * <p>{@code @DependsOn("FlywayMigrationBean")} guarantees the schema exists (all
 * V1–V20 migrations applied) before the seed runs — without it, the
 * {@code SELECT COUNT(*) FROM secbret_user} idempotency probe could execute
 * against a not-yet-migrated database. {@code @Startup} makes this eager so the
 * seed happens at deploy time, not on first request.
 *
 * <p>The actual logic lives in {@link UserService#seedAdminIfEmpty()} so it can be
 * unit-tested without an EJB container.
 */
@Singleton
@Startup
@DependsOn("FlywayMigrationBean")
public class AdminSeeder {

    private static final Logger log = LoggerFactory.getLogger(AdminSeeder.class);

    @Inject
    UserService userService;

    @PostConstruct
    public void seed() {
        log.info("Running first-run admin bootstrap check…");
        userService.seedAdminIfEmpty();
    }
}
