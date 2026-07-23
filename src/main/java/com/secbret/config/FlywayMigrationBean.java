package com.secbret.config;

import jakarta.annotation.PostConstruct;
import jakarta.ejb.Singleton;
import jakarta.ejb.Startup;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.output.MigrateResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Runs Flyway migrations at application startup before any other bean initialises.
 *
 * <p>Design decisions (spec §6):
 * <ul>
 *   <li>Reads {@code DB_URL}, {@code DB_USER}, {@code DB_PASSWORD} from environment —
 *       the same values that the JTA datasource uses, enforcing credential coupling.</li>
 *   <li>Tolerates an empty {@code classpath:db/migration} directory; Flyway reports
 *       "Current version of schema … : null / no migrations found" and exits cleanly.</li>
 *   <li>{@code baselineOnMigrate} is intentionally OFF: a pre-existing schema with
 *       no Flyway history is an error, not a silent success.</li>
 * </ul>
 */
@Singleton
@Startup
public class FlywayMigrationBean {

    private static final Logger log = LoggerFactory.getLogger(FlywayMigrationBean.class);

    @PostConstruct
    public void migrate() {
        String url  = requireEnv("DB_URL");
        String user = requireEnv("DB_USER");
        String pass = requireEnv("DB_PASSWORD");

        log.info("Starting Flyway migration against {}", url);

        Flyway flyway = Flyway.configure()
                .dataSource(url, user, pass)
                .locations("classpath:db/migration")
                .loggers("slf4j")
                // Allow startup with zero migration files (parallel task delivers them)
                .validateMigrationNaming(true)
                .load();

        MigrateResult result = flyway.migrate();
        log.info("Flyway migration complete: {} migration(s) applied, schema version = {}",
                result.migrationsExecuted, result.targetSchemaVersion);
    }

    private static String requireEnv(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(
                    "Required environment variable '" + name + "' is not set. " +
                    "Check .env and docker-compose.yml.");
        }
        return value;
    }
}
