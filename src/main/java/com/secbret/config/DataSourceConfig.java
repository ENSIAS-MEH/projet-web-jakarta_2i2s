package com.secbret.config;

import jakarta.annotation.sql.DataSourceDefinition;
import jakarta.ejb.Singleton;
import jakarta.ejb.Startup;

/**
 * Declares the application's JTA-managed JDBC datasource via
 * {@link DataSourceDefinition} — the standard Jakarta EE 10 portable mechanism.
 *
 * <p>The datasource is bound to {@code java:app/jdbc/SecBretDS} (referenced by
 * {@code persistence.xml} and {@link com.secbret.service.DatabaseHealthService}).
 *
 * <p>Connection values are read from environment variables at deployment time
 * (Payara resolves {@code ${ENV=DB_URL}} substitution at startup). Pool sizing
 * follows spec §6:
 * <ul>
 *   <li>minPoolSize = 5  — warm connections at startup</li>
 *   <li>maxPoolSize = 20 — fits PostgreSQL 512 MB limit (20 × ~5 MB work_mem)</li>
 *   <li>loginTimeout = 30 — fails fast on dead connections</li>
 *   <li>maxIdleTime  = 300 — reclaim unused connections after 5 minutes</li>
 * </ul>
 *
 * <p>Validation query ({@code SELECT 1}) is applied via Payara pool validation
 * rather than through {@code @DataSourceDefinition} (which does not expose a
 * {@code validationQuery} attribute in Jakarta EE 10); see the Payara JDBC pool
 * admin or post-deploy glassfish-resources.xml if fine-grained validation control
 * is needed. The {@link com.secbret.service.DatabaseHealthService} independently
 * executes {@code SELECT 1} for health-check purposes.
 */
@DataSourceDefinition(
        name          = "java:app/jdbc/SecBretDS",
        className     = "org.postgresql.ds.PGSimpleDataSource",
        url           = "${ENV=DB_URL}",
        user          = "${ENV=DB_USER}",
        password      = "${ENV=DB_PASSWORD}",
        minPoolSize   = 5,
        maxPoolSize   = 20,
        loginTimeout  = 30,
        maxIdleTime   = 300,
        transactional = true
)
@Singleton
@Startup
public class DataSourceConfig {
    // This bean exists solely to anchor the @DataSourceDefinition annotation.
    // Payara processes it at application startup before any other bean initialises.
}
