package com.secbret.integration;

import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.Persistence;
import org.flywaydb.core.Flyway;
import org.testcontainers.containers.PostgreSQLContainer;

import java.util.Map;

/**
 * Shared Testcontainers harness: one PostgreSQL 14 container per JVM, migrated
 * with the real Flyway V1-V20 scripts, exposed through a RESOURCE_LOCAL
 * Hibernate EntityManagerFactory (SecBretTestPU).
 *
 * <p>Container and EMF are started lazily in a static initializer and reused by
 * every IT class; Testcontainers' Ryuk reaps the container after the JVM exits.</p>
 */
public abstract class PostgresIntegrationSupport {

    protected static final PostgreSQLContainer<?> POSTGRES;
    protected static final EntityManagerFactory EMF;

    static {
        POSTGRES = new PostgreSQLContainer<>("postgres:14-alpine")
                .withDatabaseName("secbret")
                .withUsername("secbret")
                .withPassword("secbret-test");
        POSTGRES.start();

        Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration")
                .load()
                .migrate();

        EMF = Persistence.createEntityManagerFactory("SecBretTestPU", Map.of(
                "jakarta.persistence.jdbc.url", POSTGRES.getJdbcUrl(),
                "jakarta.persistence.jdbc.user", POSTGRES.getUsername(),
                "jakarta.persistence.jdbc.password", POSTGRES.getPassword(),
                "jakarta.persistence.jdbc.driver", "org.postgresql.Driver"));
    }
}
