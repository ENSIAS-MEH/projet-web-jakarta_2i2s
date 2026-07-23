package com.secbret.service;

import jakarta.annotation.Resource;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Named;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

/**
 * Lightweight database connectivity check for the /health/ready probe.
 * Executes {@code SELECT 1} via the JTA datasource (validation query per spec §6).
 */
@ApplicationScoped
@Named
public class DatabaseHealthService {

    private static final Logger log = LoggerFactory.getLogger(DatabaseHealthService.class);
    private static final String VALIDATION_QUERY = "SELECT 1";

    @Resource(lookup = "java:app/jdbc/SecBretDS")
    private DataSource dataSource;

    /**
     * Returns {@code true} if the database is reachable.
     * On failure, logs the exception and returns {@code false} — never throws.
     */
    public boolean isHealthy() {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(VALIDATION_QUERY);
             ResultSet rs = ps.executeQuery()) {
            return rs.next();
        } catch (Exception e) {
            log.warn("Database health check failed: {}", e.getMessage());
            return false;
        }
    }
}
