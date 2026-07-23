package com.secbret.controller;

import com.secbret.ai.ml.MlCircuitBreaker;
import com.secbret.service.DatabaseHealthService;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Health-check endpoints per Part III §0.
 *
 * <p>Three separate probes are provided so container orchestrators can distinguish
 * liveness from readiness and dependency health. No authentication is required.
 *
 * <ul>
 *   <li>{@code GET /api/v1/health/live} — process alive; no downstream checks.</li>
 *   <li>{@code GET /api/v1/health/ready} — DB connectivity confirmed; 503 if DOWN.</li>
 *   <li>{@code GET /api/v1/health/dependencies} — ML sidecar + SMTP availability;
 *       200 even when DEGRADED (rules-only fallback active); 503 only if DOWN.</li>
 * </ul>
 *
 * <p>Phase 1 semantics for {@code /dependencies}: the ML sidecar does not exist yet
 * (Phase 4 Lane C). Its status is represented as {@code "DEGRADED"} — circuit breaker
 * OPEN, rules-only mode is active, application is functional (200). SMTP likewise is
 * configured but not yet wired (Phase 5), represented as {@code "DEGRADED"}.
 * Both match the spec's defined statuses for configured-but-unavailable components.
 */
@Path("/health")
@Produces(MediaType.APPLICATION_JSON)
@RequestScoped
public class HealthController {

    static final String VERSION = "1.0.0";

    @Inject
    private DatabaseHealthService dbHealth;

    @Inject
    private MlCircuitBreaker mlCircuitBreaker;

    /**
     * Liveness probe — confirms the JVM process is alive.
     * Does NOT check database or any downstream service.
     * Response 200: {@code {"status":"UP","version":"1.0.0"}}
     */
    @GET
    @Path("/live")
    public Response live() {
        Map<String, String> body = new LinkedHashMap<>();
        body.put("status", "UP");
        body.put("version", VERSION);
        return Response.ok(body).build();
    }

    /**
     * Readiness probe — confirms the application can serve traffic.
     * Checks JDBC pool connectivity via {@code SELECT 1}.
     * Response 200: database UP. Response 503: database DOWN.
     */
    @GET
    @Path("/ready")
    public Response ready() {
        boolean dbUp = dbHealth.isHealthy();

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", dbUp ? "UP" : "DOWN");

        Map<String, String> checks = new LinkedHashMap<>();
        checks.put("database", dbUp ? "UP" : "DOWN");
        body.put("checks", checks);
        body.put("version", VERSION);

        int status = dbUp ? Response.Status.OK.getStatusCode()
                          : Response.Status.SERVICE_UNAVAILABLE.getStatusCode();
        return Response.status(status).entity(body).build();
    }

    /**
     * Dependency health — checks ML sidecar and SMTP availability.
     *
     * <p>Phase 1 implementation: both ML sidecar (Phase 4 Lane C) and SMTP (Phase 5)
     * are not yet implemented. Their status is {@code "DEGRADED"} — the circuit breaker
     * is OPEN for ML (rules-only fallback active) and SMTP is not yet configured.
     * Per spec, {@code DEGRADED} returns HTTP 200 because the application is still
     * functional. HTTP 503 is reserved for {@code DOWN} (unreachable and no fallback).
     *
     * <p>When the ML client and SMTP service are wired in later phases, this method
     * will call their respective health-check methods and return their actual status.
     */
    @GET
    @Path("/dependencies")
    public Response dependencies() {
        // mlSidecar (§0): UP when configured and the circuit breaker is CLOSED
        // (rules+ML blend active); DEGRADED when the breaker is OPEN/HALF_OPEN
        // (rules-only fallback) or the sidecar is unconfigured (stub). DEGRADED
        // is still 200 — the app is functional.
        // SMTP not yet wired (Phase 5) → DEGRADED.
        String mlStatus   = mlSidecarStatus();
        String smtpStatus = "DEGRADED";

        boolean anyDown = "DOWN".equals(mlStatus) || "DOWN".equals(smtpStatus);
        String overallStatus = anyDown ? "DOWN" : "UP";

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", overallStatus);

        Map<String, String> checks = new LinkedHashMap<>();
        checks.put("mlSidecar", mlStatus);
        checks.put("email", smtpStatus);
        body.put("checks", checks);
        body.put("version", VERSION);

        int httpStatus = anyDown ? Response.Status.SERVICE_UNAVAILABLE.getStatusCode()
                                 : Response.Status.OK.getStatusCode();
        return Response.status(httpStatus).entity(body).build();
    }

    /**
     * Map the ML circuit-breaker state to the §0 dependency status:
     * CLOSED + configured → UP; OPEN/HALF_OPEN or unconfigured → DEGRADED.
     * "Configured" = {@code ML_SIDECAR_HOST} is set (else the stub client is
     * wired and the sidecar is effectively absent → DEGRADED).
     */
    private String mlSidecarStatus() {
        String host = System.getenv("ML_SIDECAR_HOST");
        boolean configured = host != null && !host.isBlank();
        boolean closed = mlCircuitBreaker.currentState() == MlCircuitBreaker.State.CLOSED;
        return (configured && closed) ? "UP" : "DEGRADED";
    }
}
