package com.secbret.ai.ml;

import io.grpc.ManagedChannel;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * CDI producer that selects the live {@link MlScoringClient} implementation from
 * the environment and owns the shared gRPC {@link ManagedChannel} lifecycle.
 *
 * <h2>Selection (§6)</h2>
 * <ul>
 *   <li>{@code ML_SIDECAR_HOST} set (e.g. {@code secbret-ml:50051}) →
 *       {@link GrpcMlScoringClient} over a single {@code @ApplicationScoped}
 *       plaintext channel to that host:port.</li>
 *   <li>absent / blank → {@link StubMlScoringClient} (rules-only fallback,
 *       breaker never opens — absence is not failure). Exactly the pre-Lane-C
 *       behaviour.</li>
 * </ul>
 *
 * <p>The sidecar speaks plaintext gRPC on the internal Docker network (the
 * Compose healthcheck uses {@code grpc.insecure_channel}); there is no TLS on
 * this hop, so {@link NettyChannelBuilder#usePlaintext()} is correct. The
 * channel is created once and shut down in {@link #shutdown()} — never per call
 * (§7 Implementation Note).
 *
 * <p>Because {@code beans.xml} uses {@code bean-discovery-mode="annotated"},
 * neither {@link GrpcMlScoringClient} nor {@link StubMlScoringClient} carries a
 * scope annotation, so this producer is the single {@link MlScoringClient} bean —
 * no ambiguous-dependency error.
 */
@ApplicationScoped
public class MlScoringClientProducer {

    private static final Logger LOG = Logger.getLogger(MlScoringClientProducer.class.getName());

    private static final String ENV_SIDECAR_HOST = "ML_SIDECAR_HOST";
    private static final String ENV_TIMEOUT_MS   = "ML_TIMEOUT_MS";
    private static final long   DEFAULT_TIMEOUT_MS = 2_000L;

    private final MlCircuitBreaker circuitBreaker;

    /** The shared channel, created only when a sidecar host is configured. */
    private volatile ManagedChannel channel;

    @Inject
    public MlScoringClientProducer(MlCircuitBreaker circuitBreaker) {
        this.circuitBreaker = circuitBreaker;
    }

    /** CDI proxy constructor. */
    protected MlScoringClientProducer() {
        this.circuitBreaker = null;
    }

    @Produces
    @ApplicationScoped
    public MlScoringClient mlScoringClient() {
        String host = getenv(ENV_SIDECAR_HOST);
        if (host == null || host.isBlank()) {
            LOG.info("ML_SIDECAR_HOST unset — using StubMlScoringClient (rules-only fallback)");
            return new StubMlScoringClient(circuitBreaker);
        }
        long timeoutMs = resolveTimeoutMs();
        this.channel = buildChannel(host.trim());
        LOG.info(String.format(
                "ML sidecar configured host=%s timeoutMs=%d — using GrpcMlScoringClient",
                host.trim(), timeoutMs));
        return new GrpcMlScoringClient(channel, circuitBreaker, timeoutMs);
    }

    /**
     * Build a plaintext Netty channel to {@code host:port}. A bare host with no
     * colon defaults to the sidecar's fixed port 50051.
     */
    private ManagedChannel buildChannel(String hostPort) {
        String host;
        int port;
        int colon = hostPort.lastIndexOf(':');
        if (colon > 0 && colon < hostPort.length() - 1) {
            host = hostPort.substring(0, colon);
            port = parsePort(hostPort.substring(colon + 1));
        } else {
            host = hostPort;
            port = 50051;
        }
        return NettyChannelBuilder.forAddress(host, port)
                .usePlaintext()
                .build();
    }

    private static int parsePort(String raw) {
        try {
            int p = Integer.parseInt(raw.trim());
            if (p < 1 || p > 65_535) {
                throw new NumberFormatException("out of range: " + p);
            }
            return p;
        } catch (NumberFormatException e) {
            throw new IllegalStateException(
                    "ML_SIDECAR_HOST has an invalid port: " + raw, e);
        }
    }

    private long resolveTimeoutMs() {
        String raw = getenv(ENV_TIMEOUT_MS);
        if (raw == null || raw.isBlank()) {
            return DEFAULT_TIMEOUT_MS;
        }
        try {
            long v = Long.parseLong(raw.trim());
            return v > 0 ? v : DEFAULT_TIMEOUT_MS;
        } catch (NumberFormatException e) {
            return DEFAULT_TIMEOUT_MS;
        }
    }

    /** Seam for tests. */
    protected String getenv(String name) {
        return System.getenv(name);
    }

    @PreDestroy
    void shutdown() {
        ManagedChannel ch = this.channel;
        if (ch == null) {
            return;
        }
        LOG.info("Shutting down ML sidecar channel");
        ch.shutdown();
        try {
            if (!ch.awaitTermination(5, TimeUnit.SECONDS)) {
                ch.shutdownNow();
            }
        } catch (InterruptedException e) {
            ch.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
