package com.secbret.ai.ml;

import io.grpc.Deadline;
import io.grpc.ManagedChannel;
import io.grpc.StatusRuntimeException;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;
import secbret.ml.MLScorerGrpc;
import secbret.ml.Secbret.ClassificationRequest;
import secbret.ml.Secbret.ClassificationResponse;

/**
 * Real gRPC implementation of {@link MlScoringClient} — calls the Python ML
 * sidecar's {@code MLScorer.Classify} RPC (Part II §7 gRPC contract).
 *
 * <p><b>Not a CDI bean itself.</b> Instances are built by
 * {@link MlScoringClientProducer}, which owns the {@link ManagedChannel}
 * lifecycle and selects between this client and {@link StubMlScoringClient}
 * from the {@code ML_SIDECAR_HOST} env var (§6). This keeps the channel a single
 * {@code @ApplicationScoped} singleton (§7 Implementation Note) rather than one
 * per call, and keeps the circuit-breaker state on that singleton.
 *
 * <h2>Failure handling (§7, §15)</h2>
 * <ul>
 *   <li>Every call is routed through {@link MlCircuitBreaker#execute}. The
 *       supplier throws on any gRPC error so the breaker records a failure; the
 *       breaker maps that (and any short-circuit) to {@link Optional#empty()}.</li>
 *   <li>An explicit gRPC {@link Deadline} of {@code ML_TIMEOUT_MS} bounds every
 *       call — no unbounded waits, no retry loop (decision #17). A deadline
 *       breach surfaces as {@code StatusRuntimeException(DEADLINE_EXCEEDED)},
 *       which counts as a breaker failure.</li>
 *   <li>Rules-only fallback (empty) is the degraded, spec-conformant outcome —
 *       ML errors degrade the scan, never fail it.</li>
 * </ul>
 *
 * <h2>Model-version tracking (§7)</h2>
 * On every successful response the {@code model_version} is carried on the
 * returned {@link MlScore} (persisted to {@code secbret_analysis.model_version}).
 * When the version changes between calls a WARN is logged so operators can
 * correlate score shifts with model rollouts.
 *
 * <p>Thread safe: the blocking stub and the breaker are both safe for concurrent
 * use; {@link #lastModelVersion} is an {@link AtomicReference}.
 */
public class GrpcMlScoringClient implements MlScoringClient {

    private static final Logger LOG = Logger.getLogger(GrpcMlScoringClient.class.getName());

    private final MLScorerGrpc.MLScorerBlockingStub blockingStub;
    private final MlCircuitBreaker circuitBreaker;
    private final long timeoutMs;

    /** Last observed model version, for change-detection WARN logging. */
    private final AtomicReference<String> lastModelVersion = new AtomicReference<>(null);

    /**
     * Production constructor: derive a blocking stub from the shared channel.
     *
     * @param channel        the shared {@code @ApplicationScoped} ManagedChannel
     * @param circuitBreaker the ML circuit breaker (§15); must not be null
     * @param timeoutMs      the per-call deadline in ms ({@code ML_TIMEOUT_MS})
     */
    public GrpcMlScoringClient(ManagedChannel channel, MlCircuitBreaker circuitBreaker, long timeoutMs) {
        this(MLScorerGrpc.newBlockingStub(channel), circuitBreaker, timeoutMs);
    }

    /**
     * Test constructor: inject a blocking stub directly (mock or in-process),
     * so mapping and error paths are unit-testable without a channel.
     *
     * @param blockingStub   the gRPC blocking stub; must not be null
     * @param circuitBreaker the ML circuit breaker; must not be null
     * @param timeoutMs       the per-call deadline in ms; must be > 0
     */
    public GrpcMlScoringClient(MLScorerGrpc.MLScorerBlockingStub blockingStub,
                               MlCircuitBreaker circuitBreaker,
                               long timeoutMs) {
        if (blockingStub == null) {
            throw new IllegalArgumentException("blockingStub must not be null");
        }
        if (circuitBreaker == null) {
            throw new IllegalArgumentException("circuitBreaker must not be null");
        }
        if (timeoutMs <= 0) {
            throw new IllegalArgumentException("timeoutMs must be > 0, got " + timeoutMs);
        }
        this.blockingStub   = blockingStub;
        this.circuitBreaker = circuitBreaker;
        this.timeoutMs      = timeoutMs;
    }

    /**
     * Classify via gRPC, through the circuit breaker, with a hard deadline.
     *
     * @param request the classification request; must not be null
     * @return the mapped {@link MlScore}, or empty on any failure / breaker OPEN
     */
    @Override
    public Optional<MlScore> classify(MlScoreRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }
        return circuitBreaker.execute(() -> callSidecar(request));
    }

    /**
     * The actual RPC. Throws {@link StatusRuntimeException} on any gRPC error so
     * the circuit breaker records a failure. Non-throwing success returns a
     * mapped {@link MlScore}.
     */
    private Optional<MlScore> callSidecar(MlScoreRequest request) {
        ClassificationRequest grpcRequest = toGrpcRequest(request);

        // Fresh deadline per call — a Deadline is absolute, so it must be
        // computed at call time, not stored on the stub.
        ClassificationResponse response = blockingStub
                .withDeadline(Deadline.after(timeoutMs, TimeUnit.MILLISECONDS))
                .classify(grpcRequest);

        return Optional.of(toMlScore(request.url(), response));
    }

    /** Map the stable Java request record to the protobuf message (null → ""). */
    private static ClassificationRequest toGrpcRequest(MlScoreRequest r) {
        return ClassificationRequest.newBuilder()
                .setUrl(r.url())
                .setRuleScore(r.ruleScore())
                .setTier1FindingsJson(nullToEmpty(r.tier1FindingsJson()))
                .setTier2FindingsJson(nullToEmpty(r.tier2FindingsJson()))
                .setTier3FindingsJson(nullToEmpty(r.tier3FindingsJson()))
                .build();
    }

    /**
     * Map the protobuf response to {@link MlScore}, clamping the scores into
     * [0,1] (the record enforces the range; the sidecar is trusted but a
     * malformed value must degrade to a breaker failure via the record's
     * IllegalArgumentException rather than a bad persisted score).
     */
    private MlScore toMlScore(String url, ClassificationResponse resp) {
        String version = resp.getModelVersion();
        LOG.info(() -> String.format(
                "ML sidecar classify url=%s mlScore=%.4f confidence=%.4f modelVersion=%s",
                url, resp.getMlScore(), resp.getConfidence(), version));

        String prev = lastModelVersion.getAndSet(version);
        if (prev != null && !prev.equals(version)) {
            LOG.warning(String.format(
                    "ML model version changed: %s -> %s (correlate score shifts with rollout)",
                    prev, version));
        }
        return new MlScore(resp.getMlScore(), resp.getConfidence(), version);
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }
}
