package com.secbret.ai.ml;

import java.util.Optional;
import java.util.logging.Logger;

/**
 * Stub implementation of {@link MlScoringClient} that unconditionally returns
 * {@link Optional#empty()} — representing "ML sidecar not wired yet".
 *
 * <p>This is the sole CDI implementation until <b>Phase 4 Lane C</b>, which
 * replaces this bean with a real {@code GrpcMlScoringClient} that:
 * <ul>
 *   <li>Opens a {@code ManagedChannel} to {@code ml-sidecar:50051}
 *       (annotated {@code @ApplicationScoped @PreDestroy} for graceful shutdown)</li>
 *   <li>Calls the {@code MLScorer.Classify} RPC with a 2-second deadline
 *       ({@code ML_TIMEOUT_MS})</li>
 *   <li>Maps a {@code StatusRuntimeException} (deadline, UNAVAILABLE, etc.) to
 *       a circuit-breaker failure, then returns {@code Optional.empty()}</li>
 *   <li>On success, maps {@code ClassificationResponse} → {@link MlScore} and
 *       logs WARN if {@code model_version} differs from the last observed value</li>
 * </ul>
 *
 * <p>All calls route through {@link MlCircuitBreaker#execute(java.util.function.Supplier)}
 * so that even the stub exercises the circuit-breaker path. Because the stub
 * never throws (it always returns empty immediately), it never opens the
 * breaker — which is the correct behaviour: the stub represents "sidecar absent",
 * not "sidecar failing". The real gRPC client will drive breaker transitions via
 * actual network errors and timeouts.
 *
 * <p><b>NO gRPC dependency is added.</b> This WAR uses pure Java. The grpc-java
 * dependency and the generated proto stubs are added only in Phase 4 Lane C.
 *
 * <p>Thread safe: stateless; the circuit breaker is independently thread-safe.
 *
 * <p><b>Not a CDI bean.</b> Under {@code bean-discovery-mode="annotated"} this
 * class carries no scope annotation, so it is not discovered directly;
 * {@link MlScoringClientProducer} instantiates it when {@code ML_SIDECAR_HOST}
 * is absent. This keeps a single unambiguous {@link MlScoringClient} bean.
 */
public class StubMlScoringClient implements MlScoringClient {

    private static final Logger LOG = Logger.getLogger(StubMlScoringClient.class.getName());

    private final MlCircuitBreaker circuitBreaker;

    public StubMlScoringClient(MlCircuitBreaker circuitBreaker) {
        this.circuitBreaker = circuitBreaker;
    }

    /**
     * Always returns empty (UNAVAILABLE). Routes through the circuit breaker so
     * that the breaker's state machine is exercised (breaker remains CLOSED since
     * the stub never throws — it represents absence, not failure).
     *
     * <p>When Phase 4 Lane C replaces this class with {@code GrpcMlScoringClient},
     * only this class changes; {@link MlScoringClient}, {@link MlScoreRequest},
     * {@link MlScore}, and {@link MlCircuitBreaker} are the stable contract.
     *
     * @param request must not be null
     * @return always {@link Optional#empty()}
     */
    @Override
    public Optional<MlScore> classify(MlScoreRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }
        LOG.fine(() -> "StubMlScoringClient.classify url=" + request.url()
                + " [ML sidecar not yet wired — Phase 4 Lane C]");
        return circuitBreaker.execute(() -> Optional.empty());
    }
}
