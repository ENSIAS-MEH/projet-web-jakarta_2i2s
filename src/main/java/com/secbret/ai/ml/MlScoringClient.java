package com.secbret.ai.ml;

import java.util.Optional;

/**
 * Abstraction over the ML sidecar scoring call.
 *
 * <p>Returns {@link Optional#empty()} when the score is unavailable — the caller
 * ({@link com.secbret.ai.ScoringService}) treats an empty result as the rules-only
 * fallback per §7 "Synchronous-Ceiling ML Fallback" (B4). Callers MUST NOT
 * distinguish between "sidecar unreachable", "timeout", and "circuit-breaker OPEN"
 * — all three are signalled by the same empty Optional.
 *
 * <p><b>Contract for implementors:</b>
 * <ul>
 *   <li>All network I/O MUST be guarded by the {@code ML_TIMEOUT_MS} ceiling
 *       (default 2000 ms). A timeout counts as a circuit-breaker failure and
 *       returns empty.
 *   <li>Implementations MUST route calls through an {@link MlCircuitBreaker}.
 *       When the breaker is OPEN it short-circuits without calling the sidecar
 *       and returns empty immediately.
 *   <li>The stub implementation ({@link StubMlScoringClient}) satisfies these
 *       requirements by always returning empty. It exists until Phase 4 Lane C
 *       replaces it with a real {@code GrpcMlScoringClient} that opens a
 *       {@code ManagedChannel} to {@code ml-sidecar:50051} and enforces the
 *       2-second deadline via gRPC stub options.
 * </ul>
 *
 * <p><b>Thread safety:</b> implementations MUST be safe for concurrent invocation
 * from the async scan executor ({@link com.secbret.service.ScanExecutor}).
 */
public interface MlScoringClient {

    /**
     * Classify the given URL using the ML sidecar.
     *
     * @param request the classification request (url + rule score + tier findings);
     *                must not be null
     * @return the ML score, or empty when unavailable (timeout / breaker OPEN /
     *         sidecar absent)
     */
    Optional<MlScore> classify(MlScoreRequest request);
}
