package com.secbret.ai;

import java.util.OptionalDouble;

/**
 * The ML sidecar consultation seam consumed by {@link ThreatAnalyzer}.
 *
 * <p>Task 11 owns only this interface, not an implementation. The real client
 * (Task 12 / Lane C: gRPC + circuit breaker) supplies an {@code mlScore} in
 * [0.0, 1.0] when the sidecar answers within the 2-second synchronous ceiling,
 * and an <b>empty</b> {@link OptionalDouble} when the call times out or the
 * circuit breaker is OPEN. An empty result is the signal for the rules-only
 * fallback (§7 "Synchronous-Ceiling ML Fallback", B4): the combined score
 * degrades to the {@code ruleScore}, biasing borderline cases toward human
 * review rather than a silent auto-benign.
 *
 * @see ThreatAnalyzer#analyze(RuleInput, MlConsultation)
 */
@FunctionalInterface
public interface MlConsultation {

    /**
     * Consult the ML sidecar for the given rules outcome.
     *
     * @param ruleResult the Stage 1/2 rules outcome that triggered consultation
     * @return the mlScore in [0.0, 1.0], or empty if unavailable (timeout /
     *         breaker OPEN) — empty selects the rules-only fallback
     */
    OptionalDouble consult(RuleResult ruleResult);

    /** A consultation that is always unavailable (rules-only fallback). */
    static MlConsultation unavailable() {
        return ruleResult -> OptionalDouble.empty();
    }
}
