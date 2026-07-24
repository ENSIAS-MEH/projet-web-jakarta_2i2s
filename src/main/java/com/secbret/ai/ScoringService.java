package com.secbret.ai;

import com.secbret.ai.ml.MlScoreRequest;
import com.secbret.ai.ml.MlScoringClient;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.OptionalDouble;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;

/**
 * Composing service that drives the complete §7 scoring pipeline:
 * {@link RulesEngine} → {@link MlScoringClient} (through the circuit breaker) →
 * {@link ThreatAnalyzer} blend → {@link ThreatDisposition}.
 *
 * <p>This bean is what <b>Task 13</b> (scan endpoints) will inject and call.
 * It is introduced here (Task 12) rather than editing {@link ThreatAnalyzer} for
 * three reasons:
 * <ol>
 *   <li>Task 11 already fully verifies {@code ThreatAnalyzer}'s scoring math and
 *       the {@link ReachableRangeInvariantTest}; touching ThreatAnalyzer risks
 *       regressions in verified code.</li>
 *   <li>{@code ThreatAnalyzer} accepts an {@link MlConsultation} seam that is
 *       exactly the right abstraction — ScoringService supplies the live
 *       implementation of that seam, adapting {@link MlScoringClient} output.</li>
 *   <li>The composition boundary makes the ML client injectable and mockable for
 *       unit tests without changing ThreatAnalyzer.</li>
 * </ol>
 *
 * <h2>Pipeline</h2>
 * <pre>
 * score(url, ruleInput, tier1FindingsJson?) :
 *   1. threatAnalyzer.analyze(ruleInput, ml = adapt(mlClient))
 *      — ThreatAnalyzer calls ml.consult(ruleResult) only when ruleScore is in
 *        the open band (AUTO_APPROVE_LOW, AUTO_APPROVE_HIGH)
 *      — ml.consult builds an MlScoreRequest and routes it through the breaker
 *      — if breaker OPEN or stub: OptionalDouble.empty() → rules-only fallback
 * </pre>
 *
 * <p><b>Thread safety:</b> {@code @ApplicationScoped} singleton. All state lives in
 * {@link MlCircuitBreaker} (which is independently thread-safe) or is
 * per-call-local.
 */
@ApplicationScoped
public class ScoringService {

    private static final Logger LOG = Logger.getLogger(ScoringService.class.getName());

    private ThreatAnalyzer threatAnalyzer;
    private MlScoringClient mlClient;

    /** No-arg constructor required by CDI for proxying (@ApplicationScoped). */
    protected ScoringService() {
        this.threatAnalyzer = null;
        this.mlClient       = null;
    }

    /** CDI constructor injection. */
    @Inject
    public ScoringService(ThreatAnalyzer threatAnalyzer, MlScoringClient mlClient) {
        if (threatAnalyzer == null) {
            throw new IllegalArgumentException("threatAnalyzer must not be null");
        }
        if (mlClient == null) {
            throw new IllegalArgumentException("mlClient must not be null");
        }
        this.threatAnalyzer = threatAnalyzer;
        this.mlClient       = mlClient;
    }

    /**
     * Score a URL: run the rules, optionally consult ML (through the circuit
     * breaker), and return the blended disposition.
     *
     * @param url               the normalised target URL (used in the ML request
     *                          and for logging); must not be null
     * @param ruleInput         the eight indicator signals; must not be null
     * @param tier1FindingsJson JSON-serialised Tier 1 findings for the ML request,
     *                          or null (will be treated as empty by the sidecar)
     * @return the complete disposition (combined score, both verdicts, ML provenance)
     */
    public ThreatDisposition score(String url, RuleInput ruleInput, String tier1FindingsJson) {
        if (url == null) {
            throw new IllegalArgumentException("url must not be null");
        }
        if (ruleInput == null) {
            throw new IllegalArgumentException("ruleInput must not be null");
        }

        // Capture the sidecar's model_version out of the adapter: the
        // MlConsultation seam only carries the numeric score, so the version is
        // stashed here and attached to the disposition after analyze() returns.
        // It is set only when ML actually contributed; rules-only leaves it null
        // (§7 ML Model Version Tracking).
        AtomicReference<String> modelVersionHolder = new AtomicReference<>(null);

        // Build the MlConsultation adapter that bridges ThreatAnalyzer's seam to
        // MlScoringClient + circuit breaker.
        MlConsultation ml = ruleResult -> {
            MlScoreRequest req = new MlScoreRequest(
                    url,
                    ruleResult.ruleScore(),
                    tier1FindingsJson,
                    null,   // Tier 2 — Phase 4 Lane C
                    null);  // Tier 3 — Phase 4 Lane C
            return mlClient.classify(req)
                    .map(mlScore -> {
                        modelVersionHolder.set(mlScore.modelVersion());
                        LOG.info(() -> String.format(
                                "ML consulted url=%s mlScore=%.4f confidence=%.4f modelVersion=%s",
                                url, mlScore.mlScore(), mlScore.confidence(), mlScore.modelVersion()));
                        return mlScore.mlScore();
                    })
                    .map(OptionalDouble::of)
                    .orElseGet(OptionalDouble::empty);
        };

        ThreatDisposition analyzed = threatAnalyzer.analyze(ruleInput, ml);
        // Attach the model_version only when ML was actually blended in.
        final ThreatDisposition d = analyzed.mlConsulted()
                ? analyzed.withModelVersion(modelVersionHolder.get())
                : analyzed;
        LOG.fine(() -> String.format(
                "ScoringService.score url=%s ruleScore=%.4f combined=%.4f mlConsulted=%b autoAction=%s",
                url, d.ruleResult().ruleScore(), d.combinedScore(),
                d.mlConsulted(), d.autoAction()));
        return d;
    }
}
