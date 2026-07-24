package com.secbret.ai;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.OptionalDouble;

/**
 * Blends the synchronous {@link RulesEngine} score with the ML sidecar score and
 * derives the auto-action and tentative verdicts (Part II §7
 * "Synchronous-Ceiling ML Fallback" and "Auto-Action Thresholds").
 *
 * <p><b>Blend contract.</b>
 * <pre>
 * ruleScore = RulesEngine.evaluate(input)
 * if AUTO_APPROVE_LOW &lt; ruleScore &lt; AUTO_APPROVE_HIGH:   # open consultation band
 *     mlScore = ML sidecar (2s ceiling, circuit-breaker guarded)
 *     if unavailable (timeout / breaker OPEN):
 *         combined = ruleScore                            # rules-only fallback (B4)
 *     else:
 *         combined = 0.4*ruleScore + 0.6*mlScore
 * else:
 *     combined = ruleScore                                # extreme: ML can't change it
 * </pre>
 *
 * <p>The blend weights {@link #RULE_BLEND_WEIGHT} (0.4) and
 * {@link #ML_BLEND_WEIGHT} (0.6) are <b>compile-time constants</b>, not
 * env-tunable (§7 env-table note). The consultation band is the open interval
 * {@code (AUTO_APPROVE_LOW, AUTO_APPROVE_HIGH)} — <em>derived</em> from the only
 * two score-boundary env vars, so the "ML zone equals the PENDING_REVIEW band"
 * invariant holds by construction (there are no separate {@code ML_UNCERTAINTY_*}
 * variables).
 *
 * <p><b>Fail-safe (B4).</b> Because the non-dispositive {@code ruleScore} never
 * exceeds 0.827 (&lt; 0.95), an ML outage degrades an uncertain scan to
 * PENDING_REVIEW — a human analyst, never a silent auto-benign. The dispositive
 * override still fires without ML (kit hit → {@code ruleScore = 1.0} →
 * {@code combined = 1.0} → VERIFIED_MALICIOUS), so near-certain malicious
 * evidence is still auto-blocked during an outage.
 *
 * <p><b>Complexity.</b> {@code Θ(1)} plus at most one ML call.
 */
@ApplicationScoped
public class ThreatAnalyzer {

    /** Rule contribution to the blend. Compile-time constant per §7 (not env-tunable). */
    public static final double RULE_BLEND_WEIGHT = 0.4;
    /** ML contribution to the blend. Compile-time constant per §7 (not env-tunable). */
    public static final double ML_BLEND_WEIGHT = 0.6;

    /** Default AUTO_APPROVE_LOW (§6 env table). Auto-reject at/below; band lower bound. */
    public static final double DEFAULT_AUTO_APPROVE_LOW = 0.05;
    /** Default AUTO_APPROVE_HIGH (§6 env table). Auto-approve at/above; band upper bound. */
    public static final double DEFAULT_AUTO_APPROVE_HIGH = 0.95;

    private static final String ENV_AUTO_APPROVE_LOW = "AUTO_APPROVE_LOW";
    private static final String ENV_AUTO_APPROVE_HIGH = "AUTO_APPROVE_HIGH";

    private RulesEngine rulesEngine;
    private double autoApproveLow;
    private double autoApproveHigh;

    /** No-arg constructor required by CDI for proxying (@ApplicationScoped). */
    protected ThreatAnalyzer() {
        this.rulesEngine = null;
        this.autoApproveLow = DEFAULT_AUTO_APPROVE_LOW;
        this.autoApproveHigh = DEFAULT_AUTO_APPROVE_HIGH;
    }

    /** CDI constructor: resolves the score boundaries from the environment. */
    @Inject
    public ThreatAnalyzer(RulesEngine rulesEngine) {
        this(rulesEngine,
                resolveBoundary(ENV_AUTO_APPROVE_LOW, DEFAULT_AUTO_APPROVE_LOW),
                resolveBoundary(ENV_AUTO_APPROVE_HIGH, DEFAULT_AUTO_APPROVE_HIGH));
    }

    /** Explicit-boundary constructor for tests and deterministic wiring. */
    public ThreatAnalyzer(RulesEngine rulesEngine, double autoApproveLow, double autoApproveHigh) {
        if (rulesEngine == null) {
            throw new IllegalArgumentException("rulesEngine must not be null");
        }
        if (!(autoApproveLow >= 0.0 && autoApproveHigh <= 1.0 && autoApproveLow < autoApproveHigh)) {
            throw new IllegalArgumentException(
                    "require 0.0 <= AUTO_APPROVE_LOW < AUTO_APPROVE_HIGH <= 1.0, got low="
                            + autoApproveLow + " high=" + autoApproveHigh);
        }
        this.rulesEngine = rulesEngine;
        this.autoApproveLow = autoApproveLow;
        this.autoApproveHigh = autoApproveHigh;
    }

    /**
     * Run the full pipeline: rules, optional ML blend, and verdict derivation.
     *
     * @param input the eight indicator signals; must not be null
     * @param ml    the ML consultation seam; {@link MlConsultation#unavailable()}
     *              forces the rules-only fallback. Consulted only when
     *              {@code ruleScore} lies in the open band
     *              {@code (autoApproveLow, autoApproveHigh)}
     * @return the combined score, both verdicts, and ML provenance
     */
    public ThreatDisposition analyze(RuleInput input, MlConsultation ml) {
        if (ml == null) {
            throw new IllegalArgumentException("ml must not be null");
        }
        RuleResult ruleResult = rulesEngine.evaluate(input);
        double ruleScore = ruleResult.ruleScore();

        boolean mlConsulted = false;
        OptionalDouble blendedMl = OptionalDouble.empty();
        double combinedScore = ruleScore;

        // Consult ML only inside the open consultation band; outside it the score
        // is already extreme enough that ML cannot change the disposition.
        if (ruleScore > autoApproveLow && ruleScore < autoApproveHigh) {
            OptionalDouble mlScore = ml.consult(ruleResult);
            if (mlScore.isPresent()) {
                double m = clampUnit(mlScore.getAsDouble());
                combinedScore = RULE_BLEND_WEIGHT * ruleScore + ML_BLEND_WEIGHT * m;
                mlConsulted = true;
                blendedMl = OptionalDouble.of(m);
            }
            // else: rules-only fallback — combinedScore stays == ruleScore (B4).
        }

        return new ThreatDisposition(
                ruleResult,
                combinedScore,
                mlConsulted,
                blendedMl,
                autoAction(combinedScore),
                tentativeVerdict(combinedScore),
                null);   // modelVersion attached by ScoringService when ML was consulted
    }

    /** §7 Auto-Action Thresholds. */
    public AutoActionVerdict autoAction(double combinedScore) {
        if (combinedScore >= autoApproveHigh) {
            return AutoActionVerdict.VERIFIED_MALICIOUS;
        }
        if (combinedScore <= autoApproveLow) {
            return AutoActionVerdict.VERIFIED_BENIGN;
        }
        return AutoActionVerdict.PENDING_REVIEW;
    }

    /**
     * §7 tentative-verdict derivation: BENIGN at/below AUTO_APPROVE_LOW,
     * SUSPICIOUS above it (including the dispositive-override path).
     */
    public TentativeVerdict tentativeVerdict(double combinedScore) {
        return combinedScore <= autoApproveLow ? TentativeVerdict.BENIGN : TentativeVerdict.SUSPICIOUS;
    }

    public double autoApproveLow() {
        return autoApproveLow;
    }

    public double autoApproveHigh() {
        return autoApproveHigh;
    }

    private static double clampUnit(double v) {
        if (v < 0.0) {
            return 0.0;
        }
        if (v > 1.0) {
            return 1.0;
        }
        return v;
    }

    private static double resolveBoundary(String name, double defaultValue) {
        String raw = System.getenv(name);
        if (raw == null || raw.isBlank()) {
            return defaultValue;
        }
        try {
            double parsed = Double.parseDouble(raw.trim());
            if (parsed < 0.0 || parsed > 1.0) {
                return defaultValue;
            }
            return parsed;
        } catch (NumberFormatException notANumber) {
            return defaultValue;
        }
    }
}
