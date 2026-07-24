package com.secbret.ai;

import jakarta.enterprise.context.ApplicationScoped;
import java.util.ArrayList;
import java.util.List;

/**
 * The synchronous rules engine (Part II §7 "Rules Engine"). Produces a
 * {@code ruleScore} in [0.0, 1.0] via two-stage evaluation:
 *
 * <pre>
 * # Stage 1 — dispositive override (near-certain evidence)
 * if knownPhishingKit:            # value == 1.0, set ONLY by a
 *     ruleScore = 1.0             # dispositive-eligible marker match
 * else:
 *     # Stage 2 — normalized weighted average
 *     ruleScore = Σ(weight × ruleValue) / Σ(weights)
 * </pre>
 *
 * <p><b>Why the override exists (B1/B2).</b> The weights sum to 1.30 and the
 * per-indicator maxima give a largest attainable numerator of 1.075, so the
 * largest attainable weighted-average {@code ruleScore} is {@code 0.827}. Without
 * the override the {@code VERIFIED_MALICIOUS} threshold (combined {@code >= 0.95})
 * is mathematically unreachable, and a definitive kit hit would dilute to
 * {@code 0.25/1.30 = 0.192}. The override makes auto-block reachable
 * <em>only</em> on the dispositive signal — the conservative direction.
 *
 * <p><b>Complexity.</b> {@code Θ(1)} — a fixed eight-term sum; no allocation in
 * the override path, one 8-element list on the weighted-average path.
 *
 * <p>Stateless and side-effect free; {@code @ApplicationScoped} so it can be
 * injected by {@link ThreatAnalyzer}, but equally usable via {@code new}.
 */
@ApplicationScoped
public class RulesEngine {

    /**
     * Evaluate the eight §7 indicators for one input.
     *
     * <p>Postcondition: {@code 0.0 <= result.ruleScore() <= 1.0}, and when
     * {@code !result.dispositive()} then
     * {@code result.ruleScore() <= RuleWeights.WEIGHTED_AVERAGE_CEILING} (0.827)
     * — in fact {@code <= RuleWeights.MAX_ATTAINABLE_NON_DISPOSITIVE} (0.635),
     * since the kit row is 0.0 on this path.
     *
     * @param input the eight indicator signals; must not be null
     * @return the rule score plus the dispositive flag and per-rule breakdown
     */
    public RuleResult evaluate(RuleInput input) {
        if (input == null) {
            throw new IllegalArgumentException("input must not be null");
        }

        // Stage 1 — dispositive override. A knownPhishingKit hit (which Lane C
        // sets ONLY on a dispositive-eligible marker match) short-circuits to 1.0.
        if (input.knownPhishingKit()) {
            return new RuleResult(1.0, true, List.of());
        }

        // Stage 2 — normalized weighted average: Σ(weight × ruleValue) / Σ(weights).
        List<RuleResult.RuleContribution> contributions = new ArrayList<>(8);
        double numerator = 0.0;

        numerator += add(contributions, "domainAge",
                RuleWeights.W_DOMAIN_AGE, input.domainAge().ruleValue());
        numerator += add(contributions, "sslValidity",
                RuleWeights.W_SSL_VALIDITY, input.sslValidity().ruleValue());
        numerator += add(contributions, "securityHeaders",
                RuleWeights.W_SECURITY_HEADERS,
                input.missingSecurityHeaders() ? RuleWeights.V_SECURITY_HEADERS_MISSING : 0.0);
        // knownPhishingKit is false here (else-branch); its weighted row is 0.0.
        numerator += add(contributions, "knownPhishingKit",
                RuleWeights.W_KNOWN_PHISHING_KIT, 0.0);
        numerator += add(contributions, "suspiciousFormAction",
                RuleWeights.W_SUSPICIOUS_FORM_ACTION,
                input.suspiciousFormAction() ? RuleWeights.V_SUSPICIOUS_FORM_ACTION : 0.0);
        numerator += add(contributions, "homoglyph",
                RuleWeights.W_HOMOGLYPH,
                input.homoglyphDetected() ? RuleWeights.V_HOMOGLYPH : 0.0);
        numerator += add(contributions, "hiddenIframes",
                RuleWeights.W_HIDDEN_IFRAMES,
                input.hiddenIframes() ? RuleWeights.V_HIDDEN_IFRAMES : 0.0);
        numerator += add(contributions, "redirectAnomaly",
                RuleWeights.W_REDIRECT_ANOMALY,
                input.redirectAnomaly() ? RuleWeights.V_REDIRECT_ANOMALY : 0.0);

        double ruleScore = numerator / RuleWeights.WEIGHT_SUM;
        return new RuleResult(ruleScore, false, contributions);
    }

    private static double add(
            List<RuleResult.RuleContribution> sink, String rule, double weight, double value) {
        double contribution = weight * value;
        sink.add(new RuleResult.RuleContribution(rule, weight, value, contribution));
        return contribution;
    }
}
