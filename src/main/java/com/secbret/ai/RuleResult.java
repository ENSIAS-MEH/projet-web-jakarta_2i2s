package com.secbret.ai;

import java.util.List;

/**
 * Outcome of the {@link RulesEngine} for one {@link RuleInput}.
 *
 * @param ruleScore    the §7 {@code ruleScore} in [0.0, 1.0]. When
 *                     {@link #dispositive} is true this is exactly {@code 1.0};
 *                     otherwise it is the normalized weighted average, which is
 *                     provably {@code <= }{@link RuleWeights#WEIGHTED_AVERAGE_CEILING}
 *                     (0.827) — and in practice {@code <= 0.635}, since the kit
 *                     row is 0.0 whenever the override did not fire.
 * @param dispositive  true when the Stage 1 dispositive override fired (a
 *                     {@code knownPhishingKit} hit). The only path to
 *                     {@code ruleScore == 1.0}.
 * @param contributions per-rule {@code weight * ruleValue} breakdown, in §7 table
 *                     order, for traceability. Empty when the override fired
 *                     (Stage 2 was short-circuited and never evaluated).
 */
public record RuleResult(
        double ruleScore,
        boolean dispositive,
        List<RuleContribution> contributions) {

    public RuleResult {
        contributions = List.copyOf(contributions);
    }

    /**
     * One rule's contribution to the weighted-average numerator.
     *
     * @param rule        the indicator name (§7 table)
     * @param weight      the relative weight from {@link RuleWeights}
     * @param ruleValue   the §7 value for this indicator's observed signal
     * @param contribution {@code weight * ruleValue}
     */
    public record RuleContribution(
            String rule, double weight, double ruleValue, double contribution) {}
}
