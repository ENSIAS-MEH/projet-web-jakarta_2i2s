package com.secbret.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.secbret.ai.RuleInput.DomainAge;
import com.secbret.ai.RuleInput.SslValidity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** Unit tests for the Part II §7 rules engine (Stage 1 override + Stage 2 weighted average). */
class RulesEngineTest {

    private static final double EPS = 1e-9;

    private final RulesEngine engine = new RulesEngine();

    /** All-clean input: every indicator at its 0.0 value. */
    private static RuleInput allClean() {
        return new RuleInput(
                DomainAge.OVER_1_YEAR, SslValidity.VALID,
                false, false, false, false, false, false);
    }

    @Nested
    @DisplayName("Stage 1 — dispositive override")
    class DispositiveOverride {

        @Test
        @DisplayName("knownPhishingKit short-circuits ruleScore to exactly 1.0")
        void kitHit_scoresOne() {
            RuleInput input = new RuleInput(
                    DomainAge.OVER_1_YEAR, SslValidity.VALID,
                    false, true, false, false, false, false);

            RuleResult result = engine.evaluate(input);

            assertThat(result.dispositive()).isTrue();
            assertThat(result.ruleScore()).isEqualTo(1.0);
        }

        @Test
        @DisplayName("override fires regardless of the other seven indicators")
        void kitHit_ignoresOtherSignals() {
            RuleInput input = new RuleInput(
                    DomainAge.UNDER_7_DAYS, SslValidity.EXPIRED,
                    true, true, true, true, true, true);

            RuleResult result = engine.evaluate(input);

            assertThat(result.dispositive()).isTrue();
            assertThat(result.ruleScore()).isEqualTo(1.0);
        }

        @Test
        @DisplayName("override short-circuits Stage 2 — no per-rule contributions computed")
        void kitHit_skipsWeightedAverage() {
            RuleResult result = engine.evaluate(new RuleInput(
                    DomainAge.OVER_1_YEAR, SslValidity.VALID,
                    false, true, false, false, false, false));

            assertThat(result.contributions()).isEmpty();
        }
    }

    @Nested
    @DisplayName("Stage 2 — normalized weighted average")
    class WeightedAverage {

        @Test
        @DisplayName("all-clean input yields exactly 0.0")
        void allClean_isZero() {
            RuleResult result = engine.evaluate(allClean());

            assertThat(result.dispositive()).isFalse();
            assertThat(result.ruleScore()).isEqualTo(0.0);
        }

        @Test
        @DisplayName("non-dispositive maximum is 0.635 (0.825/1.30) and stays under the 0.827 ceiling")
        void nonDispositiveMax_is0635_underCeiling() {
            // Every indicator at its highest NON-kit value (kit forced false).
            RuleInput input = new RuleInput(
                    DomainAge.UNDER_7_DAYS,   // 0.8
                    SslValidity.EXPIRED,      // 0.9
                    true,                     // headers 0.6
                    false,                    // NOT kit  -> row is 0.0
                    true,                     // form 0.8
                    true,                     // homoglyph 0.9
                    true,                     // iframe 0.7
                    true);                    // redirect 0.5

            RuleResult result = engine.evaluate(input);

            assertThat(result.dispositive()).isFalse();
            // Genuine non-dispositive max: 0.825/1.30 = 0.634615… (the kit row is 0.0).
            assertThat(result.ruleScore()).isCloseTo(0.634615384615, org.assertj.core.data.Offset.offset(1e-9));
            assertThat(result.ruleScore()).isEqualTo(RuleWeights.MAX_ATTAINABLE_NON_DISPOSITIVE);
            // Invariant: never exceeds the §7 documented ceiling (0.827).
            assertThat(result.ruleScore()).isLessThanOrEqualTo(RuleWeights.WEIGHTED_AVERAGE_CEILING);
        }

        @Test
        @DisplayName("single domain-age hit divides by Σ(weights)=1.30, not 1.0")
        void singleIndicator_normalizedByWeightSum() {
            // domainAge UNDER_7_DAYS: 0.30 * 0.8 = 0.24 numerator; /1.30 = 0.18461…
            RuleInput input = new RuleInput(
                    DomainAge.UNDER_7_DAYS, SslValidity.VALID,
                    false, false, false, false, false, false);

            RuleResult result = engine.evaluate(input);

            assertThat(result.ruleScore())
                    .isCloseTo(0.24 / 1.30, org.assertj.core.data.Offset.offset(EPS));
        }

        @Test
        @DisplayName("a non-dispositive kit-weight row alone would dilute to 0.192 — the B2 bug the override fixes")
        void kitWeightWithoutOverride_wouldDilute() {
            // Sanity anchor on the spec's arithmetic: 0.25/1.30 = 0.192. The engine
            // never produces this because a kit hit takes the Stage 1 path; this
            // documents WHY the override is needed.
            assertThat(RuleWeights.W_KNOWN_PHISHING_KIT / RuleWeights.WEIGHT_SUM)
                    .isCloseTo(0.192307692, org.assertj.core.data.Offset.offset(1e-9));
        }

        @Test
        @DisplayName("SSL self-signed maps to 0.7, expired to 0.9")
        void sslBands() {
            double selfSigned = engine.evaluate(new RuleInput(
                    DomainAge.OVER_1_YEAR, SslValidity.SELF_SIGNED,
                    false, false, false, false, false, false)).ruleScore();
            double expired = engine.evaluate(new RuleInput(
                    DomainAge.OVER_1_YEAR, SslValidity.EXPIRED,
                    false, false, false, false, false, false)).ruleScore();

            assertThat(selfSigned).isCloseTo(0.15 * 0.7 / 1.30, org.assertj.core.data.Offset.offset(EPS));
            assertThat(expired).isCloseTo(0.15 * 0.9 / 1.30, org.assertj.core.data.Offset.offset(EPS));
        }

        @Test
        @DisplayName("contributions list breaks down all 8 rows in §7 table order")
        void contributionsBreakdown() {
            RuleResult result = engine.evaluate(allClean());

            assertThat(result.contributions()).hasSize(8);
            assertThat(result.contributions())
                    .extracting(RuleResult.RuleContribution::rule)
                    .containsExactly(
                            "domainAge", "sslValidity", "securityHeaders", "knownPhishingKit",
                            "suspiciousFormAction", "homoglyph", "hiddenIframes", "redirectAnomaly");
        }
    }

    @Nested
    @DisplayName("weight table integrity")
    class WeightTable {

        @Test
        @DisplayName("the eight relative weights sum to 1.30")
        void weightsSumTo130() {
            assertThat(RuleWeights.WEIGHT_SUM).isCloseTo(1.30, org.assertj.core.data.Offset.offset(EPS));
        }
    }

    @Test
    @DisplayName("null input is rejected")
    void nullInput_rejected() {
        assertThatThrownBy(() -> engine.evaluate(null))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
