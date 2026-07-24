package com.secbret.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.secbret.ai.RuleInput.DomainAge;
import com.secbret.ai.RuleInput.SslValidity;
import java.util.OptionalDouble;
import org.assertj.core.data.Offset;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** Unit tests for the §7 blend contract, consultation band, and fallback posture. */
class ThreatAnalyzerTest {

    private static final Offset<Double> EPS = Offset.offset(1e-9);

    private final RulesEngine engine = new RulesEngine();
    private final ThreatAnalyzer analyzer = new ThreatAnalyzer(engine, 0.05, 0.95);

    /** A mid-band input (single suspicious form action → 0.123). */
    private static RuleInput midBand() {
        return new RuleInput(
                DomainAge.OVER_1_YEAR, SslValidity.VALID,
                false, false, true, false, false, false);
    }

    @Nested
    @DisplayName("blend contract")
    class Blend {

        @Test
        @DisplayName("in-band: combined = 0.4*rule + 0.6*ml")
        void inBand_blends() {
            double rule = 0.20 * 0.8 / 1.30; // 0.12307…
            MlConsultation ml = r -> OptionalDouble.of(0.5);

            ThreatDisposition d = analyzer.analyze(midBand(), ml);

            assertThat(d.mlConsulted()).isTrue();
            assertThat(d.mlScore()).hasValue(0.5);
            assertThat(d.combinedScore())
                    .isCloseTo(0.4 * rule + 0.6 * 0.5, EPS);
        }

        @Test
        @DisplayName("blend weights are the compile-time constants 0.4 / 0.6")
        void blendConstants() {
            assertThat(ThreatAnalyzer.RULE_BLEND_WEIGHT).isEqualTo(0.4);
            assertThat(ThreatAnalyzer.ML_BLEND_WEIGHT).isEqualTo(0.6);
        }

        @Test
        @DisplayName("ml score out of [0,1] is clamped before blending")
        void mlScoreClamped() {
            MlConsultation tooHigh = r -> OptionalDouble.of(5.0);

            ThreatDisposition d = analyzer.analyze(midBand(), tooHigh);

            assertThat(d.mlScore()).hasValue(1.0);
        }
    }

    @Nested
    @DisplayName("consultation band (open interval, derived from AUTO_APPROVE_LOW/HIGH)")
    class Band {

        @Test
        @DisplayName("ruleScore <= LOW: ML not consulted, combined = ruleScore")
        void belowBand_noMl() {
            RuleInput allClean = new RuleInput(
                    DomainAge.OVER_1_YEAR, SslValidity.VALID,
                    false, false, false, false, false, false);
            // ML would say 1.0 but must be ignored — score already extreme.
            MlConsultation ml = r -> OptionalDouble.of(1.0);

            ThreatDisposition d = analyzer.analyze(allClean, ml);

            assertThat(d.mlConsulted()).isFalse();
            assertThat(d.combinedScore()).isEqualTo(0.0);
        }

        @Test
        @DisplayName("ruleScore >= HIGH (dispositive): ML not consulted")
        void aboveBand_noMl() {
            RuleInput kit = new RuleInput(
                    DomainAge.OVER_1_YEAR, SslValidity.VALID,
                    false, true, false, false, false, false);
            MlConsultation ml = r -> OptionalDouble.of(0.0);

            ThreatDisposition d = analyzer.analyze(kit, ml);

            assertThat(d.mlConsulted()).isFalse();
            assertThat(d.combinedScore()).isEqualTo(1.0);
        }

        @Test
        @DisplayName("band is derived from custom boundaries")
        void derivedBoundaries() {
            ThreatAnalyzer wide = new ThreatAnalyzer(engine, 0.20, 0.80);
            assertThat(wide.autoApproveLow()).isEqualTo(0.20);
            assertThat(wide.autoApproveHigh()).isEqualTo(0.80);

            // midBand rule score 0.123 < 0.20 → now below the widened band → no ML.
            ThreatDisposition d = wide.analyze(midBand(), r -> OptionalDouble.of(1.0));
            assertThat(d.mlConsulted()).isFalse();
        }
    }

    @Nested
    @DisplayName("rules-only fallback (B4)")
    class Fallback {

        @Test
        @DisplayName("ML unavailable in-band: combined = ruleScore, mlConsulted=false")
        void mlUnavailable_fallsBackToRules() {
            ThreatDisposition d = analyzer.analyze(midBand(), MlConsultation.unavailable());

            assertThat(d.mlConsulted()).isFalse();
            assertThat(d.mlScore()).isEmpty();
            assertThat(d.combinedScore()).isCloseTo(0.20 * 0.8 / 1.30, EPS);
            // Borderline → human review, never silent auto-benign.
            assertThat(d.autoAction()).isEqualTo(AutoActionVerdict.PENDING_REVIEW);
        }

        @Test
        @DisplayName("dispositive override still auto-blocks during ML outage")
        void dispositiveFiresDuringOutage() {
            RuleInput kit = new RuleInput(
                    DomainAge.OVER_1_YEAR, SslValidity.VALID,
                    false, true, false, false, false, false);

            ThreatDisposition d = analyzer.analyze(kit, MlConsultation.unavailable());

            assertThat(d.autoAction()).isEqualTo(AutoActionVerdict.VERIFIED_MALICIOUS);
        }
    }

    @Nested
    @DisplayName("verdict derivation")
    class Verdicts {

        @Test
        @DisplayName("combined == LOW boundary → VERIFIED_BENIGN / BENIGN")
        void atLowBoundary() {
            assertThat(analyzer.autoAction(0.05)).isEqualTo(AutoActionVerdict.VERIFIED_BENIGN);
            assertThat(analyzer.tentativeVerdict(0.05)).isEqualTo(TentativeVerdict.BENIGN);
        }

        @Test
        @DisplayName("combined just above LOW → PENDING_REVIEW / SUSPICIOUS")
        void justAboveLow() {
            assertThat(analyzer.autoAction(0.06)).isEqualTo(AutoActionVerdict.PENDING_REVIEW);
            assertThat(analyzer.tentativeVerdict(0.06)).isEqualTo(TentativeVerdict.SUSPICIOUS);
        }

        @Test
        @DisplayName("combined == HIGH boundary → VERIFIED_MALICIOUS / SUSPICIOUS")
        void atHighBoundary() {
            assertThat(analyzer.autoAction(0.95)).isEqualTo(AutoActionVerdict.VERIFIED_MALICIOUS);
            assertThat(analyzer.tentativeVerdict(0.95)).isEqualTo(TentativeVerdict.SUSPICIOUS);
        }
    }

    @Nested
    @DisplayName("construction guards")
    class Construction {

        @Test
        @DisplayName("rejects LOW >= HIGH")
        void rejectsInvertedBoundaries() {
            assertThatThrownBy(() -> new ThreatAnalyzer(engine, 0.9, 0.1))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("rejects out-of-range boundaries")
        void rejectsOutOfRange() {
            assertThatThrownBy(() -> new ThreatAnalyzer(engine, -0.1, 0.95))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> new ThreatAnalyzer(engine, 0.05, 1.1))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("rejects null ml consultation")
        void rejectsNullMl() {
            assertThatThrownBy(() -> analyzer.analyze(midBand(), null))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }
}
