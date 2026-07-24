package com.secbret.ai;

import static org.assertj.core.api.Assertions.assertThat;

import com.secbret.ai.RuleInput.DomainAge;
import com.secbret.ai.RuleInput.SslValidity;
import java.util.OptionalDouble;
import org.assertj.core.data.Offset;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The Part II §7 <b>reachable-range invariant test (required)</b>. Proves each of
 * the three auto-action verdicts is attainable and guards against silent
 * re-introduction of the B1/B2 unreachable-threshold bug (the "Scoring cap" trap
 * in HANDOFF.md):
 *
 * <ul>
 *   <li>(a) a dispositive-signal input reaches {@code combined >= 0.95} → VERIFIED_MALICIOUS;
 *   <li>(b) an all-clean input reaches {@code combined <= 0.05} → VERIFIED_BENIGN;
 *   <li>(c) a mid-range input reaches PENDING_REVIEW;
 *   <li>and the <b>non-dispositive weighted-average path never exceeds 0.827</b>.
 * </ul>
 */
class ReachableRangeInvariantTest {

    private static final Offset<Double> EPS = Offset.offset(1e-9);

    private final RulesEngine engine = new RulesEngine();
    // Explicit default boundaries so the invariant does not depend on the environment.
    private final ThreatAnalyzer analyzer = new ThreatAnalyzer(engine, 0.05, 0.95);

    private static RuleInput allClean() {
        return new RuleInput(
                DomainAge.OVER_1_YEAR, SslValidity.VALID,
                false, false, false, false, false, false);
    }

    @Test
    @DisplayName("(a) dispositive kit hit → combined >= 0.95 → VERIFIED_MALICIOUS")
    void dispositive_reachesVerifiedMalicious() {
        RuleInput kit = new RuleInput(
                DomainAge.OVER_1_YEAR, SslValidity.VALID,
                false, true, false, false, false, false);

        // Even with ML unavailable, the dispositive override alone reaches auto-block.
        ThreatDisposition d = analyzer.analyze(kit, MlConsultation.unavailable());

        assertThat(d.ruleResult().dispositive()).isTrue();
        assertThat(d.combinedScore()).isEqualTo(1.0);
        assertThat(d.combinedScore()).isGreaterThanOrEqualTo(0.95);
        assertThat(d.autoAction()).isEqualTo(AutoActionVerdict.VERIFIED_MALICIOUS);
        // Tentative verdict is SUSPICIOUS even on the dispositive path (§7 normative).
        assertThat(d.tentativeVerdict()).isEqualTo(TentativeVerdict.SUSPICIOUS);
        // ML is NOT consulted: score is already extreme (outside the open band).
        assertThat(d.mlConsulted()).isFalse();
    }

    @Test
    @DisplayName("(b) all-clean input → combined <= 0.05 → VERIFIED_BENIGN")
    void allClean_reachesVerifiedBenign() {
        ThreatDisposition d = analyzer.analyze(allClean(), MlConsultation.unavailable());

        assertThat(d.ruleResult().dispositive()).isFalse();
        assertThat(d.combinedScore()).isEqualTo(0.0);
        assertThat(d.combinedScore()).isLessThanOrEqualTo(0.05);
        assertThat(d.autoAction()).isEqualTo(AutoActionVerdict.VERIFIED_BENIGN);
        assertThat(d.tentativeVerdict()).isEqualTo(TentativeVerdict.BENIGN);
        assertThat(d.mlConsulted()).isFalse();
    }

    @Test
    @DisplayName("(c) mid-range input → PENDING_REVIEW")
    void midRange_reachesPendingReview() {
        // A single suspicious form action: 0.20*0.8/1.30 = 0.123 — inside the band.
        RuleInput mid = new RuleInput(
                DomainAge.OVER_1_YEAR, SslValidity.VALID,
                false, false, true, false, false, false);

        ThreatDisposition d = analyzer.analyze(mid, MlConsultation.unavailable());

        assertThat(d.combinedScore()).isGreaterThan(0.05).isLessThan(0.95);
        assertThat(d.autoAction()).isEqualTo(AutoActionVerdict.PENDING_REVIEW);
        assertThat(d.tentativeVerdict()).isEqualTo(TentativeVerdict.SUSPICIOUS);
    }

    @Test
    @DisplayName("non-dispositive weighted-average path never exceeds the 0.827 ceiling (B1/B2 guard)")
    void nonDispositivePath_cappedAt0827() {
        // Maximum non-kit input: every other indicator at its highest value.
        RuleInput worstNonKit = new RuleInput(
                DomainAge.UNDER_7_DAYS, SslValidity.EXPIRED,
                true, false, true, true, true, true);

        RuleResult result = engine.evaluate(worstNonKit);

        assertThat(result.dispositive()).isFalse();
        // The §7 required invariant: the non-dispositive path never exceeds 0.827.
        assertThat(result.ruleScore()).isLessThanOrEqualTo(RuleWeights.WEIGHTED_AVERAGE_CEILING);
        // Attained value with the kit row forced to 0.0: 0.825/1.30 = 0.634615…
        // (the spec's 0.827 ceiling includes the kit maximum, which fires the
        // override and so never flows through this path).
        assertThat(result.ruleScore()).isCloseTo(0.634615384615, EPS);
        // And it is well below 0.95: the non-dispositive path can never auto-block on rules alone.
        assertThat(result.ruleScore()).isLessThan(0.95);
    }

    @Test
    @DisplayName("even perfect ML cannot push a max non-dispositive rule score to auto-block")
    void perfectMl_stillBelowAutoBlock() {
        // Worst non-kit input scores 0.635 → inside the band → ML consulted.
        RuleInput worstNonKit = new RuleInput(
                DomainAge.UNDER_7_DAYS, SslValidity.EXPIRED,
                true, false, true, true, true, true);
        MlConsultation perfectMl = r -> OptionalDouble.of(1.0);

        ThreatDisposition d = analyzer.analyze(worstNonKit, perfectMl);

        // 0.4*0.634615 + 0.6*1.0 = 0.853846 < 0.95.
        assertThat(d.mlConsulted()).isTrue();
        assertThat(d.combinedScore()).isCloseTo(0.853846153846, Offset.offset(1e-9));
        assertThat(d.combinedScore()).isLessThan(0.95);
        assertThat(d.autoAction()).isEqualTo(AutoActionVerdict.PENDING_REVIEW);
    }
}
