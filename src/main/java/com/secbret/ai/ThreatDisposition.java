package com.secbret.ai;

import java.util.OptionalDouble;

/**
 * The complete outcome of {@link ThreatAnalyzer}: the blended combined score,
 * the two derived verdicts, and provenance of the ML consultation.
 *
 * @param ruleResult      the underlying rules outcome (score + dispositive flag)
 * @param combinedScore   the §7 combined score in [0.0, 1.0]: {@code ruleScore}
 *                        outside the consultation band or on ML fallback,
 *                        otherwise {@code 0.4*ruleScore + 0.6*mlScore}
 * @param mlConsulted     true when the ML sidecar was called <em>and</em>
 *                        answered (blend applied); false for the rules-only path
 *                        (band boundary, or timeout / breaker OPEN)
 * @param mlScore         the mlScore that was blended, present iff
 *                        {@code mlConsulted} — mirrors {@code ml_consulted}
 *                        provenance for {@code secbret_analysis}
 * @param autoAction      the auto-action disposition (§7 thresholds)
 * @param tentativeVerdict the BENIGN/SUSPICIOUS tentative verdict for
 *                        {@code secbret_analysis.verdict}
 * @param modelVersion    the ML sidecar {@code model_version} when the ML
 *                        sidecar contributed, else {@code null} (rules-only path
 *                        has no version — §7 ML Model Version Tracking). Set by
 *                        {@link com.secbret.ai.ScoringService}, which is the only
 *                        component that sees the sidecar response; persisted to
 *                        {@code secbret_analysis.model_version}.
 */
public record ThreatDisposition(
        RuleResult ruleResult,
        double combinedScore,
        boolean mlConsulted,
        OptionalDouble mlScore,
        AutoActionVerdict autoAction,
        TentativeVerdict tentativeVerdict,
        String modelVersion) {

    /**
     * Return a copy with {@code modelVersion} set. Used by {@code ScoringService}
     * to attach the sidecar's version after {@link ThreatAnalyzer} produces the
     * (version-less) disposition, without threading the version through the
     * {@code MlConsultation} seam.
     */
    public ThreatDisposition withModelVersion(String modelVersion) {
        return new ThreatDisposition(
                ruleResult, combinedScore, mlConsulted, mlScore,
                autoAction, tentativeVerdict, modelVersion);
    }
}
