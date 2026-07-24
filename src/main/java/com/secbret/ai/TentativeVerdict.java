package com.secbret.ai;

/**
 * The AI engine's tentative verdict written to {@code secbret_analysis.verdict}
 * (NOT NULL, constrained to BENIGN/SUSPICIOUS by {@code chk_analysis_verdict}),
 * per Part II §7 "Tentative-verdict derivation (normative)".
 *
 * <pre>
 * combinedScore &lt;= AUTO_APPROVE_LOW (0.05) -&gt; BENIGN
 * combinedScore &gt;  AUTO_APPROVE_LOW (0.05) -&gt; SUSPICIOUS
 * </pre>
 *
 * <p>This applies uniformly to all three {@link AutoActionVerdict} outcomes,
 * including the dispositive-override path ({@code combinedScore == 1.0} writes
 * SUSPICIOUS). The tentative verdict never carries {@code VERIFIED_*} values.
 */
public enum TentativeVerdict {
    BENIGN,
    SUSPICIOUS
}
