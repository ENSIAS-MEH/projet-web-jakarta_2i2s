package com.secbret.ai;

/**
 * Auto-action outcome derived from {@code combinedScore} per Part II §7
 * "Auto-Action Thresholds":
 *
 * <pre>
 * combinedScore &gt;= AUTO_APPROVE_HIGH (0.95) -&gt; VERIFIED_MALICIOUS (auto-approved)
 * combinedScore &lt;= AUTO_APPROVE_LOW  (0.05) -&gt; VERIFIED_BENIGN    (auto-rejected)
 * otherwise                                  -&gt; PENDING_REVIEW      (human analyst)
 * </pre>
 *
 * <p>This is the automated disposition only. It is distinct from
 * {@code secbret_analysis.verdict} (the tentative BENIGN/SUSPICIOUS verdict, see
 * {@link ThreatDisposition}) and from the final analyst-owned verdict tables
 * ({@code user_report.verdict} / {@code security_team_review.final_verdict}).
 */
public enum AutoActionVerdict {
    VERIFIED_MALICIOUS,
    VERIFIED_BENIGN,
    PENDING_REVIEW
}
