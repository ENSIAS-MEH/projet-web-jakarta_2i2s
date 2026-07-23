package com.secbret.ai;

/**
 * The Part II §7 rule table as compile-time constants: the eight indicator
 * weights and the per-indicator rule values for the boolean signals.
 *
 * <p>The weights are <b>unnormalized relative weights</b> that sum to
 * {@value #WEIGHT_SUM}, not 1.0 (§7 "Note"). The {@link RulesEngine} divides by
 * {@link #WEIGHT_SUM}, so normalization is handled by the formula, not here.
 *
 * <p><b>The 0.827 cap.</b> The eight per-indicator maxima are
 * {@code {0.8, 0.9, 0.6, 1.0, 0.8, 0.9, 0.7, 0.5}}, so the largest attainable
 * numerator is {@code 1.075} and the largest attainable weighted-average
 * {@code ruleScore} is {@code 1.075 / 1.30 = 0.826923…}. The
 * <em>dispositive override</em> (a {@code knownPhishingKit} hit) is the only
 * path to {@code ruleScore = 1.0}; see {@link RulesEngine} and the
 * reachable-range invariant test.
 */
public final class RuleWeights {

    private RuleWeights() {}

    // §7 rule weights (relative, unnormalized).
    public static final double W_DOMAIN_AGE = 0.30;
    public static final double W_SSL_VALIDITY = 0.15;
    public static final double W_SECURITY_HEADERS = 0.10;
    public static final double W_KNOWN_PHISHING_KIT = 0.25;
    public static final double W_SUSPICIOUS_FORM_ACTION = 0.20;
    public static final double W_HOMOGLYPH = 0.15;
    public static final double W_HIDDEN_IFRAMES = 0.10;
    public static final double W_REDIRECT_ANOMALY = 0.05;

    /** Sum of all eight relative weights: 1.30 (§7 "Note"). */
    public static final double WEIGHT_SUM =
            W_DOMAIN_AGE
                    + W_SSL_VALIDITY
                    + W_SECURITY_HEADERS
                    + W_KNOWN_PHISHING_KIT
                    + W_SUSPICIOUS_FORM_ACTION
                    + W_HOMOGLYPH
                    + W_HIDDEN_IFRAMES
                    + W_REDIRECT_ANOMALY;

    // §7 rule values for the boolean-signalled indicators (the "detected" value).
    public static final double V_SECURITY_HEADERS_MISSING = 0.6;
    public static final double V_KNOWN_PHISHING_KIT = 1.0;
    public static final double V_SUSPICIOUS_FORM_ACTION = 0.8;
    public static final double V_HOMOGLYPH = 0.9;
    public static final double V_HIDDEN_IFRAMES = 0.7;
    public static final double V_REDIRECT_ANOMALY = 0.5;

    /**
     * The §7 documented weighted-average <b>ceiling</b>: {@code 1.075 / 1.30 =
     * 0.826923…} ("0.827"). This is the value the rationale box derives by
     * plugging in <em>every</em> per-indicator maximum from
     * {@code {0.8, 0.9, 0.6, 1.0, 0.8, 0.9, 0.7, 0.5}} — <b>including the kit row
     * at 1.0</b>. It is the ceiling the reachable-range invariant asserts the
     * non-dispositive path never exceeds. Not a runtime clamp.
     *
     * <p>Note this ceiling is <em>not itself attainable</em> on the actual
     * non-dispositive path: a kit value of 1.0 fires the Stage 1 override and so
     * never flows through Stage 2. The genuinely attainable non-dispositive
     * maximum is {@link #MAX_ATTAINABLE_NON_DISPOSITIVE} — strictly below this
     * ceiling — which is exactly why the {@code ≤ 0.827} bound holds.
     */
    public static final double WEIGHTED_AVERAGE_CEILING = 1.075 / WEIGHT_SUM;

    /**
     * The maximum weighted-average {@code ruleScore} actually attainable on the
     * non-dispositive path (kit forced to 0.0, all seven other indicators at
     * their maxima): {@code 0.825 / 1.30 = 0.634615…}. Strictly below
     * {@link #WEIGHTED_AVERAGE_CEILING} (0.827) and far below the 0.95 auto-block
     * threshold — the B1/B2 conservative property.
     */
    public static final double MAX_ATTAINABLE_NON_DISPOSITIVE = 0.825 / WEIGHT_SUM;
}
