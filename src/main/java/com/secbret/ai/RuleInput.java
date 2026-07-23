package com.secbret.ai;

/**
 * The eight indicator signals consumed by the {@link RulesEngine}, per the
 * Part II §7 rule table. Each field is the <em>raw signal</em>; the engine maps
 * signals to per-rule values ({@link RuleWeights}) so the §7 value mapping lives
 * in exactly one place.
 *
 * <p>Multi-valued signals (domain age, SSL) are modelled as enums so illegal
 * states are unrepresentable; boolean signals map to their single non-zero rule
 * value when true and to {@code 0.0} when false.
 *
 * <p>{@code knownPhishingKit} is the <b>dispositive boolean</b>. Per the
 * "Phishing-Kit Marker Governance" section it may be {@code true} only when a
 * <em>dispositive-eligible</em> marker matched (Tier 3 / Lane C supplies it);
 * this engine merely consumes the boolean and does not judge marker eligibility.
 * When {@code true} it fires the Stage 1 override ({@code ruleScore = 1.0}).
 *
 * @param domainAge          age band of the registered domain
 * @param sslValidity        TLS certificate validity classification
 * @param missingSecurityHeaders true when CSP+HSTS+XFO are all absent (§7: 0.6)
 * @param knownPhishingKit   dispositive marker matched (§7: 1.0, fires override)
 * @param suspiciousFormAction true when a form posts to an external origin (§7: 0.8)
 * @param homoglyphDetected  true when homoglyph/lookalike characters found (§7: 0.9)
 * @param hiddenIframes      true when hidden iframes found (§7: 0.7)
 * @param redirectAnomaly    true when &gt;3 redirects or the target differs (§7: 0.5)
 */
public record RuleInput(
        DomainAge domainAge,
        SslValidity sslValidity,
        boolean missingSecurityHeaders,
        boolean knownPhishingKit,
        boolean suspiciousFormAction,
        boolean homoglyphDetected,
        boolean hiddenIframes,
        boolean redirectAnomaly) {

    public RuleInput {
        if (domainAge == null) {
            throw new IllegalArgumentException("domainAge must not be null");
        }
        if (sslValidity == null) {
            throw new IllegalArgumentException("sslValidity must not be null");
        }
    }

    /**
     * All-false/unknown input: used when no prior scan data is available (incident
     * submitted without a prior Tier 1 scan — Part III §3). Runs the rules engine
     * with every indicator at its lowest-risk value, producing a degraded score.
     */
    public static RuleInput allFalse() {
        return new RuleInput(
                DomainAge.ESTABLISHED_OR_UNKNOWN,
                SslValidity.VALID,
                false, false, false, false, false, false);
    }

    /** Domain-age band. §7: &lt;7d = 0.8, &lt;30d = 0.5, &gt;1yr = 0.0. */
    public enum DomainAge {
        /** Registered less than 7 days ago. Rule value 0.8. */
        UNDER_7_DAYS(0.8),
        /** Registered 7 to 30 days ago. Rule value 0.5. */
        UNDER_30_DAYS(0.5),
        /**
         * Between 30 days and 1 year, or age unknown. Rule value 0.0.
         *
         * <p>§7 specifies only the three named bands; the 30d–1yr gap and the
         * "unknown age" case both map to 0.0 (no age-based suspicion). Recorded
         * as a deliberate literal reading of the §7 table.
         */
        ESTABLISHED_OR_UNKNOWN(0.0),
        /** Older than one year. Rule value 0.0. */
        OVER_1_YEAR(0.0);

        private final double ruleValue;

        DomainAge(double ruleValue) {
            this.ruleValue = ruleValue;
        }

        public double ruleValue() {
            return ruleValue;
        }
    }

    /** SSL validity classification. §7: self-signed = 0.7, expired = 0.9, valid = 0.0. */
    public enum SslValidity {
        /** Certificate chains to a trusted CA and is in-date. Rule value 0.0. */
        VALID(0.0),
        /** Self-signed certificate. Rule value 0.7. */
        SELF_SIGNED(0.7),
        /** Expired certificate. Rule value 0.9. */
        EXPIRED(0.9);

        private final double ruleValue;

        SslValidity(double ruleValue) {
            this.ruleValue = ruleValue;
        }

        public double ruleValue() {
            return ruleValue;
        }
    }
}
