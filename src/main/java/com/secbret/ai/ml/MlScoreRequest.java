package com.secbret.ai.ml;

/**
 * Request to the ML scoring client, modelling the {@code ClassificationRequest} fields
 * from the gRPC contract (Part II §7 "gRPC Contract"):
 *
 * <pre>
 * message ClassificationRequest {
 *     string url              = 1;
 *     double rule_score       = 2;
 *     string tier1_findings_json = 3;
 *     string tier2_findings_json = 4;
 *     string tier3_findings_json = 5;
 * }
 * </pre>
 *
 * <p>This is the <b>stable Java contract</b>. Phase 4 Lane C replaces
 * {@link StubMlScoringClient} with a real {@code GrpcMlScoringClient} that maps
 * this record to a protobuf {@code ClassificationRequest} message; no callers
 * need to change.
 *
 * <p>All {@code *FindingsJson} fields are nullable — Tier 2 and Tier 3 findings
 * are not available until their respective scanners are wired (Lane C). The stub
 * client and the real gRPC client both treat null as an empty string.
 *
 * @param url               the normalised target URL (never null)
 * @param ruleScore         the rules-engine score in [0.0, 1.0]
 * @param tier1FindingsJson JSON-serialised Tier 1 findings, or null
 * @param tier2FindingsJson JSON-serialised Tier 2 findings, or null (Phase 4)
 * @param tier3FindingsJson JSON-serialised Tier 3 findings, or null (Lane C)
 */
public record MlScoreRequest(
        String url,
        double ruleScore,
        String tier1FindingsJson,
        String tier2FindingsJson,
        String tier3FindingsJson) {

    /** Compact constructor validates invariants. */
    public MlScoreRequest {
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("url must not be null or blank");
        }
        if (ruleScore < 0.0 || ruleScore > 1.0) {
            throw new IllegalArgumentException(
                    "ruleScore must be in [0.0, 1.0], got " + ruleScore);
        }
    }

    /**
     * Convenience factory: no tier findings yet (Tier 1-only scan path used until
     * Lane C delivers Tier 2/3 scanners).
     */
    public static MlScoreRequest ofRulesOnly(String url, double ruleScore) {
        return new MlScoreRequest(url, ruleScore, null, null, null);
    }
}
