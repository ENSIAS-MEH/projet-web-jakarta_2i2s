package com.secbret.scanner;

import java.util.List;

/**
 * Versioned phishing-kit marker ruleset (Part II §7 Phishing-Kit Marker Governance).
 *
 * <p>This is the curated, version-tracked artifact mandated by the spec:
 * <ul>
 *   <li>Every ruleset change MUST be reviewed; changes that promote a dispositive-eligible
 *       marker MUST receive two-person review.</li>
 *   <li>Each analysis records {@link #version()} as {@code tier3_findings.kitRulesetVersion}
 *       so verdicts are traceable to the exact marker set.</li>
 * </ul>
 *
 * <p><strong>Singleton via CDI:</strong> The static {@link #CURRENT} instance is the
 * production ruleset. Tests may construct their own ruleset directly.
 *
 * <p><strong>Governance note (Part II §7 item 3):</strong> The version string uses
 * the format {@code YYYY.MM.revision} (e.g. {@code 2026.07.1}). Increment the
 * revision on any change; increment year/month on a calendar boundary.
 */
public record PhishingKitRuleset(
        /** Monotonically increasing version identifier, e.g. "2026.07.1". */
        String version,
        /** Ordered list of markers; order does not affect matching. */
        List<KitMarker> markers
) {

    /**
     * Production ruleset v1 — 2026.07.1.
     *
     * <p>Marker selection rationale (Part II §7 item 2 precision bar):
     * <ul>
     *   <li>KIT-0001 — dispositive: kit-unique constant "__kit_darkside_v19__" is a
     *       fabricated placeholder unique to this kit; near-zero FP on legitimate sites.</li>
     *   <li>KIT-0002 — dispositive: kit-unique path "/panel/admin_login_kit.php" that
     *       cannot plausibly occur on a legitimate site.</li>
     *   <li>KIT-0003 — NON-dispositive: generic credential-harvester keyword "harvester_id"
     *       is a weak heuristic — contributes evidence only, never fires the override.</li>
     *   <li>KIT-0004 — NON-dispositive: generic obfuscation pattern "eval(base64_decode"
     *       occurs on legitimate sites using minifiers; heuristic only.</li>
     * </ul>
     *
     * Phase 7 action item (ROADMAP §7): evaluate real phishing-kit corpus,
     * replace placeholder signatures with validated kit-unique artifacts,
     * measure precision per marker, demote any below the dispositive bar.
     */
    public static final PhishingKitRuleset CURRENT = new PhishingKitRuleset(
            "2026.07.1",
            List.of(
                    new KitMarker("KIT-0001", "DarkSide v19 kit constant",
                            "__kit_darkside_v19__", true),
                    new KitMarker("KIT-0002", "DarkSide admin panel path",
                            "/panel/admin_login_kit.php", true),
                    new KitMarker("KIT-0003", "Generic harvester marker",
                            "harvester_id", false),
                    new KitMarker("KIT-0004", "Generic base64 eval obfuscation",
                            "eval(base64_decode", false)
            )
    );
}
