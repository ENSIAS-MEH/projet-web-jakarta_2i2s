package com.secbret.scanner;

import java.util.List;

/**
 * Typed DTO for the {@code tier3_findings} JSONB column (Part IV).
 *
 * <p>Canonical JSONB structure:
 * <pre>
 * {
 *   "knownPhishingKit": true,
 *   "phishingKitName": "v19_darkside",
 *   "kitRulesetVersion": "2026.07.1",
 *   "kitMarkersMatched": [{ "id": "KIT-0042", "dispositiveEligible": true }],
 *   "outdatedLibraries": ["jquery-1.6.3"],
 *   "cveMatches": ["CVE-2021-12345"],
 *   "openRedirect": false,
 *   "directoryListing": false
 * }
 * </pre>
 *
 * <p>{@code kitRulesetVersion} and {@code kitMarkersMatched} are REQUIRED whenever the
 * Tier 3 kit detector ran (Part II §7 Phishing-Kit Marker Governance / Part IV).
 * {@code knownPhishingKit} MUST be {@code true} only when at least one matched marker
 * has {@code dispositiveEligible: true}.
 */
public class Tier3Findings {

    /** True only when a dispositive-eligible marker matched (§7 governance rule). */
    private boolean knownPhishingKit;
    /** Name of the matched kit, if identified; null otherwise. */
    private String phishingKitName;
    /**
     * Version of the ruleset that produced this result (REQUIRED when kit detector ran).
     * Stored as {@code tier3_findings.kitRulesetVersion} per Part IV.
     */
    private String kitRulesetVersion;
    /**
     * All markers that matched (dispositive and non-dispositive alike).
     * REQUIRED when kit detector ran.
     */
    private List<MarkerMatch> kitMarkersMatched = List.of();
    /** Outdated JS/CSS libraries detected in page source (e.g. "jquery-1.6.3"). */
    private List<String> outdatedLibraries = List.of();
    /** CVE identifiers associated with detected outdated libraries. */
    private List<String> cveMatches = List.of();
    /** True when an open-redirect pattern was detected in URL parameters or meta-refresh. */
    private boolean openRedirect;
    /** True when directory listing was detected (not implemented in v1 — always false). */
    private boolean directoryListing;

    // =========================================================================
    // Nested type
    // =========================================================================

    /** A single matched marker entry recorded in {@code kitMarkersMatched}. */
    public static class MarkerMatch {
        private String id;
        private boolean dispositiveEligible;

        public MarkerMatch() {}

        public MarkerMatch(String id, boolean dispositiveEligible) {
            this.id = id;
            this.dispositiveEligible = dispositiveEligible;
        }

        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public boolean isDispositiveEligible() { return dispositiveEligible; }
        public void setDispositiveEligible(boolean dispositiveEligible) {
            this.dispositiveEligible = dispositiveEligible;
        }
    }

    // =========================================================================
    // Getters / setters
    // =========================================================================

    public boolean isKnownPhishingKit() { return knownPhishingKit; }
    public void setKnownPhishingKit(boolean knownPhishingKit) {
        this.knownPhishingKit = knownPhishingKit;
    }
    public String getPhishingKitName() { return phishingKitName; }
    public void setPhishingKitName(String phishingKitName) {
        this.phishingKitName = phishingKitName;
    }
    public String getKitRulesetVersion() { return kitRulesetVersion; }
    public void setKitRulesetVersion(String kitRulesetVersion) {
        this.kitRulesetVersion = kitRulesetVersion;
    }
    public List<MarkerMatch> getKitMarkersMatched() { return kitMarkersMatched; }
    public void setKitMarkersMatched(List<MarkerMatch> kitMarkersMatched) {
        this.kitMarkersMatched = kitMarkersMatched == null ? List.of() : kitMarkersMatched;
    }
    public List<String> getOutdatedLibraries() { return outdatedLibraries; }
    public void setOutdatedLibraries(List<String> outdatedLibraries) {
        this.outdatedLibraries = outdatedLibraries == null ? List.of() : outdatedLibraries;
    }
    public List<String> getCveMatches() { return cveMatches; }
    public void setCveMatches(List<String> cveMatches) {
        this.cveMatches = cveMatches == null ? List.of() : cveMatches;
    }
    public boolean isOpenRedirect() { return openRedirect; }
    public void setOpenRedirect(boolean openRedirect) { this.openRedirect = openRedirect; }
    public boolean isDirectoryListing() { return directoryListing; }
    public void setDirectoryListing(boolean directoryListing) {
        this.directoryListing = directoryListing;
    }
}
