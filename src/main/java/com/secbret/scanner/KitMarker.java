package com.secbret.scanner;

/**
 * A single phishing-kit marker/signature entry in the versioned ruleset.
 *
 * <p>Each marker carries an explicit {@code dispositiveEligible} boolean (Part II §7
 * Phishing-Kit Marker Governance item 2). Only a match on a dispositive-eligible
 * marker may set {@code knownPhishingKit = true} and thereby fire the Stage 1
 * dispositive override.
 *
 * <p>A marker MUST NOT be flagged dispositive-eligible unless it is near-zero-false-positive
 * by construction — qualified by either:
 * <ul>
 *   <li>an exact match on a kit-unique artifact (file hash, kit-unique path/resource
 *       fingerprint, or kit-unique string constant); or</li>
 *   <li>corroboration by ≥ 2 independent kit indicators on the same page.</li>
 * </ul>
 */
public record KitMarker(
        /** Stable marker identifier, e.g. "KIT-0042". */
        String id,
        /** Human-readable name for logging and audit. */
        String name,
        /**
         * Literal string to search for in the page source (case-sensitive).
         * The Tier3Scanner performs a simple {@code contains} check.
         */
        String signature,
        /**
         * When {@code true} a match fires the Stage 1 dispositive override
         * (knownPhishingKit = true). MUST only be set on near-zero-FP markers.
         * ponytail: simple contains match; upgrade to regex/hash when FP pressure warrants.
         */
        boolean dispositiveEligible
) {}
