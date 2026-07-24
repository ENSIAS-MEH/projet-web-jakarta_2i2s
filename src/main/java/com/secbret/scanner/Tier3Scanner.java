package com.secbret.scanner;

import com.secbret.exception.ScanFailedException;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Tier 3 scanner: phishing-kit detection, outdated-library/CVE heuristics, open-redirect
 * detection (Part II §B / Part III §2 / Part IV).
 *
 * <h2>What it checks</h2>
 * <ul>
 *   <li><strong>Kit marker matching</strong> against the versioned {@link PhishingKitRuleset}.
 *       Only a match on a {@code dispositiveEligible} marker sets {@code knownPhishingKit}
 *       ({@code true}) per §7 Phishing-Kit Marker Governance. Non-dispositive matches are
 *       recorded in {@code kitMarkersMatched} but do not fire the Stage 1 override.</li>
 *   <li><strong>Outdated libraries and CVEs</strong> — heuristic detection of common
 *       vulnerable library versions referenced in {@code <script src>} or {@code <link href>}
 *       tags. Known CVE mappings for detected versions are recorded.</li>
 *   <li><strong>Open redirects</strong> — URL parameters named {@code redirect}, {@code url},
 *       {@code next}, {@code return}, {@code goto}, or {@code redir} with external values, or
 *       {@code <meta http-equiv=refresh>} pointing off-origin.</li>
 * </ul>
 *
 * <h2>Constraints</h2>
 * Same as Tier 2: 5s/5s timeouts, 5 MB limit, jsoup only, SSRF guard on every fetch.
 *
 * <h2>Failure contract (Decision #17)</h2>
 * Throws {@link ScanFailedException} on unrecoverable errors. No retry.
 *
 * <h2>kitRulesetVersion persistence</h2>
 * The version string from {@link PhishingKitRuleset#CURRENT} is always persisted in
 * {@code tier3_findings.kitRulesetVersion} so that verdicts are traceable (§7 item 1).
 * On version change, a WARN log is emitted (§7 / Part II §ML Model Version Tracking).
 */
@ApplicationScoped
public class Tier3Scanner {

    private static final Logger log = LoggerFactory.getLogger(Tier3Scanner.class);

    static final int TIMEOUT_MS = 5_000;
    static final int MAX_RESPONSE_BYTES = 5_242_880;

    /**
     * Known vulnerable library versions → CVE mappings.
     * Format: filename substring → CVE list.
     * ponytail: static map sufficient for v1; replace with NVD API or OSINT feed in Phase 7.
     */
    private static final Map<String, List<String>> CVE_MAP = Map.of(
            "jquery-1.6",      List.of("CVE-2011-4969", "CVE-2012-6708"),
            "jquery-1.7",      List.of("CVE-2012-6708"),
            "jquery-1.8",      List.of("CVE-2015-9251"),
            "jquery-1.9",      List.of("CVE-2015-9251"),
            "jquery-1.10",     List.of("CVE-2015-9251"),
            "jquery-1.11",     List.of("CVE-2015-9251", "CVE-2019-11358"),
            "jquery-1.12",     List.of("CVE-2015-9251", "CVE-2019-11358"),
            "jquery-2.0",      List.of("CVE-2015-9251", "CVE-2019-11358"),
            "jquery-2.1",      List.of("CVE-2019-11358"),
            "jquery-2.2",      List.of("CVE-2019-11358")
    );

    /** URL parameter names that commonly carry redirect targets. */
    private static final List<String> REDIRECT_PARAMS = List.of(
            "redirect", "url", "next", "return", "goto", "redir", "returnurl", "redirecturi"
    );

    private final PinnedHttpConnector connector;
    private final PhishingKitRuleset ruleset;

    @Inject
    public Tier3Scanner(PinnedHttpConnector connector) {
        this.connector = connector;
        this.ruleset = PhishingKitRuleset.CURRENT;
    }

    /** Package-private constructor for unit tests with a custom ruleset. */
    Tier3Scanner(PinnedHttpConnector connector, PhishingKitRuleset ruleset) {
        this.connector = connector;
        this.ruleset = ruleset;
    }

    /** No-arg constructor for CDI proxying. */
    protected Tier3Scanner() {
        this.connector = null;
        this.ruleset = PhishingKitRuleset.CURRENT;
    }

    // =========================================================================
    // Public API
    // =========================================================================

    /**
     * Result returned by {@link #scan(String, String)}.
     *
     * @param findings the populated {@link Tier3Findings} DTO
     */
    public record ScanOutcome(Tier3Findings findings) {}

    /**
     * Run Tier 3 analysis against {@code normalizedUrl}.
     *
     * @param normalizedUrl the normalized URL (Part II §C output)
     * @param pageHtml      the raw HTML fetched during Tier 2 (reused to avoid double-fetch);
     *                      if blank, a fresh fetch is performed with SSRF validation
     * @return {@link ScanOutcome} with a fully populated {@link Tier3Findings}
     * @throws ScanFailedException on SSRF block, timeout, or I/O error (Decision #17)
     */
    public ScanOutcome scan(String normalizedUrl, String pageHtml) {
        log.debug("Tier3 scan starting for '{}'", normalizedUrl);

        // Log WARN on ruleset version change so operators can correlate score shifts.
        // ponytail: version compared against no prior version here; Phase 7 adds DB-stored previous.
        log.info("Tier3 using kit ruleset version={}", ruleset.version());

        Document doc;
        if (pageHtml != null && !pageHtml.isBlank()) {
            doc = Jsoup.parse(pageHtml, normalizedUrl);
        } else {
            java.net.URI uri;
            try {
                uri = java.net.URI.create(normalizedUrl);
            } catch (IllegalArgumentException e) {
                throw new ScanFailedException("Malformed URL for Tier 3: " + normalizedUrl, e);
            }
            // Full pin-and-connect fetch (§B3): scheme + deny-set + pin + per-hop re-validate
            // all live in the connector. jsoup only parses the fetched bytes (no re-resolve).
            doc = Jsoup.parse(connector.fetch(uri).body(), normalizedUrl);
        }

        Tier3Findings findings = analyse(doc, normalizedUrl);
        log.info("Tier3 scan complete: knownPhishingKit={} cveMatches={} openRedirect={}",
                findings.isKnownPhishingKit(), findings.getCveMatches(), findings.isOpenRedirect());
        return new ScanOutcome(findings);
    }

    // =========================================================================
    // Analysis
    // =========================================================================

    private Tier3Findings analyse(Document doc, String normalizedUrl) {
        Tier3Findings f = new Tier3Findings();

        // Always record the ruleset version (§7 item 1 — REQUIRED).
        f.setKitRulesetVersion(ruleset.version());

        String html = doc.html();

        // --- Kit marker matching ---
        matchKitMarkers(html, f);

        // --- Outdated libraries + CVEs ---
        detectOutdatedLibraries(doc, f);

        // --- Open redirects ---
        f.setOpenRedirect(detectOpenRedirect(doc, normalizedUrl));

        return f;
    }

    /**
     * Match all markers in the ruleset against the page HTML.
     *
     * <p>Governance rule (§7 item 2): {@code knownPhishingKit = true} MUST be set ONLY
     * when at least one matched marker has {@code dispositiveEligible = true}. This method
     * enforces that invariant.
     */
    private void matchKitMarkers(String html, Tier3Findings f) {
        List<Tier3Findings.MarkerMatch> matched = new ArrayList<>();
        boolean anyDispositive = false;

        for (KitMarker marker : ruleset.markers()) {
            if (html.contains(marker.signature())) {
                log.debug("Kit marker matched: id={} dispositiveEligible={}", marker.id(), marker.dispositiveEligible());
                matched.add(new Tier3Findings.MarkerMatch(marker.id(), marker.dispositiveEligible()));
                if (marker.dispositiveEligible()) {
                    anyDispositive = true;
                    // Record the kit name from the first dispositive match.
                    if (f.getPhishingKitName() == null) {
                        f.setPhishingKitName(marker.name());
                    }
                }
            }
        }

        f.setKitMarkersMatched(matched);
        // Governance invariant: knownPhishingKit MUST be true only when a dispositive-eligible
        // marker matched (§7 item 2 + Part IV schema note).
        f.setKnownPhishingKit(anyDispositive);
    }

    /**
     * Detect outdated libraries by scanning {@code <script src>} and {@code <link href>}
     * attributes against the {@link #CVE_MAP} lookup.
     * ponytail: substring match on filename; upgrade to SRI hash matching in Phase 7.
     */
    private void detectOutdatedLibraries(Document doc, Tier3Findings f) {
        List<String> outdated = new ArrayList<>();
        List<String> cves = new ArrayList<>();

        Elements scripts = doc.select("script[src]");
        Elements links = doc.select("link[href]");

        List<String> srcs = new ArrayList<>();
        for (Element el : scripts) {
            srcs.add(el.attr("src").toLowerCase());
        }
        for (Element el : links) {
            srcs.add(el.attr("href").toLowerCase());
        }

        for (String src : srcs) {
            for (Map.Entry<String, List<String>> entry : CVE_MAP.entrySet()) {
                if (src.contains(entry.getKey())) {
                    if (!outdated.contains(entry.getKey())) {
                        outdated.add(entry.getKey());
                    }
                    for (String cve : entry.getValue()) {
                        if (!cves.contains(cve)) {
                            cves.add(cve);
                        }
                    }
                }
            }
        }

        f.setOutdatedLibraries(outdated);
        f.setCveMatches(cves);
    }

    /**
     * Detect open-redirect patterns:
     * <ol>
     *   <li>URL query parameters with redirect-like names pointing to external URLs.</li>
     *   <li>{@code <meta http-equiv="refresh">} pointing to an external domain.</li>
     * </ol>
     */
    private boolean detectOpenRedirect(Document doc, String normalizedUrl) {
        String pageHost;
        try {
            java.net.URI uri = java.net.URI.create(normalizedUrl);
            pageHost = uri.getHost() == null ? "" : uri.getHost().toLowerCase();
        } catch (IllegalArgumentException e) {
            pageHost = "";
        }

        // Check meta refresh redirect.
        Elements metaRefresh = doc.select("meta[http-equiv=refresh]");
        for (Element meta : metaRefresh) {
            String content = meta.attr("content");
            if (content.toLowerCase().contains("url=")) {
                String redirectTarget = content.substring(content.toLowerCase().indexOf("url=") + 4).trim();
                if (isExternalUrl(redirectTarget, pageHost)) {
                    return true;
                }
            }
        }

        // Check anchor hrefs with redirect params in query string.
        Elements anchors = doc.select("a[href]");
        for (Element a : anchors) {
            String href = a.attr("abs:href");
            if (href.isBlank()) {
                continue;
            }
            try {
                java.net.URI linkUri = java.net.URI.create(href);
                String query = linkUri.getQuery();
                if (query == null) {
                    continue;
                }
                for (String param : REDIRECT_PARAMS) {
                    if (query.toLowerCase().contains(param + "=")) {
                        // Extract the value.
                        int idx = query.toLowerCase().indexOf(param + "=");
                        String remainder = query.substring(idx + param.length() + 1);
                        int ampIdx = remainder.indexOf('&');
                        String val = ampIdx >= 0 ? remainder.substring(0, ampIdx) : remainder;
                        if (isExternalUrl(val, pageHost)) {
                            return true;
                        }
                    }
                }
            } catch (IllegalArgumentException e) {
                // Malformed href; skip.
            }
        }

        return false;
    }

    private boolean isExternalUrl(String target, String pageHost) {
        if (target == null || target.isBlank()) {
            return false;
        }
        // Decode common URL-encoding.
        String decoded = java.net.URLDecoder.decode(target, java.nio.charset.StandardCharsets.UTF_8);
        if (!decoded.startsWith("http://") && !decoded.startsWith("https://")) {
            return false;
        }
        try {
            java.net.URI uri = java.net.URI.create(decoded);
            String host = uri.getHost();
            return host != null && !host.equalsIgnoreCase(pageHost);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
