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

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Tier 2 scanner: active HTML analysis via jsoup (Part II §B / Part III §2 / Part IV).
 *
 * <h2>What it checks</h2>
 * <ul>
 *   <li><strong>Forms</strong> — credential/password forms posting to an external origin
 *       ({@code suspiciousFormAction} signal, §7 weight 0.20 / rule value 0.8).</li>
 *   <li><strong>iframes</strong> — hidden iframes (zero or tiny dimensions, or
 *       {@code display:none} style; §7 weight 0.10 / rule value 0.7).</li>
 *   <li><strong>Homoglyphs</strong> — Unicode lookalike characters in the page text or
 *       document title that resemble ASCII brand names ({@code homoglyphDetected} signal,
 *       §7 weight 0.15 / rule value 0.9).</li>
 *   <li>Link counts (internal vs external), external domains, suspicious scripts,
 *       content size, login-form heuristic, brand-logo heuristic.</li>
 * </ul>
 *
 * <h2>Constraints (Part II §B scanner safety table)</h2>
 * <ul>
 *   <li>5-second connect + read timeout (mirrors Tier 1).</li>
 *   <li>5 MB response-size limit ({@code SCAN_MAX_RESPONSE_BYTES} env default = 5 242 880).</li>
 *   <li>jsoup parsing only; no JavaScript execution.</li>
 *   <li>SSRF scheme allowlist + deny-set enforced via {@link SsrfGuard} before fetch.</li>
 *   <li>Maximum 3 redirects (jsoup follows redirects internally; we post-validate).</li>
 * </ul>
 *
 * <h2>Failure contract (Decision #17)</h2>
 * Throws {@link ScanFailedException} on I/O error, SSRF block, or timeout.
 * The caller ({@link ScanExecutor}) marks the job FAILED. No retry.
 *
 * <h2>Homoglyph detection approach</h2>
 * We scan for Unicode characters in known confusable ranges that visually mimic ASCII
 * letters used in common brand names (e.g. Cyrillic а/е/о/р/с/х, Greek ο/ρ/α, etc.).
 * This is a heuristic — non-dispositive per §7 governance. A proper confusables table
 * (Unicode TR#39) would be Phase 7 scope.
 * ponytail: codepoint-range heuristic; upgrade to full Unicode TR#39 confusables when
 * false-positive pressure from Cyrillic-script legitimate sites is measured.
 */
@ApplicationScoped
public class Tier2Scanner {

    private static final Logger log = LoggerFactory.getLogger(Tier2Scanner.class);

    /** 5 MB limit per Part II §B / env SCAN_MAX_RESPONSE_BYTES. */
    static final int MAX_RESPONSE_BYTES = 5_242_880;
    /** Connect + read timeout in milliseconds, mirrors Tier 1. */
    static final int TIMEOUT_MS = 5_000;
    /** jsoup redirect cap. */
    private static final int MAX_REDIRECTS = 3;

    /**
     * Credential-related input field name substrings.
     * A form containing any of these is treated as a credential form.
     */
    private static final List<String> CREDENTIAL_FIELD_NAMES = List.of(
            "password", "passwd", "pass", "pwd", "credential", "secret", "pin", "cvv", "ssn"
    );

    /**
     * Confusable Unicode codepoint ranges (Cyrillic + Greek lookalikes for Latin).
     * Presence of any codepoint in these ranges in the visible text triggers
     * {@code homoglyphDetected}.
     * ponytail: range list; replace with full TR#39 table when FP rate measured.
     */
    private static final int[][] HOMOGLYPH_RANGES = {
        // Cyrillic block: U+0400–U+04FF (contains а=U+0430, е=U+0435, о=U+043E, р=U+0440,
        // с=U+0441, х=U+0445 which are visually identical to Latin a, e, o, p, c, x)
        {0x0400, 0x04FF},
        // Greek block: U+0370–U+03FF (contains ο=U+03BF, ρ=U+03C1, α=U+03B1, etc.)
        {0x0370, 0x03FF},
        // Latin Extended Additional U+1E00–U+1EFF (many lookalike diacritics)
        {0x1E00, 0x1EFF},
    };

    private final PinnedHttpConnector connector;

    @Inject
    public Tier2Scanner(PinnedHttpConnector connector) {
        this.connector = connector;
    }

    /** No-arg constructor for CDI proxying. */
    protected Tier2Scanner() {
        this.connector = null;
    }

    // =========================================================================
    // Public API
    // =========================================================================

    /**
     * Result returned by {@link #scan(String)}.
     *
     * @param findings   the populated {@link Tier2Findings} DTO
     */
    public record ScanOutcome(Tier2Findings findings) {}

    /**
     * Fetch and parse the HTML at {@code normalizedUrl}, returning Tier 2 findings.
     *
     * @param normalizedUrl the normalized URL (Part II §C output)
     * @return {@link ScanOutcome} with a fully populated {@link Tier2Findings}
     * @throws ScanFailedException on SSRF block, timeout, or I/O error (Decision #17)
     */
    public ScanOutcome scan(String normalizedUrl) {
        URI uri;
        try {
            uri = URI.create(normalizedUrl);
        } catch (IllegalArgumentException e) {
            throw new ScanFailedException("Malformed URL for Tier 2: " + normalizedUrl, e);
        }

        // Full pin-and-connect fetch: scheme + deny-set validated and pinned per hop
        // (§B3) inside the connector — jsoup only parses the already-fetched bytes, so it
        // never re-resolves the host (no TOCTOU window).
        Document doc = fetchDocument(uri, normalizedUrl);
        Tier2Findings findings = analyse(doc, uri);

        log.debug("Tier2 scan complete for '{}': suspiciousFormAction={} hiddenIframes={} homoglyph={}",
                normalizedUrl, findings.isSuspiciousFormAction(),
                findings.isHasHiddenIframes(), findings.isHomoglyphDetected());
        return new ScanOutcome(findings);
    }

    // =========================================================================
    // Package-private for tests
    // =========================================================================

    /**
     * Exposed for unit tests: run analysis on a pre-parsed Document without SSRF/network.
     *
     * @param doc     pre-parsed jsoup Document
     * @param pageUrl base URL of the page (for origin comparisons)
     * @return ScanOutcome with populated findings
     */
    ScanOutcome analyseDirect(Document doc, String pageUrl) {
        URI uri;
        try {
            uri = URI.create(pageUrl);
        } catch (IllegalArgumentException e) {
            uri = URI.create("https://unknown.invalid/");
        }
        return new ScanOutcome(analyse(doc, uri));
    }

    // =========================================================================
    // Fetch
    // =========================================================================

    private Document fetchDocument(URI uri, String baseUrl) {
        PinnedResponse resp = connector.fetch(uri);
        // jsoup parses the already-fetched, pin-validated body. baseUrl anchors relative links.
        return Jsoup.parse(resp.body(), baseUrl);
    }

    // =========================================================================
    // Analysis
    // =========================================================================

    private Tier2Findings analyse(Document doc, URI pageUri) {
        Tier2Findings f = new Tier2Findings();

        String pageHost = pageUri.getHost() == null ? "" : pageUri.getHost().toLowerCase();

        // Content size (bytes of the raw HTML string as UTF-8 approximation).
        f.setContentSizeBytes(doc.html().getBytes(java.nio.charset.StandardCharsets.UTF_8).length);

        // --- Forms ---
        analyseFormsSection(doc, pageHost, f);

        // --- iframes ---
        analyseIframes(doc, f);

        // --- Links ---
        analyseLinks(doc, pageHost, f);

        // --- Scripts ---
        f.setSuspiciousScripts(doc.select("script[src]").size());

        // --- Heuristics ---
        f.setHasBrandLogo(doc.select("img[src*=logo], img[alt*=logo], img[class*=logo]").size() > 0);

        // --- Homoglyphs ---
        f.setHomoglyphDetected(detectHomoglyphs(doc));

        return f;
    }

    /**
     * Analyse all {@code <form>} elements. Sets {@code suspiciousFormAction} when a form
     * with credential input fields posts to a different origin than the page.
     */
    private void analyseFormsSection(Document doc, String pageHost, Tier2Findings f) {
        Elements formElements = doc.select("form");
        List<Tier2Findings.FormFinding> forms = new ArrayList<>();
        boolean hasLoginForm = false;
        boolean suspiciousFormAction = false;

        for (Element form : formElements) {
            Tier2Findings.FormFinding ff = new Tier2Findings.FormFinding();
            String action = form.attr("abs:action");
            String method = form.attr("method").toUpperCase();
            if (method.isEmpty()) {
                method = "GET";
            }
            ff.setAction(action.isEmpty() ? form.attr("action") : action);
            ff.setMethod(method);

            List<String> inputNames = new ArrayList<>();
            for (Element input : form.select("input")) {
                String name = input.attr("name").toLowerCase();
                String type = input.attr("type").toLowerCase();
                if (!name.isEmpty()) {
                    inputNames.add(name);
                }
                // Credential form if any input is type=password or name matches credential list.
                if ("password".equals(type) || isCredentialFieldName(name)) {
                    hasLoginForm = true;
                    // Suspicious if posting to a different host (§7 suspiciousFormAction).
                    if ("POST".equals(method) && isExternalAction(action, pageHost)) {
                        suspiciousFormAction = true;
                    }
                }
            }
            ff.setInputFields(inputNames);
            forms.add(ff);
        }

        f.setForms(forms);
        f.setHasLoginForm(hasLoginForm);
        f.setSuspiciousFormAction(suspiciousFormAction);
    }

    private boolean isCredentialFieldName(String name) {
        for (String keyword : CREDENTIAL_FIELD_NAMES) {
            if (name.contains(keyword)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns true when the form action resolves to a different host than the page.
     * Empty / relative action → same origin → false.
     */
    private boolean isExternalAction(String absAction, String pageHost) {
        if (absAction == null || absAction.isBlank()) {
            return false;
        }
        try {
            URI actionUri = URI.create(absAction);
            String actionHost = actionUri.getHost();
            if (actionHost == null) {
                return false;
            }
            return !actionHost.equalsIgnoreCase(pageHost);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Detect hidden iframes (zero/tiny dimensions or display:none).
     * Sets {@code hasHiddenIframes} and {@code hiddenIframes} count on the findings.
     */
    private void analyseIframes(Document doc, Tier2Findings f) {
        Elements iframes = doc.select("iframe");
        int hiddenCount = 0;
        for (Element iframe : iframes) {
            if (isHidden(iframe)) {
                hiddenCount++;
            }
        }
        f.setHiddenIframes(hiddenCount);
        f.setHasHiddenIframes(hiddenCount > 0);
    }

    /** Returns true when an element is styled/attributed to be invisible. */
    private boolean isHidden(Element el) {
        String style = el.attr("style").toLowerCase();
        if (style.contains("display:none") || style.contains("display: none")
                || style.contains("visibility:hidden") || style.contains("visibility: hidden")) {
            return true;
        }
        // Width/height of 0 or 1px.
        String w = el.attr("width");
        String h = el.attr("height");
        return isZeroOrOne(w) || isZeroOrOne(h);
    }

    private boolean isZeroOrOne(String dim) {
        if (dim == null || dim.isBlank()) {
            return false;
        }
        String d = dim.trim().replaceAll("px$", "");
        return "0".equals(d) || "1".equals(d);
    }

    /** Count internal vs external links and collect distinct external domains. */
    private void analyseLinks(Document doc, String pageHost, Tier2Findings f) {
        Elements anchors = doc.select("a[href]");
        int internal = 0;
        int external = 0;
        List<String> externalDomains = new ArrayList<>();

        for (Element a : anchors) {
            String href = a.attr("abs:href");
            if (href.isBlank()) {
                internal++;
                continue;
            }
            try {
                URI linkUri = URI.create(href);
                String linkHost = linkUri.getHost();
                if (linkHost == null || linkHost.equalsIgnoreCase(pageHost)) {
                    internal++;
                } else {
                    external++;
                    String domain = linkHost.toLowerCase();
                    if (!externalDomains.contains(domain)) {
                        externalDomains.add(domain);
                    }
                }
            } catch (IllegalArgumentException e) {
                internal++; // treat malformed hrefs as internal
            }
        }

        Tier2Findings.LinkCounts lc = new Tier2Findings.LinkCounts();
        lc.setInternal(internal);
        lc.setExternal(external);
        f.setLinks(lc);
        f.setExternalDomains(externalDomains);
    }

    /**
     * Detect homoglyph / lookalike Unicode characters in the document's visible text
     * and title (Part II §7 homoglyphDetected rule).
     *
     * <p>Scans the page title and body text for codepoints in known confusable ranges.
     * This is a heuristic — non-dispositive per governance rules.
     */
    private boolean detectHomoglyphs(Document doc) {
        // Check title and the first 10 000 chars of body text to bound cost.
        String title = doc.title();
        String bodyText = doc.body() != null ? doc.body().text() : "";
        // ponytail: truncate to 10k chars; full scan when CPU budget measured.
        String sample = (title + " " + bodyText);
        int limit = Math.min(sample.length(), 10_000);

        for (int i = 0; i < limit; ) {
            int cp = sample.codePointAt(i);
            if (isConfusable(cp)) {
                return true;
            }
            i += Character.charCount(cp);
        }
        return false;
    }

    private boolean isConfusable(int codepoint) {
        for (int[] range : HOMOGLYPH_RANGES) {
            if (codepoint >= range[0] && codepoint <= range[1]) {
                return true;
            }
        }
        return false;
    }
}
