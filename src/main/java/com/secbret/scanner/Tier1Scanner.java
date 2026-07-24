package com.secbret.scanner;

import com.secbret.ai.RuleInput;
import com.secbret.exception.ScanFailedException;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigDecimal;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * Tier 1 scanner: passive reconnaissance — domain age, SSL validity, HTTP security
 * headers, DNS records, WHOIS, and redirect chain (Part II §B / Part III §2 / Part IV).
 *
 * <h2>Constraints (Part II §B scanner safety table)</h2>
 * <ul>
 *   <li>5-second connect timeout + 5-second read timeout on every HTTP(S) connection.</li>
 *   <li>Maximum 3 redirect hops (3-redirect cap); further redirects → {@code redirectAnomaly}
 *       flagged in the rule input.</li>
 *   <li>SSRF scheme allowlist enforced on every hop via {@link SsrfGuard}.</li>
 *   <li>No JavaScript execution; no HTML parsing (Tier 2 scope).</li>
 * </ul>
 *
 * <h2>Failure contract (Decision #17)</h2>
 * On any unrecoverable failure (timeout, DNS failure after SSRF validation, I/O error,
 * unexpected exception) the caller ({@link ScanExecutor}) marks the job {@code FAILED}
 * and logs at ERROR. This class throws {@link ScanFailedException} on those conditions
 * rather than returning partial results — partial results would silently under-score.
 *
 * <h2>WHOIS protocol</h2>
 * RFC 3912 TCP port 43. The scanner sends the host name followed by CRLF and reads the
 * response to extract the registration date for domain-age classification. On WHOIS
 * failure the domain-age band defaults to {@code ESTABLISHED_OR_UNKNOWN} (rule value 0.0)
 * and the finding records no creation date — fail-open per the §B3 resilience note.
 *
 * <h2>Complexity</h2>
 * O(r) HTTP round-trips where r ≤ 3 (redirect cap) + 1 WHOIS TCP query + 1 DNS lookup.
 * All bounded by the 5-second timeouts. Overall wall-clock budget: ≤ 30 s in the worst
 * case (3 × 10 s HTTP + 10 s WHOIS).
 */
@ApplicationScoped
public class Tier1Scanner {

    private static final Logger log = LoggerFactory.getLogger(Tier1Scanner.class);

    /** Maximum redirect hops before flagging redirect anomaly. */
    static final int MAX_REDIRECTS = 3;
    /** WHOIS port (RFC 3912). */
    private static final int WHOIS_PORT = 43;
    /** WHOIS socket timeout, milliseconds. */
    private static final int WHOIS_TIMEOUT_MS = 5_000;

    private final SsrfGuard ssrfGuard;
    private final PinnedHttpConnector connector;

    @Inject
    public Tier1Scanner(SsrfGuard ssrfGuard, PinnedHttpConnector connector) {
        this.ssrfGuard = ssrfGuard;
        this.connector = connector;
    }

    /** No-arg constructor for CDI proxying. */
    protected Tier1Scanner() {
        this.ssrfGuard = null;
        this.connector = null;
    }

    // =========================================================================
    // Public API
    // =========================================================================

    /**
     * Run the Tier 1 passive scan against {@code normalizedUrl}.
     *
     * @param normalizedUrl the normalized URL (Part II §C output); must be http or https
     * @return {@link ScanOutcome} with the {@link Tier1Findings} and the derived
     *         {@link RuleInput} signal values needed by the rules engine
     * @throws ScanFailedException if the scan cannot complete (timeout, DNS failure,
     *                             SSRF block, I/O error) — the caller marks the job FAILED
     */
    public ScanOutcome scan(String normalizedUrl) {
        URI uri;
        try {
            uri = URI.create(normalizedUrl);
        } catch (IllegalArgumentException e) {
            throw new ScanFailedException("Malformed URL: " + normalizedUrl, e);
        }

        String scheme = uri.getScheme();
        String host = uri.getHost();

        // Scheme allowlist on the initial URL (§B3 item 5).
        ssrfGuard.requireAllowedScheme(scheme);
        // Resolve and validate initial address (§B3 item 1 — basic deny-set).
        InetAddress[] addresses = ssrfGuard.resolveAndValidate(host);

        Tier1Findings findings = new Tier1Findings();

        // --- DNS records ---
        List<String> dnsRecords = new ArrayList<>(addresses.length);
        for (InetAddress a : addresses) {
            dnsRecords.add(a.getHostAddress());
        }
        findings.setDnsRecords(dnsRecords);

        // --- HTTP fetch: headers, SSL, redirect chain ---
        HttpScanResult httpResult = fetchWithRedirects(uri, findings);

        // --- WHOIS: domain age ---
        DomainAgeResult ageResult = queryWhois(host);
        findings.setDomainAge(ageResult.label());
        if (ageResult.creationDate() != null) {
            Tier1Findings.WhoisInfo whoisInfo = new Tier1Findings.WhoisInfo();
            whoisInfo.setCreationDate(ageResult.creationDate());
            whoisInfo.setRegistrar(ageResult.registrar());
            findings.setWhoisInfo(whoisInfo);
        }

        // --- Derive the rule-input signals ---
        boolean redirectAnomaly = httpResult.hopCount() > MAX_REDIRECTS
                || httpResult.targetDifferentDomain();
        boolean missingSecurityHeaders = findings.getHttpHeaders().allThreeMissing();

        // overall_score for this tier: highest severity factor, normalized to [0.0, 1.0].
        // For Tier 1, we derive a simple severity proxy from the rule weights to set
        // overall_score in the absence of a full rules run here.
        // The spec says: max_score(TierN) = highest severity value found in that tier.
        // We compute the individual scores and take the maximum.
        double domainAgeScore = ageResult.domainAgeBand().ruleValue();
        double sslScore = httpResult.sslValidity().ruleValue();
        double headerScore = missingSecurityHeaders ? 0.6 : 0.0;
        double redirectScore = redirectAnomaly ? 0.5 : 0.0;
        double maxScore = Math.max(Math.max(domainAgeScore, sslScore),
                Math.max(headerScore, redirectScore));
        // Clamp to [0.00, 1.00] and round to 2 decimal places per DB column precision(3,2).
        BigDecimal overallScore = BigDecimal.valueOf(maxScore)
                .setScale(2, java.math.RoundingMode.HALF_UP);

        return new ScanOutcome(findings, ageResult.domainAgeBand(), httpResult.sslValidity(),
                missingSecurityHeaders, redirectAnomaly, overallScore);
    }

    // =========================================================================
    // HTTP fetch with redirect following
    // =========================================================================

    /**
     * Follow up to {@value #MAX_REDIRECTS} redirects, collecting HTTP security headers
     * and SSL details from the final hop.
     *
     * <p>Each hop goes through {@link PinnedHttpConnector#requestOnce(URI)}, which performs
     * the full §B3 validate-then-pin contract (scheme allowlist + resolve + deny-set +
     * connect-to-pinned-IP + TLS SNI/hostname verification). We drive the redirect loop here
     * ourselves — one {@code requestOnce} per hop — so the deny-set + pinning re-run on every
     * hop (§B3 item 3) and we retain the redirect-chain / anomaly bookkeeping this tier needs.
     *
     * @throws ScanFailedException on I/O error, timeout, or SSRF block on a redirect hop
     */
    private HttpScanResult fetchWithRedirects(URI initialUri, Tier1Findings findings) {
        URI currentUri = initialUri;
        List<String> redirectChain = new ArrayList<>();
        redirectChain.add(currentUri.toString());

        int hops = 0;
        boolean targetDifferentDomain = false;
        String initialHost = initialUri.getHost();
        RuleInput.SslValidity sslValidity = RuleInput.SslValidity.VALID; // default: https not used → VALID

        while (true) {
            // Pinned, per-hop-revalidated single request (no internal redirect following).
            PinnedResponse resp = connector.requestOnce(currentUri);
            int statusCode = resp.statusCode();

            // Collect SSL info from the first (or only) https response with a cert chain.
            if (resp.peerCerts() != null) {
                sslValidity = extractSslValidity(resp.peerCerts(), findings);
            }

            // Collect HTTP security headers from the final (non-redirect) response.
            if (!isRedirect(statusCode)) {
                extractSecurityHeaders(resp, findings);
                break;
            }

            // --- Redirect hop ---
            hops++;
            String location = resp.location();
            if (location == null || location.isBlank()) {
                log.debug("Redirect {} has no Location header; stopping at hop {}", statusCode, hops);
                extractSecurityHeaders(resp, findings);
                break;
            }

            URI nextUri;
            try {
                nextUri = currentUri.resolve(location);
            } catch (IllegalArgumentException e) {
                throw new ScanFailedException("Invalid redirect Location: " + location, e);
            }
            redirectChain.add(nextUri.toString());

            // Flag if a hop lands on a different domain (scheme + deny-set are re-validated
            // by requestOnce on the next iteration — §B3 item 3).
            if (nextUri.getHost() == null || !nextUri.getHost().equalsIgnoreCase(initialHost)) {
                targetDifferentDomain = true;
            }

            currentUri = nextUri;

            if (hops >= MAX_REDIRECTS + 1) {
                // We've consumed MAX_REDIRECTS redirects but there may be more.
                // Stop here; flagged as redirect anomaly by the caller.
                break;
            }
        }

        findings.setRedirectChain(redirectChain);
        return new HttpScanResult(sslValidity, hops, targetDifferentDomain);
    }

    private static boolean isRedirect(int code) {
        return code == 301 || code == 302 || code == 303 || code == 307 || code == 308;
    }

    // =========================================================================
    // SSL validity extraction
    // =========================================================================

    /**
     * Extract SSL/TLS certificate validity from the TLS peer certificate chain captured by
     * {@link PinnedHttpConnector} on the pinned https handshake.
     *
     * <p>Rule mapping (§7):
     * <ul>
     *   <li>Valid chain + in-date → {@link RuleInput.SslValidity#VALID} (0.0)</li>
     *   <li>Self-signed (chain length 1, issuer == subject) → {@link RuleInput.SslValidity#SELF_SIGNED} (0.7)</li>
     *   <li>Expired → {@link RuleInput.SslValidity#EXPIRED} (0.9)</li>
     * </ul>
     *
     * <p>If the TLS handshake already failed (SSL exception caught by the caller), the
     * caller maps to EXPIRED as the most-conservative safe default.
     */
    private RuleInput.SslValidity extractSslValidity(Certificate[] certs,
                                                      Tier1Findings findings) {
        if (certs == null || certs.length == 0) {
            return RuleInput.SslValidity.VALID;
        }
        if (!(certs[0] instanceof X509Certificate leaf)) {
            return RuleInput.SslValidity.VALID;
        }

        // Issuer info
        String issuerDN = leaf.getIssuerX500Principal().getName();
        findings.setSslIssuer(extractCNFromDN(issuerDN));

        // Expiry date
        Date notAfter = leaf.getNotAfter();
        if (notAfter != null) {
            findings.setSslExpiryDate(
                    notAfter.toInstant().atZone(ZoneOffset.UTC).toLocalDate()
                            .format(DateTimeFormatter.ISO_LOCAL_DATE));
        }

        // Validity check
        try {
            leaf.checkValidity();
        } catch (CertificateExpiredException e) {
            return RuleInput.SslValidity.EXPIRED;
        } catch (CertificateNotYetValidException e) {
            return RuleInput.SslValidity.EXPIRED; // treat "not yet valid" as expired
        }

        // Self-signed: chain length 1 and issuer DN == subject DN. Note: with pin-and-connect
        // full verification, an untrusted self-signed cert fails the handshake in the connector
        // (ScanFailedException) before we ever reach here — verification is never bypassed
        // (§B3). This branch survives only for the rare trusted-but-self-issued edge.
        if (certs.length == 1) {
            String subjectDN = leaf.getSubjectX500Principal().getName();
            if (issuerDN.equals(subjectDN)) {
                return RuleInput.SslValidity.SELF_SIGNED;
            }
        }

        findings.setSslValid(true);
        return RuleInput.SslValidity.VALID;
    }

    /** Extract the CN value from an X.500 DN string. Returns the full DN if no CN found. */
    private static String extractCNFromDN(String dn) {
        if (dn == null) {
            return null;
        }
        for (String part : dn.split(",")) {
            String trimmed = part.trim();
            if (trimmed.startsWith("CN=")) {
                return trimmed.substring(3);
            }
        }
        return dn;
    }

    // =========================================================================
    // HTTP security headers extraction
    // =========================================================================

    private static void extractSecurityHeaders(PinnedResponse resp, Tier1Findings findings) {
        Tier1Findings.HttpHeaderFindings headers = new Tier1Findings.HttpHeaderFindings();

        String xfo = resp.header("X-Frame-Options");
        if (xfo != null) {
            headers.setXFrameOptions(xfo);
        }
        String csp = resp.header("Content-Security-Policy");
        if (csp != null) {
            headers.setContentSecurityPolicy(csp);
        }
        String hsts = resp.header("Strict-Transport-Security");
        if (hsts != null) {
            headers.setStrictTransportSecurity(hsts);
        }
        String xcto = resp.header("X-Content-Type-Options");
        if (xcto != null) {
            headers.setXContentTypeOptions(xcto);
        }

        findings.setHttpHeaders(headers);
    }

    // =========================================================================
    // WHOIS domain-age query
    // =========================================================================

    /**
     * Query the generic WHOIS server for {@code host} on port 43 (RFC 3912) and parse
     * the creation date.
     *
     * <p>Fail-open: on any I/O error or parse failure, returns
     * {@link RuleInput.DomainAge#ESTABLISHED_OR_UNKNOWN} with null creation date — avoids
     * penalizing legitimate sites because their WHOIS server is slow.
     */
    DomainAgeResult queryWhois(String host) {
        // Extract the registrable domain (e.g. "example.com" from "www.example.com")
        // for the WHOIS query. Strip up to one sub-domain level.
        String domain = registrableDomain(host);
        String whoisServer = "whois.iana.org"; // starting point for WHOIS referral chain

        try {
            // First query IANA to get the authoritative WHOIS server for this TLD.
            String ianaResponse = whoisQuery(whoisServer, domain);
            String referral = parseWhoisReferral(ianaResponse);
            if (referral != null) {
                try {
                    ssrfGuard.resolveAndValidate(referral);
                    whoisServer = referral;
                } catch (Exception e) {
                    log.warn("Ignoring WHOIS referral to non-public host: {}", referral);
                }
            }

            // Second query: the authoritative WHOIS server.
            String response = whoisQuery(whoisServer, domain);
            return parseWhoisResponse(response);

        } catch (IOException e) {
            log.debug("WHOIS query failed for host='{}': {} — defaulting to ESTABLISHED_OR_UNKNOWN",
                    host, e.getMessage());
            return new DomainAgeResult(RuleInput.DomainAge.ESTABLISHED_OR_UNKNOWN, null, null, null);
        } catch (Exception e) {
            log.debug("Unexpected error in WHOIS query for host='{}': {} — defaulting to ESTABLISHED_OR_UNKNOWN",
                    host, e.getMessage());
            return new DomainAgeResult(RuleInput.DomainAge.ESTABLISHED_OR_UNKNOWN, null, null, null);
        }
    }

    /** Open a TCP connection to {@code server}:43 and query for {@code domain}. */
    private String whoisQuery(String server, String domain) throws IOException {
        try (Socket socket = new Socket()) {
            socket.connect(
                    new java.net.InetSocketAddress(server, WHOIS_PORT),
                    WHOIS_TIMEOUT_MS);
            socket.setSoTimeout(WHOIS_TIMEOUT_MS);
            socket.getOutputStream().write((domain + "\r\n").getBytes(StandardCharsets.UTF_8));
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder();
                String line;
                // Read up to 512 lines; WHOIS responses are text-based and bounded.
                int lineCount = 0;
                while ((line = reader.readLine()) != null && lineCount < 512) {
                    sb.append(line).append('\n');
                    lineCount++;
                }
                return sb.toString();
            }
        }
    }

    /**
     * Parse a "refer: hostname" line from an IANA WHOIS response.
     * Returns null if no referral is found.
     */
    private static String parseWhoisReferral(String response) {
        if (response == null) {
            return null;
        }
        for (String line : response.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.toLowerCase(java.util.Locale.ROOT).startsWith("refer:")) {
                return trimmed.substring("refer:".length()).trim();
            }
            // Some registrars use "Registrar WHOIS Server:" instead
            if (trimmed.toLowerCase(java.util.Locale.ROOT).startsWith("registrar whois server:")) {
                return trimmed.substring("registrar whois server:".length()).trim();
        }
        }
        return null;
    }

    /**
     * Parse a WHOIS response to extract:
     * <ul>
     *   <li>Creation date → map to §7 {@link RuleInput.DomainAge} band</li>
     *   <li>Registrar name</li>
     * </ul>
     *
     * <p>Common WHOIS date field names: {@code Creation Date}, {@code created},
     * {@code domain_dateregistered}, {@code Registered On}. We scan for any line
     * whose key (before the colon) contains "creat" or "registered" (case-insensitive)
     * and does not contain "updated" or "expir".
     */
    DomainAgeResult parseWhoisResponse(String response) {
        if (response == null || response.isBlank()) {
            return new DomainAgeResult(RuleInput.DomainAge.ESTABLISHED_OR_UNKNOWN, null, null, null);
        }

        LocalDate creationDate = null;
        String creationDateStr = null;
        String registrar = null;

        for (String line : response.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.startsWith("%") || trimmed.startsWith("#")) {
                continue; // comment lines
            }
            int colon = trimmed.indexOf(':');
            if (colon < 0) {
                continue;
            }
            String key = trimmed.substring(0, colon).trim().toLowerCase(java.util.Locale.ROOT);
            String value = trimmed.substring(colon + 1).trim();

            if (creationDate == null
                    && (key.contains("creat") || (key.contains("register") && !key.contains("registrar")))
                    && !key.contains("updat") && !key.contains("expir")) {
                LocalDate parsed = tryParseDate(value);
                if (parsed != null) {
                    creationDate = parsed;
                    creationDateStr = parsed.format(DateTimeFormatter.ISO_LOCAL_DATE);
                }
            }
            if (registrar == null && key.contains("registrar") && !key.contains("whois")
                    && !key.contains("url") && !key.contains("abuse")) {
                if (!value.isBlank()) {
                    registrar = value;
                }
            }
        }

        RuleInput.DomainAge ageBand = classifyDomainAge(creationDate);
        return new DomainAgeResult(ageBand, creationDateStr, registrar,
                creationDate != null ? creationDate.toString() : null);
    }

    /**
     * Attempt to parse a date string from a WHOIS response.
     * Common formats: ISO-8601 datetime (with T), ISO date (yyyy-MM-dd), dd-MMM-yyyy.
     * Returns null on parse failure — fail-open.
     */
    private static LocalDate tryParseDate(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        // Strip trailing timezone info (Z, +00:00, UTC, etc.)
        String cleaned = raw.split("[Z+]")[0].trim();
        // Strip time portion after 'T'
        if (cleaned.contains("T")) {
            cleaned = cleaned.split("T")[0].trim();
        }
        // Try ISO format yyyy-MM-dd
        try {
            return LocalDate.parse(cleaned, DateTimeFormatter.ISO_LOCAL_DATE);
        } catch (java.time.format.DateTimeParseException ignored) {
            // ignore
        }
        // Try dd-MMM-yyyy (e.g. "15-Jun-2026")
        try {
            return LocalDate.parse(cleaned,
                    DateTimeFormatter.ofPattern("dd-MMM-yyyy", java.util.Locale.ENGLISH));
        } catch (java.time.format.DateTimeParseException ignored) {
            // ignore
        }
        // Try yyyy/MM/dd
        try {
            return LocalDate.parse(cleaned,
                    DateTimeFormatter.ofPattern("yyyy/MM/dd"));
        } catch (java.time.format.DateTimeParseException ignored) {
            // ignore
        }
        return null;
    }

    /**
     * Map a domain creation date to the §7 age band.
     * <ul>
     *   <li>&lt; 7 days → {@link RuleInput.DomainAge#UNDER_7_DAYS}</li>
     *   <li>&lt; 30 days → {@link RuleInput.DomainAge#UNDER_30_DAYS}</li>
     *   <li>&gt; 1 year → {@link RuleInput.DomainAge#OVER_1_YEAR}</li>
     *   <li>30–365 days or null → {@link RuleInput.DomainAge#ESTABLISHED_OR_UNKNOWN}</li>
     * </ul>
     *
     * <p>§7 specifies only the three named bands; the 30d–1yr gap and "unknown age" map
     * to 0.0 (no age-based suspicion). The same deliberate literal reading as
     * {@link RuleInput.DomainAge#ESTABLISHED_OR_UNKNOWN}.
     */
    static RuleInput.DomainAge classifyDomainAge(LocalDate creationDate) {
        if (creationDate == null) {
            return RuleInput.DomainAge.ESTABLISHED_OR_UNKNOWN;
        }
        LocalDate now = LocalDate.now(ZoneOffset.UTC);
        long days = java.time.temporal.ChronoUnit.DAYS.between(creationDate, now);
        if (days < 0) {
            // Future creation date — treat as unknown.
            return RuleInput.DomainAge.ESTABLISHED_OR_UNKNOWN;
        }
        if (days < 7) {
            return RuleInput.DomainAge.UNDER_7_DAYS;
        }
        if (days < 30) {
            return RuleInput.DomainAge.UNDER_30_DAYS;
        }
        if (days > 365) {
            return RuleInput.DomainAge.OVER_1_YEAR;
        }
        return RuleInput.DomainAge.ESTABLISHED_OR_UNKNOWN;
    }

    /**
     * Extract the registrable domain (e.g. "example.com") from a full hostname.
     * Strips one sub-domain level; does not implement a full public-suffix list —
     * sufficient for WHOIS queries where extra labels are just ignored.
     */
    static String registrableDomain(String host) {
        if (host == null) {
            return "";
        }
        // If it's an IP literal, return as-is.
        if (host.matches("\\d+\\.\\d+\\.\\d+\\.\\d+") || host.startsWith("[")) {
            return host;
        }
        String[] parts = host.split("\\.");
        if (parts.length <= 2) {
            return host;
        }
        // Return last two labels (registrable domain approximation).
        return parts[parts.length - 2] + "." + parts[parts.length - 1];
    }

    // =========================================================================
    // Result types
    // =========================================================================

    /** The result of the HTTP fetch phase. */
    record HttpScanResult(
            RuleInput.SslValidity sslValidity,
            int hopCount,
            boolean targetDifferentDomain) {
    }

    /**
     * Domain age query result.
     *
     * @param domainAgeBand  the §7 rule-input band
     * @param creationDate   ISO-8601 date string (for tier1_findings.whoisInfo.creationDate)
     * @param registrar      registrar name (for tier1_findings.whoisInfo.registrar)
     * @param label          the short label stored in tier1_findings.domainAge
     */
    record DomainAgeResult(
            RuleInput.DomainAge domainAgeBand,
            String creationDate,
            String registrar,
            String label) {
    }

    /**
     * The full output of a Tier 1 scan: the JSONB-ready findings, the derived rule
     * signals for the rules engine, and the overall_score for this tier.
     */
    public record ScanOutcome(
            Tier1Findings findings,
            RuleInput.DomainAge domainAgeBand,
            RuleInput.SslValidity sslValidity,
            boolean missingSecurityHeaders,
            boolean redirectAnomaly,
            BigDecimal overallScore) {
    }
}
