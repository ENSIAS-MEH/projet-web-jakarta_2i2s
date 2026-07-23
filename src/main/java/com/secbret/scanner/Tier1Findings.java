package com.secbret.scanner;

import java.util.List;
import java.util.Map;

/**
 * Typed DTO for the {@code tier1_findings} JSONB column (Part IV).
 *
 * <p>Serialized to / deserialized from JSON by the scanner layer. The canonical
 * JSONB structure is defined in Part IV:
 *
 * <pre>
 * {
 *   "domainAge":      "3_days",
 *   "sslValid":       false,
 *   "sslExpiryDate":  null,
 *   "sslIssuer":      "Let's Encrypt",
 *   "httpHeaders":    { "xFrameOptions": "missing", ... },
 *   "dnsRecords":     ["1.2.3.4"],
 *   "redirectChain":  ["https://example.com/a"],
 *   "whoisInfo":      { "registrar": "...", "creationDate": "...", "nameservers": [...] }
 * }
 * </pre>
 *
 * <p>Fields are public and mutable so a builder-style setter sequence works during
 * scanning without needing a separate builder class at this scale. Null-safe by
 * construction: all list/map fields default to empty collections rather than null
 * so JSON serialisation never emits null arrays.
 */
public class Tier1Findings {

    // -------------------------------------------------------------------------
    // Domain age — one of the short canonical strings the spec uses in examples.
    // The scanner maps the registered-date delta to a §7 band label.
    // -------------------------------------------------------------------------
    /** Canonical age label as stored in tier1_findings (e.g. "3_days", ">1_year"). */
    private String domainAge;

    // -------------------------------------------------------------------------
    // SSL
    // -------------------------------------------------------------------------
    private boolean sslValid;
    private String sslExpiryDate;   // ISO-8601 date string, or null if no cert / expired
    private String sslIssuer;       // CA name or null

    // -------------------------------------------------------------------------
    // HTTP security headers (§7 rule: missing CSP+HSTS+XFO = 0.6)
    // -------------------------------------------------------------------------
    private HttpHeaderFindings httpHeaders = new HttpHeaderFindings();

    // -------------------------------------------------------------------------
    // DNS / network
    // -------------------------------------------------------------------------
    private List<String> dnsRecords = List.of();

    // -------------------------------------------------------------------------
    // Redirect chain (used by redirectAnomaly rule in §7)
    // -------------------------------------------------------------------------
    private List<String> redirectChain = List.of();

    // -------------------------------------------------------------------------
    // WHOIS
    // -------------------------------------------------------------------------
    private WhoisInfo whoisInfo;

    // =========================================================================
    // Nested types
    // =========================================================================

    /**
     * The four HTTP security headers tracked by the §7 "HTTP security headers" rule.
     * Values are the literal header value string when present, or {@code "missing"}.
     */
    public static class HttpHeaderFindings {
        private String xFrameOptions       = "missing";
        private String contentSecurityPolicy = "missing";
        private String strictTransportSecurity = "missing";
        private String xContentTypeOptions = "missing";

        public String getXFrameOptions() { return xFrameOptions; }
        public void setXFrameOptions(String v) { this.xFrameOptions = v; }
        public String getContentSecurityPolicy() { return contentSecurityPolicy; }
        public void setContentSecurityPolicy(String v) { this.contentSecurityPolicy = v; }
        public String getStrictTransportSecurity() { return strictTransportSecurity; }
        public void setStrictTransportSecurity(String v) { this.strictTransportSecurity = v; }
        public String getXContentTypeOptions() { return xContentTypeOptions; }
        public void setXContentTypeOptions(String v) { this.xContentTypeOptions = v; }

        /**
         * Returns {@code true} when all three CSP+HSTS+X-Frame-Options headers are absent,
         * which triggers the §7 "HTTP security headers" rule value of 0.6.
         */
        public boolean allThreeMissing() {
            return "missing".equals(contentSecurityPolicy)
                    && "missing".equals(strictTransportSecurity)
                    && "missing".equals(xFrameOptions);
        }
    }

    /** WHOIS metadata extracted during Tier 1 scanning. */
    public static class WhoisInfo {
        private String registrar;
        private String creationDate;   // ISO-8601 date when available
        private List<String> nameservers = List.of();

        public String getRegistrar() { return registrar; }
        public void setRegistrar(String v) { this.registrar = v; }
        public String getCreationDate() { return creationDate; }
        public void setCreationDate(String v) { this.creationDate = v; }
        public List<String> getNameservers() { return nameservers; }
        public void setNameservers(List<String> v) { this.nameservers = v == null ? List.of() : v; }
    }

    // =========================================================================
    // Getters / setters
    // =========================================================================

    public String getDomainAge() { return domainAge; }
    public void setDomainAge(String domainAge) { this.domainAge = domainAge; }
    public boolean isSslValid() { return sslValid; }
    public void setSslValid(boolean sslValid) { this.sslValid = sslValid; }
    public String getSslExpiryDate() { return sslExpiryDate; }
    public void setSslExpiryDate(String sslExpiryDate) { this.sslExpiryDate = sslExpiryDate; }
    public String getSslIssuer() { return sslIssuer; }
    public void setSslIssuer(String sslIssuer) { this.sslIssuer = sslIssuer; }
    public HttpHeaderFindings getHttpHeaders() { return httpHeaders; }
    public void setHttpHeaders(HttpHeaderFindings httpHeaders) {
        this.httpHeaders = httpHeaders == null ? new HttpHeaderFindings() : httpHeaders;
    }
    public List<String> getDnsRecords() { return dnsRecords; }
    public void setDnsRecords(List<String> dnsRecords) {
        this.dnsRecords = dnsRecords == null ? List.of() : dnsRecords;
    }
    public List<String> getRedirectChain() { return redirectChain; }
    public void setRedirectChain(List<String> redirectChain) {
        this.redirectChain = redirectChain == null ? List.of() : redirectChain;
    }
    public WhoisInfo getWhoisInfo() { return whoisInfo; }
    public void setWhoisInfo(WhoisInfo whoisInfo) { this.whoisInfo = whoisInfo; }
}
