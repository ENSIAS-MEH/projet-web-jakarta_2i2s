package com.secbret.scanner;

import java.util.List;

/**
 * Typed DTO for the {@code tier2_findings} JSONB column (Part IV).
 *
 * <p>Canonical JSONB structure:
 * <pre>
 * {
 *   "hasLoginForm": true,
 *   "hasBrandLogo": true,
 *   "externalDomains": ["cdn.evil.com"],
 *   "suspiciousScripts": 3,
 *   "hiddenIframes": 1,
 *   "contentSizeBytes": 45230,
 *   "forms": [{ "action": "...", "method": "POST", "inputFields": ["username","password"] }],
 *   "links": { "internal": 12, "external": 5 }
 * }
 * </pre>
 *
 * <p>Fields are mutable for setter-style construction during scanning, matching
 * the Tier1Findings pattern.
 */
public class Tier2Findings {

    private boolean hasLoginForm;
    private boolean hasBrandLogo;
    private List<String> externalDomains = List.of();
    private int suspiciousScripts;
    private int hiddenIframes;
    private long contentSizeBytes;
    private List<FormFinding> forms = List.of();
    private LinkCounts links = new LinkCounts();
    /** True when any form posts to an external origin (§7 suspiciousFormAction rule). */
    private boolean suspiciousFormAction;
    /** True when hiddenIframes > 0 (§7 hiddenIframes rule). */
    private boolean hasHiddenIframes;
    /** True when homoglyph/lookalike characters detected in domain or page content (§7). */
    private boolean homoglyphDetected;

    // =========================================================================
    // Nested types
    // =========================================================================

    /** A single HTML form found during Tier 2 parsing. */
    public static class FormFinding {
        private String action;
        private String method;
        private List<String> inputFields = List.of();

        public String getAction() { return action; }
        public void setAction(String action) { this.action = action; }
        public String getMethod() { return method; }
        public void setMethod(String method) { this.method = method; }
        public List<String> getInputFields() { return inputFields; }
        public void setInputFields(List<String> fields) {
            this.inputFields = fields == null ? List.of() : fields;
        }
    }

    /** Internal vs external link counts. */
    public static class LinkCounts {
        private int internal;
        private int external;

        public int getInternal() { return internal; }
        public void setInternal(int internal) { this.internal = internal; }
        public int getExternal() { return external; }
        public void setExternal(int external) { this.external = external; }
    }

    // =========================================================================
    // Getters / setters
    // =========================================================================

    public boolean isHasLoginForm() { return hasLoginForm; }
    public void setHasLoginForm(boolean hasLoginForm) { this.hasLoginForm = hasLoginForm; }
    public boolean isHasBrandLogo() { return hasBrandLogo; }
    public void setHasBrandLogo(boolean hasBrandLogo) { this.hasBrandLogo = hasBrandLogo; }
    public List<String> getExternalDomains() { return externalDomains; }
    public void setExternalDomains(List<String> externalDomains) {
        this.externalDomains = externalDomains == null ? List.of() : externalDomains;
    }
    public int getSuspiciousScripts() { return suspiciousScripts; }
    public void setSuspiciousScripts(int suspiciousScripts) { this.suspiciousScripts = suspiciousScripts; }
    public int getHiddenIframes() { return hiddenIframes; }
    public void setHiddenIframes(int hiddenIframes) { this.hiddenIframes = hiddenIframes; }
    public long getContentSizeBytes() { return contentSizeBytes; }
    public void setContentSizeBytes(long contentSizeBytes) { this.contentSizeBytes = contentSizeBytes; }
    public List<FormFinding> getForms() { return forms; }
    public void setForms(List<FormFinding> forms) {
        this.forms = forms == null ? List.of() : forms;
    }
    public LinkCounts getLinks() { return links; }
    public void setLinks(LinkCounts links) { this.links = links == null ? new LinkCounts() : links; }
    public boolean isSuspiciousFormAction() { return suspiciousFormAction; }
    public void setSuspiciousFormAction(boolean suspiciousFormAction) {
        this.suspiciousFormAction = suspiciousFormAction;
    }
    public boolean isHasHiddenIframes() { return hasHiddenIframes; }
    public void setHasHiddenIframes(boolean hasHiddenIframes) { this.hasHiddenIframes = hasHiddenIframes; }
    public boolean isHomoglyphDetected() { return homoglyphDetected; }
    public void setHomoglyphDetected(boolean homoglyphDetected) {
        this.homoglyphDetected = homoglyphDetected;
    }
}
