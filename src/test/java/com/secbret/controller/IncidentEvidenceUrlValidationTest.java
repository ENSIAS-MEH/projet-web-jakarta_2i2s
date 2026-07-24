package com.secbret.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for H-1: evidence-URL allowlist validation in
 * {@link IncidentWebController#validateEvidenceUrls(String)}.
 */
class IncidentEvidenceUrlValidationTest {

    @Test
    @DisplayName("null/blank input is valid (no evidence URLs)")
    void nullInput_valid() {
        assertThat(IncidentWebController.validateEvidenceUrls(null)).isNull();
        assertThat(IncidentWebController.validateEvidenceUrls("")).isNull();
        assertThat(IncidentWebController.validateEvidenceUrls("   ")).isNull();
    }

    @Test
    @DisplayName("single http:// URL is accepted")
    void httpUrl_accepted() {
        assertThat(IncidentWebController.validateEvidenceUrls("http://example.com/evidence")).isNull();
    }

    @Test
    @DisplayName("single https:// URL is accepted")
    void httpsUrl_accepted() {
        assertThat(IncidentWebController.validateEvidenceUrls("https://example.com/evidence")).isNull();
    }

    @Test
    @DisplayName("javascript: scheme is rejected")
    void javascriptScheme_rejected() {
        assertThat(IncidentWebController.validateEvidenceUrls("javascript:alert(document.cookie)"))
                .isEqualTo("Each evidence URL must be a valid HTTP(S) URL");
    }

    @Test
    @DisplayName("data: scheme is rejected")
    void dataScheme_rejected() {
        assertThat(IncidentWebController.validateEvidenceUrls("data:text/html,<script>alert(1)</script>"))
                .isEqualTo("Each evidence URL must be a valid HTTP(S) URL");
    }

    @Test
    @DisplayName("exactly 5 URLs are accepted")
    void fiveUrls_accepted() {
        String input = "https://a.com,https://b.com,https://c.com,https://d.com,https://e.com";
        assertThat(IncidentWebController.validateEvidenceUrls(input)).isNull();
    }

    @Test
    @DisplayName("more than 5 URLs are rejected")
    void sixUrls_rejected() {
        String input = "https://a.com,https://b.com,https://c.com,https://d.com,https://e.com,https://f.com";
        assertThat(IncidentWebController.validateEvidenceUrls(input))
                .isEqualTo("At most 5 evidence URLs are allowed");
    }

    @Test
    @DisplayName("URL longer than 2048 characters is rejected")
    void tooLongUrl_rejected() {
        String longUrl = "https://example.com/" + "a".repeat(2048);
        assertThat(IncidentWebController.validateEvidenceUrls(longUrl))
                .isEqualTo("Each evidence URL must be a valid HTTP(S) URL");
    }

    @Test
    @DisplayName("mixed valid and invalid URLs: invalid entry causes rejection")
    void mixedUrls_invalidCausesRejection() {
        String input = "https://ok.com,javascript:alert(1)";
        assertThat(IncidentWebController.validateEvidenceUrls(input))
                .isEqualTo("Each evidence URL must be a valid HTTP(S) URL");
    }

    @Test
    @DisplayName("blank entries between commas are ignored")
    void blankEntriesIgnored() {
        // "https://a.com,,https://b.com" → 2 real URLs, valid
        assertThat(IncidentWebController.validateEvidenceUrls("https://a.com,,https://b.com")).isNull();
    }
}
