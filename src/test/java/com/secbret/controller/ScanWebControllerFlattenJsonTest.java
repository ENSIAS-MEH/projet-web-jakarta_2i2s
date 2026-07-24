package com.secbret.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** Unit tests for {@link ScanWebController#flattenJson(String)} (findings display). */
class ScanWebControllerFlattenJsonTest {

    @Test
    @DisplayName("flattens nested objects and arrays into ordered dotted paths")
    void flattensNestedStructures() {
        String json = """
                {"sslValid":true,
                 "httpHeaders":{"hsts":false},
                 "dnsRecords":["1.2.3.4","5.6.7.8"],
                 "forms":[{"action":"/steal","method":"post"}]}
                """;

        Map<String, String> flat = ScanWebController.flattenJson(json);

        assertThat(flat).containsEntry("sslValid", "true")
                .containsEntry("httpHeaders.hsts", "false")
                .containsEntry("dnsRecords[1]", "1.2.3.4")
                .containsEntry("dnsRecords[2]", "5.6.7.8")
                .containsEntry("forms[1].action", "/steal")
                .containsEntry("forms[1].method", "post");
        assertThat(List.copyOf(flat.keySet()).get(0)).isEqualTo("sslValid");
    }

    @Test
    @DisplayName("returns empty map for null/blank and raw fallback for invalid JSON")
    void handlesDegenerateInput() {
        assertThat(ScanWebController.flattenJson(null)).isEmpty();
        assertThat(ScanWebController.flattenJson("  ")).isEmpty();
        assertThat(ScanWebController.flattenJson("not-json{"))
                .containsEntry("raw", "not-json{");
    }

    @Test
    @DisplayName("empty arrays render as 'none' instead of disappearing")
    void emptyArraysKeepTheirKey() {
        assertThat(ScanWebController.flattenJson("{\"cveMatches\":[]}"))
                .containsEntry("cveMatches", "none");
    }
}
