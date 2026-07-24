package com.secbret.scanner;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for Tier3Scanner logic: kit-marker matching, dispositiveEligible gating,
 * outdated-library/CVE detection, and open-redirect detection.
 *
 * <p>All tests use inline HTML strings passed as {@code pageHtml} so no SSRF guard
 * or network is needed. The {@code Tier3Scanner(SsrfGuard, PhishingKitRuleset)}
 * package-private constructor is used to inject a test ruleset.
 */
@DisplayName("Tier3Scanner — kit marker matching, CVEs, open-redirect")
class Tier3ScannerTest {

    // =========================================================================
    // Kit Marker Matching
    // =========================================================================

    @Nested
    @DisplayName("Kit marker matching — dispositiveEligible gating")
    class KitMarkerTests {

        @Test
        @DisplayName("no markers matched → knownPhishingKit false, kitMarkersMatched empty")
        void noMarkersMatched_cleanResult() {
            PhishingKitRuleset ruleset = new PhishingKitRuleset("2026.07.1",
                    List.of(new KitMarker("KIT-0001", "DarkSide", "__unique_kit__", true)));
            Tier3Scanner scanner = new Tier3Scanner(null, ruleset);

            String html = "<html><body><p>Totally legit site</p></body></html>";
            Tier3Findings f = scanner.scan("https://example.com", html).findings();

            assertThat(f.isKnownPhishingKit()).isFalse();
            assertThat(f.getKitMarkersMatched()).isEmpty();
            assertThat(f.getKitRulesetVersion()).isEqualTo("2026.07.1");
        }

        @Test
        @DisplayName("dispositive marker matched → knownPhishingKit true")
        void dispositiveMarker_matched_knownPhishingKitTrue() {
            PhishingKitRuleset ruleset = new PhishingKitRuleset("2026.07.1",
                    List.of(new KitMarker("KIT-0001", "DarkSide v19", "__kit_darkside_v19__", true)));
            Tier3Scanner scanner = new Tier3Scanner(null, ruleset);

            String html = "<html><body><script>var x = '__kit_darkside_v19__';</script></body></html>";
            Tier3Findings f = scanner.scan("https://phish.example.com", html).findings();

            assertThat(f.isKnownPhishingKit()).isTrue();
            assertThat(f.getKitMarkersMatched()).hasSize(1);
            assertThat(f.getKitMarkersMatched().get(0).getId()).isEqualTo("KIT-0001");
            assertThat(f.getKitMarkersMatched().get(0).isDispositiveEligible()).isTrue();
        }

        @Test
        @DisplayName("non-dispositive marker matched → knownPhishingKit false, marker recorded")
        void nonDispositiveMarker_matched_kitFalse_markerRecorded() {
            PhishingKitRuleset ruleset = new PhishingKitRuleset("2026.07.1",
                    List.of(new KitMarker("KIT-0003", "Generic harvester", "harvester_id", false)));
            Tier3Scanner scanner = new Tier3Scanner(null, ruleset);

            String html = "<html><body><input name='harvester_id' type='hidden'></body></html>";
            Tier3Findings f = scanner.scan("https://suspicious.example.com", html).findings();

            // Governance invariant: non-dispositive match MUST NOT set knownPhishingKit.
            assertThat(f.isKnownPhishingKit()).isFalse();
            assertThat(f.getKitMarkersMatched()).hasSize(1);
            assertThat(f.getKitMarkersMatched().get(0).isDispositiveEligible()).isFalse();
        }

        @Test
        @DisplayName("mix of dispositive and non-dispositive markers matched → knownPhishingKit true")
        void mixedMarkers_anyDispositive_kitTrue() {
            PhishingKitRuleset ruleset = new PhishingKitRuleset("2026.07.1", List.of(
                    new KitMarker("KIT-0003", "Weak heuristic", "harvester_id", false),
                    new KitMarker("KIT-0001", "Kit constant", "__kit_darkside_v19__", true)
            ));
            Tier3Scanner scanner = new Tier3Scanner(null, ruleset);

            String html = "<html><body>harvester_id __kit_darkside_v19__</body></html>";
            Tier3Findings f = scanner.scan("https://phish.example.com", html).findings();

            assertThat(f.isKnownPhishingKit()).isTrue();
            assertThat(f.getKitMarkersMatched()).hasSize(2);
        }

        @Test
        @DisplayName("only non-dispositive markers matched → knownPhishingKit false")
        void onlyNonDispositive_kitFalse() {
            PhishingKitRuleset ruleset = new PhishingKitRuleset("2026.07.1", List.of(
                    new KitMarker("KIT-0003", "Generic", "harvester_id", false),
                    new KitMarker("KIT-0004", "Obfuscation", "eval(base64_decode", false)
            ));
            Tier3Scanner scanner = new Tier3Scanner(null, ruleset);

            String html = "<html><body>harvester_id eval(base64_decode('xxx'))</body></html>";
            Tier3Findings f = scanner.scan("https://suspicious.example.com", html).findings();

            assertThat(f.isKnownPhishingKit()).isFalse();
            assertThat(f.getKitMarkersMatched()).hasSize(2);
        }

        @Test
        @DisplayName("kitRulesetVersion is always persisted regardless of matches")
        void kitRulesetVersion_alwaysPersisted() {
            PhishingKitRuleset ruleset = new PhishingKitRuleset("test.99.1", List.of());
            Tier3Scanner scanner = new Tier3Scanner(null, ruleset);

            Tier3Findings f = scanner.scan("https://example.com", "<html><body>clean</body></html>").findings();

            assertThat(f.getKitRulesetVersion()).isEqualTo("test.99.1");
        }
    }

    // =========================================================================
    // CVE detection
    // =========================================================================

    @Nested
    @DisplayName("Outdated library and CVE detection")
    class CveTests {

        private Tier3Scanner scanner;

        @BeforeEach
        void setUp() {
            // Use production ruleset; CVE detection is independent of markers.
            scanner = new Tier3Scanner(null, PhishingKitRuleset.CURRENT);
        }

        @Test
        @DisplayName("no outdated libraries → cveMatches empty")
        void noOutdatedLibraries_cveEmpty() {
            String html = "<html><head><script src='/js/app.js'></script></head><body></body></html>";
            Tier3Findings f = scanner.scan("https://example.com", html).findings();

            assertThat(f.getOutdatedLibraries()).isEmpty();
            assertThat(f.getCveMatches()).isEmpty();
        }

        @Test
        @DisplayName("jquery-1.6 in script src → CVE-2011-4969 detected")
        void jquery16_cveDetected() {
            String html = "<html><head><script src='/js/jquery-1.6.4.min.js'></script></head><body></body></html>";
            Tier3Findings f = scanner.scan("https://example.com", html).findings();

            assertThat(f.getOutdatedLibraries()).anyMatch(lib -> lib.contains("jquery-1.6"));
            assertThat(f.getCveMatches()).contains("CVE-2011-4969");
        }

        @Test
        @DisplayName("jquery-2.1 in script src → CVE-2019-11358 detected")
        void jquery21_cveDetected() {
            String html = "<html><head><script src='https://cdn.example.com/jquery-2.1.4.min.js'></script></head><body></body></html>";
            Tier3Findings f = scanner.scan("https://example.com", html).findings();

            assertThat(f.getCveMatches()).contains("CVE-2019-11358");
        }

        @Test
        @DisplayName("multiple outdated versions deduplicated")
        void multipleVersions_deduplicated() {
            String html = """
                    <html><head>
                    <script src='/jquery-1.6.4.min.js'></script>
                    <script src='/jquery-1.6.2.min.js'></script>
                    </head><body></body></html>""";
            Tier3Findings f = scanner.scan("https://example.com", html).findings();

            // Both scripts match jquery-1.6 — recorded once.
            long jqueryCount = f.getOutdatedLibraries().stream()
                    .filter(lib -> lib.contains("jquery-1.6")).count();
            assertThat(jqueryCount).isEqualTo(1);
        }
    }

    // =========================================================================
    // Open redirect
    // =========================================================================

    @Nested
    @DisplayName("Open redirect detection")
    class OpenRedirectTests {

        private Tier3Scanner scanner;

        @BeforeEach
        void setUp() {
            scanner = new Tier3Scanner(null, PhishingKitRuleset.CURRENT);
        }

        @Test
        @DisplayName("no redirect signals → openRedirect false")
        void noRedirect_false() {
            String html = "<html><body><a href='/home'>Home</a></body></html>";
            Tier3Findings f = scanner.scan("https://example.com", html).findings();

            assertThat(f.isOpenRedirect()).isFalse();
        }

        @Test
        @DisplayName("meta refresh to external domain → openRedirect true")
        void metaRefresh_externalDomain_detected() {
            String html = "<html><head><meta http-equiv='refresh' content='0; url=https://evil.com/land'></head><body></body></html>";
            Tier3Findings f = scanner.scan("https://mysite.com", html).findings();

            assertThat(f.isOpenRedirect()).isTrue();
        }

        @Test
        @DisplayName("meta refresh to same domain → openRedirect false")
        void metaRefresh_sameDomain_notDetected() {
            String html = "<html><head><meta http-equiv='refresh' content='2; url=https://mysite.com/new'></head><body></body></html>";
            Tier3Findings f = scanner.scan("https://mysite.com", html).findings();

            assertThat(f.isOpenRedirect()).isFalse();
        }

        @Test
        @DisplayName("anchor with redirect param pointing to external URL → detected")
        void anchorRedirectParam_external_detected() {
            String html = "<html><body><a href='https://mysite.com/go?redirect=https://evil.com'>Click</a></body></html>";
            Tier3Findings f = scanner.scan("https://mysite.com", html).findings();

            assertThat(f.isOpenRedirect()).isTrue();
        }

        @Test
        @DisplayName("anchor with next param pointing to same-origin → not detected")
        void anchorNextParam_sameOrigin_notDetected() {
            String html = "<html><body><a href='https://mysite.com/go?next=https://mysite.com/dashboard'>Home</a></body></html>";
            Tier3Findings f = scanner.scan("https://mysite.com", html).findings();

            assertThat(f.isOpenRedirect()).isFalse();
        }
    }
}
