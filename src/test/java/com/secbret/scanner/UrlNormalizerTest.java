package com.secbret.scanner;

import com.secbret.exception.ValidationException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for {@link UrlNormalizer} implementing Part II §C (all 8 steps).
 *
 * <p>Structure:
 * <ol>
 *   <li>One test per algorithm step (§C steps 1–7), plus hash (step 8).</li>
 *   <li>Equivalence-class contract: URLs that differ only in case/port/trailing-slash/
 *       query-order MUST produce the same normalized form and the same hash.</li>
 *   <li>Different URLs MUST produce different hashes.</li>
 *   <li>Rejection cases: fragment, non-http(s), oversized, blank, null, garbage,
 *       userinfo, unicode hostnames.</li>
 * </ol>
 */
class UrlNormalizerTest {

    private final UrlNormalizer normalizer = new UrlNormalizer();

    // ==========================================================================
    // Step 1 — Lowercase scheme and host
    // ==========================================================================

    @Nested
    @DisplayName("Step 1: lowercase scheme and host")
    class Step1 {

        @Test
        @DisplayName("uppercase HTTP scheme is lowercased")
        void normalize_uppercaseScheme_isLowercased() {
            assertThat(normalizer.normalize("HTTP://example.com/"))
                    .startsWith("http://");
        }

        @Test
        @DisplayName("mixed-case HTTPS scheme is lowercased")
        void normalize_mixedCaseScheme_isLowercased() {
            assertThat(normalizer.normalize("HtTpS://example.com/"))
                    .startsWith("https://");
        }

        @Test
        @DisplayName("uppercase host is lowercased")
        void normalize_uppercaseHost_isLowercased() {
            assertThat(normalizer.normalize("http://EXAMPLE.COM/path"))
                    .contains("example.com");
        }

        @Test
        @DisplayName("mixed-case host is lowercased")
        void normalize_mixedCaseHost_isLowercased() {
            assertThat(normalizer.normalize("http://Example.Com/path"))
                    .contains("example.com");
        }

        @Test
        @DisplayName("path case is preserved (path is case-sensitive per RFC 3986)")
        void normalize_pathCase_isPreserved() {
            // RFC 3986 §2.7.3: path segments are case-sensitive.
            assertThat(normalizer.normalize("http://example.com/Path/To/Resource"))
                    .endsWith("/Path/To/Resource");
        }

        @Test
        @DisplayName("query case is preserved")
        void normalize_queryCase_isPreserved() {
            assertThat(normalizer.normalize("http://example.com/path?Key=Value"))
                    .endsWith("?Key=Value");
        }
    }

    // ==========================================================================
    // Step 2 — Remove default ports
    // ==========================================================================

    @Nested
    @DisplayName("Step 2: remove default ports")
    class Step2 {

        @Test
        @DisplayName("port 80 is removed from http URLs")
        void normalize_http80_portRemoved() {
            assertThat(normalizer.normalize("http://example.com:80/path"))
                    .isEqualTo("http://example.com/path");
        }

        @Test
        @DisplayName("port 443 is removed from https URLs")
        void normalize_https443_portRemoved() {
            assertThat(normalizer.normalize("https://example.com:443/path"))
                    .isEqualTo("https://example.com/path");
        }

        @Test
        @DisplayName("non-default port 8080 is retained")
        void normalize_http8080_portRetained() {
            assertThat(normalizer.normalize("http://example.com:8080/path"))
                    .isEqualTo("http://example.com:8080/path");
        }

        @Test
        @DisplayName("non-default port 8443 is retained on https")
        void normalize_https8443_portRetained() {
            assertThat(normalizer.normalize("https://example.com:8443/path"))
                    .isEqualTo("https://example.com:8443/path");
        }

        @Test
        @DisplayName("port 80 on https is NOT a default and is retained")
        void normalize_https80_portRetained() {
            assertThat(normalizer.normalize("https://example.com:80/path"))
                    .isEqualTo("https://example.com:80/path");
        }

        @Test
        @DisplayName("port 443 on http is NOT a default and is retained")
        void normalize_http443_portRetained() {
            assertThat(normalizer.normalize("http://example.com:443/path"))
                    .isEqualTo("http://example.com:443/path");
        }
    }

    // ==========================================================================
    // Step 3 — Strip fragment
    // ==========================================================================

    @Nested
    @DisplayName("Step 3: strip fragment")
    class Step3 {

        @Test
        @DisplayName("fragment is stripped")
        void normalize_withFragment_fragmentStripped() {
            assertThat(normalizer.normalize("http://example.com/path#section"))
                    .isEqualTo("http://example.com/path");
        }

        @Test
        @DisplayName("fragment with query is stripped; query is kept")
        void normalize_queryAndFragment_fragmentStripped() {
            assertThat(normalizer.normalize("http://example.com/path?q=1#anchor"))
                    .isEqualTo("http://example.com/path?q=1");
        }

        @Test
        @DisplayName("empty fragment is also stripped")
        void normalize_emptyFragment_fragmentStripped() {
            // URI parses "http://example.com/path#" as fragment="" — we still omit it.
            assertThat(normalizer.normalize("http://example.com/path#"))
                    .isEqualTo("http://example.com/path");
        }
    }

    // ==========================================================================
    // Step 4 — Collapse duplicate path separators
    // ==========================================================================

    @Nested
    @DisplayName("Step 4: collapse duplicate path separators")
    class Step4 {

        @Test
        @DisplayName("double slashes in path are collapsed")
        void normalize_doubleSeparators_collapsed() {
            assertThat(normalizer.normalize("http://example.com//path//to//resource"))
                    .isEqualTo("http://example.com/path/to/resource");
        }

        @Test
        @DisplayName("triple slashes in path are collapsed")
        void normalize_tripleSeparators_collapsed() {
            assertThat(normalizer.normalize("http://example.com///path"))
                    .isEqualTo("http://example.com/path");
        }

        @Test
        @DisplayName("single slashes are unaffected")
        void normalize_singleSeparators_unchanged() {
            assertThat(normalizer.normalize("http://example.com/path/to/resource"))
                    .isEqualTo("http://example.com/path/to/resource");
        }
    }

    // ==========================================================================
    // Step 5 — Remove trailing slash except root
    // ==========================================================================

    @Nested
    @DisplayName("Step 5: remove trailing slash except root")
    class Step5 {

        @Test
        @DisplayName("trailing slash removed from non-root path")
        void normalize_trailingSlash_removed() {
            assertThat(normalizer.normalize("http://example.com/path/"))
                    .isEqualTo("http://example.com/path");
        }

        @Test
        @DisplayName("root path '/' is preserved")
        void normalize_rootPath_preserved() {
            assertThat(normalizer.normalize("http://example.com/"))
                    .isEqualTo("http://example.com/");
        }

        @Test
        @DisplayName("deep path trailing slash removed")
        void normalize_deepPathTrailingSlash_removed() {
            assertThat(normalizer.normalize("http://example.com/a/b/c/"))
                    .isEqualTo("http://example.com/a/b/c");
        }

        @Test
        @DisplayName("path with no trailing slash is unchanged")
        void normalize_noTrailingSlash_unchanged() {
            assertThat(normalizer.normalize("http://example.com/path"))
                    .isEqualTo("http://example.com/path");
        }
    }

    // ==========================================================================
    // Step 6 — Sort query parameters lexicographically
    // ==========================================================================

    @Nested
    @DisplayName("Step 6: sort query parameters lexicographically")
    class Step6 {

        @Test
        @DisplayName("query parameters are sorted lexicographically")
        void normalize_queryParams_sorted() {
            assertThat(normalizer.normalize("http://example.com/path?z=3&a=1&m=2"))
                    .isEqualTo("http://example.com/path?a=1&m=2&z=3");
        }

        @Test
        @DisplayName("already-sorted query params remain unchanged")
        void normalize_alreadySortedQuery_unchanged() {
            assertThat(normalizer.normalize("http://example.com/path?a=1&b=2&c=3"))
                    .isEqualTo("http://example.com/path?a=1&b=2&c=3");
        }

        @Test
        @DisplayName("duplicate keys retain relative insertion order (stable sort)")
        void normalize_duplicateKeys_stableSort() {
            // a=1 and a=2 are equal-key; stable sort preserves their relative order.
            assertThat(normalizer.normalize("http://example.com/?b=0&a=1&a=2"))
                    .isEqualTo("http://example.com/?a=1&a=2&b=0");
        }

        @Test
        @DisplayName("empty query string '?' produces URL without query component")
        void normalize_emptyQueryString_queryStripped() {
            // Edge semantic: trailing '?' with no params is stripped.
            assertThat(normalizer.normalize("http://example.com/path?"))
                    .isEqualTo("http://example.com/path");
        }

        @Test
        @DisplayName("single query parameter is unchanged")
        void normalize_singleQueryParam_unchanged() {
            assertThat(normalizer.normalize("http://example.com/path?key=value"))
                    .isEqualTo("http://example.com/path?key=value");
        }

        @Test
        @DisplayName("query param without value is preserved")
        void normalize_valuelessQueryParam_preserved() {
            assertThat(normalizer.normalize("http://example.com/path?flag"))
                    .isEqualTo("http://example.com/path?flag");
        }
    }

    // ==========================================================================
    // Step 7 — Convert hostname to Punycode (IDN)
    // ==========================================================================

    @Nested
    @DisplayName("Step 7: convert hostname to Punycode")
    class Step7 {

        @Test
        @DisplayName("ASCII hostname is unchanged by IDN.toASCII")
        void normalize_asciiHostname_unchanged() {
            assertThat(normalizer.normalize("http://example.com/path"))
                    .isEqualTo("http://example.com/path");
        }

        @Test
        @DisplayName("Unicode hostname is converted to Punycode")
        void normalize_unicodeHostname_convertedToPunycode() {
            // münchen.de → xn--mnchen-3ya.de
            String result = normalizer.normalize("http://münchen.de/path");
            assertThat(result).contains("xn--mnchen-3ya.de");
        }

        @Test
        @DisplayName("IDN with multiple labels is converted correctly")
        void normalize_idnMultiLabel_convertedToPunycode() {
            // 日本語.jp has Punycode: xn--wgv71a309e.jp
            String result = normalizer.normalize("http://日本語.jp/");
            assertThat(result).startsWith("http://xn--");
        }
    }

    // ==========================================================================
    // Step 8 — SHA-256 hash
    // ==========================================================================

    @Nested
    @DisplayName("Step 8: SHA-256 hash of normalized form")
    class Step8 {

        @Test
        @DisplayName("hash returns a 64-character lowercase hex string")
        void hash_returnsValid64CharHex() {
            String h = normalizer.hash("http://example.com/path");
            assertThat(h)
                    .hasSize(64)
                    .matches("[0-9a-f]{64}");
        }

        @Test
        @DisplayName("hash is deterministic: same input always produces same hash")
        void hash_deterministic() {
            String h1 = normalizer.hash("https://example.com/path?a=1");
            String h2 = normalizer.hash("https://example.com/path?a=1");
            assertThat(h1).isEqualTo(h2);
        }

        @Test
        @DisplayName("sha256Hex of a known input produces a known digest")
        void sha256Hex_knownInput_knownOutput() {
            // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            assertThat(UrlNormalizer.sha256Hex(""))
                    .isEqualTo("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        }
    }

    // ==========================================================================
    // §C Equivalence contract:
    // URLs that differ ONLY in case / port / trailing-slash / query-order
    // MUST produce the same normalized form AND the same hash.
    // ==========================================================================

    @Nested
    @DisplayName("§C equivalence contract: same hash for equivalent URLs")
    class EquivalenceContract {

        @Test
        @DisplayName("differing scheme case produce identical hash")
        void sameHash_differentSchemeCase() {
            assertThat(normalizer.hash("HTTP://example.com/"))
                    .isEqualTo(normalizer.hash("http://example.com/"));
        }

        @Test
        @DisplayName("differing host case produce identical hash")
        void sameHash_differentHostCase() {
            assertThat(normalizer.hash("http://EXAMPLE.COM/path"))
                    .isEqualTo(normalizer.hash("http://example.com/path"));
        }

        @Test
        @DisplayName("explicit default port vs no port produce identical hash (http:80)")
        void sameHash_explicitDefaultPortHttp() {
            assertThat(normalizer.hash("http://example.com:80/path"))
                    .isEqualTo(normalizer.hash("http://example.com/path"));
        }

        @Test
        @DisplayName("explicit default port vs no port produce identical hash (https:443)")
        void sameHash_explicitDefaultPortHttps() {
            assertThat(normalizer.hash("https://example.com:443/"))
                    .isEqualTo(normalizer.hash("https://example.com/"));
        }

        @Test
        @DisplayName("trailing slash vs no trailing slash (non-root) produce identical hash")
        void sameHash_trailingSlashVsNone() {
            assertThat(normalizer.hash("http://example.com/path/"))
                    .isEqualTo(normalizer.hash("http://example.com/path"));
        }

        @Test
        @DisplayName("query param order permutations produce identical hash")
        void sameHash_queryOrderPermutations() {
            String h1 = normalizer.hash("http://example.com/?a=1&b=2&c=3");
            String h2 = normalizer.hash("http://example.com/?c=3&a=1&b=2");
            String h3 = normalizer.hash("http://example.com/?b=2&c=3&a=1");
            assertThat(h1).isEqualTo(h2).isEqualTo(h3);
        }

        @Test
        @DisplayName("combination: case + port + trailing slash + query order all equivalent")
        void sameHash_combinedEquivalence() {
            String canonical = normalizer.hash("http://example.com/path?a=1&b=2");
            String variant = normalizer.hash("HTTP://EXAMPLE.COM:80/path/?b=2&a=1");
            assertThat(variant).isEqualTo(canonical);
        }

        @Test
        @DisplayName("fragment-only difference: same hash (fragment stripped)")
        void sameHash_fragmentStripped() {
            assertThat(normalizer.hash("http://example.com/path#section"))
                    .isEqualTo(normalizer.hash("http://example.com/path"));
        }
    }

    // ==========================================================================
    // Genuinely different URLs MUST produce different hashes
    // ==========================================================================

    @Nested
    @DisplayName("Different URLs produce different hashes")
    class DifferentHashes {

        @Test
        @DisplayName("different scheme produces different hash")
        void differentHash_differentScheme() {
            assertThat(normalizer.hash("http://example.com/"))
                    .isNotEqualTo(normalizer.hash("https://example.com/"));
        }

        @Test
        @DisplayName("different path produces different hash")
        void differentHash_differentPath() {
            assertThat(normalizer.hash("http://example.com/path"))
                    .isNotEqualTo(normalizer.hash("http://example.com/other"));
        }

        @Test
        @DisplayName("path case difference produces different hash (path is case-sensitive)")
        void differentHash_pathCaseDifference() {
            // /Path and /path are semantically distinct per RFC 3986 §2.7.3.
            assertThat(normalizer.hash("http://example.com/Path"))
                    .isNotEqualTo(normalizer.hash("http://example.com/path"));
        }

        @Test
        @DisplayName("different query values produce different hash")
        void differentHash_differentQueryValues() {
            assertThat(normalizer.hash("http://example.com/?a=1"))
                    .isNotEqualTo(normalizer.hash("http://example.com/?a=2"));
        }

        @Test
        @DisplayName("different host produces different hash")
        void differentHash_differentHost() {
            assertThat(normalizer.hash("http://example.com/path"))
                    .isNotEqualTo(normalizer.hash("http://other.com/path"));
        }

        @Test
        @DisplayName("different non-default ports produce different hash")
        void differentHash_differentNonDefaultPorts() {
            assertThat(normalizer.hash("http://example.com:8080/path"))
                    .isNotEqualTo(normalizer.hash("http://example.com:9090/path"));
        }

        @Test
        @DisplayName("with-query vs without-query produces different hash")
        void differentHash_queryPresenceAbsence() {
            assertThat(normalizer.hash("http://example.com/path?q=1"))
                    .isNotEqualTo(normalizer.hash("http://example.com/path"));
        }
    }

    // ==========================================================================
    // Rejection cases
    // ==========================================================================

    @Nested
    @DisplayName("Rejection: invalid / disallowed inputs")
    class RejectionCases {

        @Test
        @DisplayName("null input is rejected")
        void normalize_null_throwsValidationException() {
            assertThatThrownBy(() -> normalizer.normalize(null))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("null or blank");
        }

        @Test
        @DisplayName("blank input is rejected")
        void normalize_blank_throwsValidationException() {
            assertThatThrownBy(() -> normalizer.normalize("   "))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("null or blank");
        }

        @Test
        @DisplayName("URL exceeding 2048 characters is rejected")
        void normalize_oversized_throwsValidationException() {
            String oversized = "http://example.com/" + "a".repeat(2030);
            assertThat(oversized.length()).isGreaterThan(2048);
            assertThatThrownBy(() -> normalizer.normalize(oversized))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("2048");
        }

        @Test
        @DisplayName("URL of exactly 2048 characters is accepted")
        void normalize_exactly2048Chars_accepted() {
            // Build a 2048-char URL: "http://example.com/" (19) + 2029 'a' chars = 2048.
            String url2048 = "http://example.com/" + "a".repeat(2029);
            assertThat(url2048.length()).isEqualTo(2048);
            assertThatCode(() -> normalizer.normalize(url2048)).doesNotThrowAnyException();
        }

        @ParameterizedTest
        @ValueSource(strings = {"ftp://example.com/", "file:///etc/passwd"})
        @DisplayName("non-http(s) hierarchical schemes are rejected with 'not allowed' message")
        void normalize_nonHttpHierarchicalScheme_throwsValidationException(String url) {
            assertThatThrownBy(() -> normalizer.normalize(url))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("not allowed");
        }

        @ParameterizedTest
        @ValueSource(strings = {"mailto:user@example.com", "javascript:alert(1)", "data:text/html,<h1>"})
        @DisplayName("opaque (non-hierarchical) scheme URLs are rejected")
        void normalize_opaqueScheme_throwsValidationException(String url) {
            // Opaque URIs (no authority/host) fail either at parse time (URISyntaxException
            // → "not a valid URI") or at the scheme check ("not allowed") depending on content.
            assertThatThrownBy(() -> normalizer.normalize(url))
                    .isInstanceOf(ValidationException.class);
        }

        @Test
        @DisplayName("URL with userinfo (credentials) is rejected")
        void normalize_withUserInfo_throwsValidationException() {
            assertThatThrownBy(() -> normalizer.normalize("http://user:pass@example.com/"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("userinfo");
        }

        @Test
        @DisplayName("username-only userinfo is rejected")
        void normalize_usernameOnlyUserInfo_throwsValidationException() {
            assertThatThrownBy(() -> normalizer.normalize("http://user@example.com/"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("userinfo");
        }

        @ParameterizedTest
        @ValueSource(strings = {"not a url", "://example.com", "example.com", "//example.com"})
        @DisplayName("garbage / scheme-less strings are rejected")
        void normalize_garbage_throwsValidationException(String url) {
            assertThatThrownBy(() -> normalizer.normalize(url))
                    .isInstanceOf(ValidationException.class);
        }
    }

    // ==========================================================================
    // Normalize edge cases: no path, unicode host
    // ==========================================================================

    @Nested
    @DisplayName("Edge cases")
    class EdgeCases {

        @Test
        @DisplayName("URL with no explicit path gets a root '/' path")
        void normalize_noPath_rootPathAdded() {
            // java.net.URI parses "http://example.com" with rawPath="".
            assertThat(normalizer.normalize("http://example.com"))
                    .isEqualTo("http://example.com/");
        }

        @Test
        @DisplayName("duplicate slashes combined with trailing slash are both handled")
        void normalize_doubleSeparatorsAndTrailingSlash() {
            assertThat(normalizer.normalize("http://example.com//path//"))
                    .isEqualTo("http://example.com/path");
        }

        @Test
        @DisplayName("combination: uppercase host + default port + trailing slash + sorted query")
        void normalize_fullCombination() {
            assertThat(normalizer.normalize("HTTP://EXAMPLE.COM:80/Path/?z=last&a=first#frag"))
                    .isEqualTo("http://example.com/Path?a=first&z=last");
        }

        @ParameterizedTest
        @CsvSource({
                // input, expected
                "http://example.com/path?a=1&b=2, http://example.com/path?a=1&b=2",
                "http://EXAMPLE.COM:80/path?b=2&a=1, http://example.com/path?a=1&b=2",
                "HTTP://Example.COM/path/#anchor, http://example.com/path",
                "https://example.com:443//path//, https://example.com/path"
        })
        @DisplayName("table-style normalization equivalence cases")
        void normalize_tableEquivalence(String input, String expected) {
            assertThat(normalizer.normalize(input)).isEqualTo(expected);
        }
    }
}
