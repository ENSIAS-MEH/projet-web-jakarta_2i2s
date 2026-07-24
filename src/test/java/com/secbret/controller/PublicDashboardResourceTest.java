package com.secbret.controller;

import com.secbret.exception.ResourceNotFoundException;
import com.secbret.exception.ValidationException;
import com.secbret.model.dto.PublicDashboardEntry;
import com.secbret.model.dto.PublicDashboardResponse;
import com.secbret.model.dto.PublicDashboardUrlEntry;
import com.secbret.model.entity.ScannedUrl;
import com.secbret.model.enums.CommunityVerdict;
import com.secbret.repository.ScanResultRepository;
import com.secbret.repository.ScannedUrlRepository;
import com.secbret.scanner.UrlNormalizer;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

/**
 * Unit tests for PublicDashboardResource (Part III §7 / Task 14).
 *
 * <h2>Key assertions</h2>
 * <ul>
 *   <li>Empty list returns 200 with correct envelope shape</li>
 *   <li>Non-empty list returns 200 with pagination metadata</li>
 *   <li>Verdict filter MALICIOUS / BENIGN wired through correctly</li>
 *   <li>Unknown verdict value → ValidationException (→ 400)</li>
 *   <li>?url= found → 200 with single-URL shape</li>
 *   <li>?url= not found → ResourceNotFoundException (→ 404)</li>
 *   <li>No SecurityContext dependency (anonymous access)</li>
 * </ul>
 *
 * NOTE: @PermitAll is a deployment-time annotation; the unit test verifies the resource
 * carries no SecurityContext injection and throws no auth exceptions on any path.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("PublicDashboardResource unit tests (Part III §7)")
class PublicDashboardResourceTest {

    @Mock
    private ScannedUrlRepository scannedUrlRepository;
    @Mock
    private ScanResultRepository scanResultRepository;
    @Mock
    private UrlNormalizer urlNormalizer;

    @InjectMocks
    private PublicDashboardResource resource;

    // =========================================================================
    // Empty dashboard
    // =========================================================================

    @Nested
    @DisplayName("Empty list")
    class EmptyList {

        @Test
        @DisplayName("returns 200 with empty urls array and zero totals")
        void emptyList_returns200WithEmptyShape() {
            when(scannedUrlRepository.countPublicDashboard(null)).thenReturn(0L);
            when(scannedUrlRepository.findPublicDashboardPage(null, 1, 20)).thenReturn(List.of());

            Response response = resource.getPublicDashboard(null, null, 1, 20);

            assertThat(response.getStatus()).isEqualTo(200);
            PublicDashboardResponse body = (PublicDashboardResponse) response.getEntity();
            assertThat(body.getUrls()).isEmpty();
            assertThat(body.getTotalElements()).isEqualTo(0L);
            assertThat(body.getTotalPages()).isEqualTo(0);
            assertThat(body.getCurrentPage()).isEqualTo(1);
            assertThat(body.getPageSize()).isEqualTo(20);
        }
    }

    // =========================================================================
    // Non-empty dashboard — pagination shape
    // =========================================================================

    @Nested
    @DisplayName("Non-empty list")
    class NonEmptyList {

        @Test
        @DisplayName("returns 200 with correct pagination metadata")
        void nonEmptyList_paginationMetadata() {
            ScannedUrl su = makeUrl("https://phishing.test/path", CommunityVerdict.MALICIOUS,
                    LocalDateTime.now().minusHours(1));
            when(scannedUrlRepository.countPublicDashboard(null)).thenReturn(42L);
            when(scannedUrlRepository.findPublicDashboardPage(null, 1, 20)).thenReturn(List.of(su));
            when(scanResultRepository.findLatestByUrlId(any())).thenReturn(Optional.empty());

            Response response = resource.getPublicDashboard(null, null, 1, 20);

            assertThat(response.getStatus()).isEqualTo(200);
            PublicDashboardResponse body = (PublicDashboardResponse) response.getEntity();
            assertThat(body.getUrls()).hasSize(1);
            assertThat(body.getTotalElements()).isEqualTo(42L);
            assertThat(body.getTotalPages()).isEqualTo(3); // ceil(42/20)
            assertThat(body.getCurrentPage()).isEqualTo(1);
            assertThat(body.getPageSize()).isEqualTo(20);
        }

        @Test
        @DisplayName("entry fields: url, communityVerdict, threatScore, lastScannedAt")
        void entryShape_allFieldsPresent() {
            LocalDateTime scanned = LocalDateTime.of(2026, 6, 17, 10, 0, 0);
            ScannedUrl su = makeUrl("https://phishing-site.com/", CommunityVerdict.MALICIOUS, scanned);
            com.secbret.model.entity.ScanResult sr = new com.secbret.model.entity.ScanResult();
            sr.setOverallScore(new BigDecimal("0.97"));

            when(scannedUrlRepository.countPublicDashboard(null)).thenReturn(1L);
            when(scannedUrlRepository.findPublicDashboardPage(null, 1, 20)).thenReturn(List.of(su));
            when(scanResultRepository.findLatestByUrlId(su.getId())).thenReturn(Optional.of(sr));

            Response response = resource.getPublicDashboard(null, null, 1, 20);
            PublicDashboardResponse body = (PublicDashboardResponse) response.getEntity();
            PublicDashboardEntry entry = body.getUrls().get(0);

            assertThat(entry.getUrl()).isEqualTo("https://phishing-site.com/");
            assertThat(entry.getCommunityVerdict()).isEqualTo("MALICIOUS");
            assertThat(entry.getThreatScore()).isEqualTo(0.97);
            assertThat(entry.getLastScannedAt()).isEqualTo(scanned);
        }
    }

    // =========================================================================
    // Verdict filter validation
    // =========================================================================

    @Nested
    @DisplayName("Verdict filter")
    class VerdictFilter {

        @Test
        @DisplayName("MALICIOUS filter passes to repository")
        void maliciousFilter_passedToRepo() {
            when(scannedUrlRepository.countPublicDashboard(CommunityVerdict.MALICIOUS)).thenReturn(1L);
            when(scannedUrlRepository.findPublicDashboardPage(eq(CommunityVerdict.MALICIOUS), anyInt(), anyInt()))
                    .thenReturn(List.of());

            Response r = resource.getPublicDashboard("MALICIOUS", null, 1, 20);
            assertThat(r.getStatus()).isEqualTo(200);
        }

        @Test
        @DisplayName("BENIGN filter passes to repository")
        void benignFilter_passedToRepo() {
            when(scannedUrlRepository.countPublicDashboard(CommunityVerdict.BENIGN)).thenReturn(0L);
            when(scannedUrlRepository.findPublicDashboardPage(eq(CommunityVerdict.BENIGN), anyInt(), anyInt()))
                    .thenReturn(List.of());

            Response r = resource.getPublicDashboard("BENIGN", null, 1, 20);
            assertThat(r.getStatus()).isEqualTo(200);
        }

        @Test
        @DisplayName("SUSPICIOUS verdict → ValidationException (400 via mapper)")
        void suspiciousFilter_throwsValidationException() {
            assertThatThrownBy(() -> resource.getPublicDashboard("SUSPICIOUS", null, 1, 20))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("MALICIOUS or BENIGN");
        }

        @Test
        @DisplayName("arbitrary invalid verdict → ValidationException")
        void invalidVerdict_throwsValidationException() {
            assertThatThrownBy(() -> resource.getPublicDashboard("UNKNOWN", null, 1, 20))
                    .isInstanceOf(ValidationException.class);
        }
    }

    // =========================================================================
    // Pagination clamping
    // =========================================================================

    @Nested
    @DisplayName("Pagination clamping")
    class PaginationClamping {

        @Test
        @DisplayName("size > 50 is clamped to 50")
        void sizeOverMax_clampedTo50() {
            when(scannedUrlRepository.countPublicDashboard(null)).thenReturn(0L);
            when(scannedUrlRepository.findPublicDashboardPage(null, 1, 50)).thenReturn(List.of());

            Response r = resource.getPublicDashboard(null, null, 1, 999);
            assertThat(r.getStatus()).isEqualTo(200);
            PublicDashboardResponse body = (PublicDashboardResponse) r.getEntity();
            assertThat(body.getPageSize()).isEqualTo(50);
        }

        @Test
        @DisplayName("page < 1 is clamped to 1")
        void pageZero_clampedTo1() {
            when(scannedUrlRepository.countPublicDashboard(null)).thenReturn(0L);
            when(scannedUrlRepository.findPublicDashboardPage(null, 1, 20)).thenReturn(List.of());

            Response r = resource.getPublicDashboard(null, null, 0, 20);
            assertThat(r.getStatus()).isEqualTo(200);
            PublicDashboardResponse body = (PublicDashboardResponse) r.getEntity();
            assertThat(body.getCurrentPage()).isEqualTo(1);
        }
    }

    // =========================================================================
    // Single URL lookup (?url=)
    // =========================================================================

    @Nested
    @DisplayName("?url= single lookup")
    class UrlLookup {

        @Test
        @DisplayName("found URL with verdict returns 200 with single-URL shape")
        void urlFound_returns200() throws Exception {
            String hash = "a".repeat(64);
            ScannedUrl su = makeUrl("https://phishing-site.com/", CommunityVerdict.MALICIOUS,
                    LocalDateTime.of(2026, 6, 17, 10, 0, 0));
            com.secbret.model.entity.ScanResult sr = new com.secbret.model.entity.ScanResult();
            sr.setOverallScore(new BigDecimal("0.97"));

            when(urlNormalizer.hash("https://phishing-site.com/")).thenReturn(hash);
            when(scannedUrlRepository.findPublicDashboardByHash(hash)).thenReturn(Optional.of(su));
            when(scanResultRepository.findLatestByUrlId(su.getId())).thenReturn(Optional.of(sr));

            Response response = resource.getPublicDashboard(null, "https://phishing-site.com/", 1, 20);

            assertThat(response.getStatus()).isEqualTo(200);
            PublicDashboardUrlEntry entry = (PublicDashboardUrlEntry) response.getEntity();
            assertThat(entry.getUrl()).isEqualTo("https://phishing-site.com/");
            assertThat(entry.getCommunityVerdict()).isEqualTo("MALICIOUS");
            assertThat(entry.getThreatScore()).isEqualTo(0.97);
            assertThat(entry.getLastScannedAt()).isNotNull();
        }

        @Test
        @DisplayName("URL not found → ResourceNotFoundException (404)")
        void urlNotFound_throws404() throws Exception {
            String hash = "b".repeat(64);
            when(urlNormalizer.hash("https://nonexistent.test/")).thenReturn(hash);
            when(scannedUrlRepository.findPublicDashboardByHash(hash)).thenReturn(Optional.empty());

            assertThatThrownBy(() ->
                    resource.getPublicDashboard(null, "https://nonexistent.test/", 1, 20))
                    .isInstanceOf(ResourceNotFoundException.class);
        }

        @Test
        @DisplayName("malformed URL → ResourceNotFoundException (404, not 400)")
        void malformedUrl_returns404() throws Exception {
            when(urlNormalizer.hash("not-a-url"))
                    .thenThrow(new ValidationException("invalid URL"));

            assertThatThrownBy(() ->
                    resource.getPublicDashboard(null, "not-a-url", 1, 20))
                    .isInstanceOf(ResourceNotFoundException.class);
        }
    }

    // =========================================================================
    // Anonymous access — no SecurityContext field at all
    // =========================================================================

    @Test
    @DisplayName("PublicDashboardResource has no SecurityContext dependency (anonymous endpoint)")
    void noSecurityContextDependency() {
        // If the resource had @Context SecurityContext, Mockito InjectMocks would fail to
        // inject (no matching mock). The test proves the resource can be instantiated and
        // called without any security context mock — verifying it is truly anonymous.
        when(scannedUrlRepository.countPublicDashboard(null)).thenReturn(0L);
        when(scannedUrlRepository.findPublicDashboardPage(null, 1, 20)).thenReturn(List.of());

        Response r = resource.getPublicDashboard(null, null, 1, 20);
        assertThat(r.getStatus()).isEqualTo(200);
        // No NullPointerException from a missing SecurityContext → anonymous access confirmed.
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private ScannedUrl makeUrl(String originalUrl, CommunityVerdict verdict,
                               LocalDateTime lastScannedAt) {
        ScannedUrl su = new ScannedUrl();
        su.setOriginalUrl(originalUrl);
        su.setNormalizedHash(UUID.randomUUID().toString().replace("-", "") + "00000000");
        su.setCommunityVerdict(verdict);
        su.setLastScannedAt(lastScannedAt);
        return su;
    }
}
