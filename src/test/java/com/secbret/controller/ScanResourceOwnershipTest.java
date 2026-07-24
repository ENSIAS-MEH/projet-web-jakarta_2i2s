package com.secbret.controller;

import com.secbret.exception.AuthorizationException;
import com.secbret.exception.ResourceNotFoundException;
import com.secbret.model.entity.ScanJob;
import com.secbret.model.entity.ScannedUrl;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.enums.ScanDepth;
import com.secbret.model.enums.ScanJobStatus;
import com.secbret.model.enums.UserRole;
import com.secbret.repository.ScanJobRepository;
import com.secbret.repository.ScanResultRepository;
import com.secbret.repository.ScannedUrlRepository;
import com.secbret.repository.UserRepository;
import com.secbret.service.ScanExecutor;
import com.secbret.service.ScanPersistence;
import jakarta.ws.rs.core.SecurityContext;
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

import java.security.Principal;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for ScanResource ownership and role-based access semantics (Part III §2 /
 * Part II §A.2 / Part II §4).
 *
 * <h2>Key rules under test</h2>
 * <ul>
 *   <li>REPORTER accessing another user's job → 404 (not 403, anti-enumeration)</li>
 *   <li>REPORTER accessing a URL they never scanned → 404 (not 403)</li>
 *   <li>REPORTER using ?all=true → 403 (role-permission failure, not ownership)</li>
 *   <li>ANALYST/ADMIN may access any job → 200 path</li>
 * </ul>
 *
 * All tests run without a container (Mockito only).
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("ScanResource ownership + role rules")
class ScanResourceOwnershipTest {

    @Mock
    private ScanJobRepository scanJobRepository;
    @Mock
    private ScanResultRepository scanResultRepository;
    @Mock
    private ScannedUrlRepository scannedUrlRepository;
    @Mock
    private UserRepository userRepository;
    @Mock
    private ScanPersistence scanPersistence;
    @Mock
    private ScanExecutor scanExecutor;
    @Mock
    private SecurityContext securityContext;

    @InjectMocks
    private ScanResource resource;

    private final UUID ownerUserId    = UUID.randomUUID();
    private final UUID otherUserId    = UUID.randomUUID();
    private final UUID jobId          = UUID.randomUUID();
    private final UUID otherJobId     = UUID.randomUUID();
    private final UUID urlId          = UUID.randomUUID();

    private SecBretUser ownerUser;
    private ScanJob ownerJob;

    @BeforeEach
    void setUp() {
        ownerUser = new SecBretUser();
        ownerUser.setUsername("reporter1");
        ownerUser.setRole(UserRole.REPORTER);

        ScannedUrl scannedUrl = new ScannedUrl();
        scannedUrl.setOriginalUrl("https://example.test/page");

        ownerJob = new ScanJob();
        ownerJob.setUrl(scannedUrl);
        ownerJob.setScanDepth(ScanDepth.QUICK);
        ownerJob.setStatus(ScanJobStatus.PENDING);
        ownerJob.setSubmittedBy(ownerUser);
    }

    // =========================================================================
    // GET /scan/{jobId} — ownership
    // =========================================================================

    @Nested
    @DisplayName("GET /scan/{jobId}")
    class GetJob {

        @Test
        @DisplayName("REPORTER accessing own job returns 200 path (no exception)")
        void reporter_ownJob_ok() {
            stubReporter("reporter1");
            stubUserLookup("reporter1", ownerUserId);
            // ownerJob.submittedBy.id must match ownerUserId
            SecBretUser u = userWithId(ownerUserId);
            ownerJob.setSubmittedBy(u);
            when(scanJobRepository.findByIdEager(jobId)).thenReturn(Optional.of(ownerJob));
            when(scanResultRepository.findByScanJobId(any())).thenReturn(Optional.empty());

            // Should NOT throw
            resource.getJob(jobId);
        }

        @Test
        @DisplayName("REPORTER accessing another user's job → 404 (anti-enumeration, not 403)")
        void reporter_otherUsersJob_returns404() {
            stubReporter("reporter1");
            stubUserLookup("reporter1", ownerUserId);
            // job belongs to otherUser
            ScanJob otherJob = buildJob(userWithId(otherUserId));
            when(scanJobRepository.findByIdEager(otherJobId)).thenReturn(Optional.of(otherJob));

            assertThatThrownBy(() -> resource.getJob(otherJobId))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .as("Must be 404, not 403 — ownership-hidden per Part II §A.2");
        }

        @Test
        @DisplayName("REPORTER accessing a job with null submittedBy → 404")
        void reporter_jobNoOwner_returns404() {
            stubReporter("reporter1");
            stubUserLookup("reporter1", ownerUserId);
            ScanJob anonJob = buildJob(null);
            when(scanJobRepository.findByIdEager(jobId)).thenReturn(Optional.of(anonJob));

            assertThatThrownBy(() -> resource.getJob(jobId))
                    .isInstanceOf(ResourceNotFoundException.class);
        }

        @Test
        @DisplayName("ANALYST accessing any job returns 200 path (no exception)")
        void analyst_anyJob_ok() {
            stubAnalyst("analyst1");
            stubUserLookup("analyst1", UUID.randomUUID());
            ScanJob otherJob = buildJob(userWithId(otherUserId));
            otherJob.setStatus(ScanJobStatus.COMPLETED);
            when(scanJobRepository.findByIdEager(otherJobId)).thenReturn(Optional.of(otherJob));
            when(scanResultRepository.findByScanJobId(any())).thenReturn(Optional.empty());

            // Should NOT throw
            resource.getJob(otherJobId);
        }
    }

    // =========================================================================
    // GET /scan?all=true — role-based 403
    // =========================================================================

    @Nested
    @DisplayName("GET /scan?all=true")
    class ListAll {

        @Test
        @DisplayName("REPORTER with ?all=true → 403 (role-permission failure)")
        void reporter_allTrue_returns403() {
            stubReporter("reporter1");
            stubUserLookup("reporter1", ownerUserId);

            assertThatThrownBy(() -> resource.listScans(true, null, null, 1, 20))
                    .isInstanceOf(AuthorizationException.class)
                    .as("REPORTER + ?all=true must be 403, not 404 — role-permission failure per §A.2");
        }

        @Test
        @DisplayName("ANALYST with ?all=true returns 200 path (no exception)")
        void analyst_allTrue_ok() {
            stubAnalyst("analyst1");
            stubUserLookup("analyst1", UUID.randomUUID());
            when(scanJobRepository.count(null, null, null)).thenReturn(0L);
            when(scanJobRepository.findPage(null, null, null, 1, 20)).thenReturn(List.of());

            // Should NOT throw
            resource.listScans(true, null, null, 1, 20);
        }

        @Test
        @DisplayName("REPORTER without ?all=true sees only own jobs (no exception)")
        void reporter_allFalse_ok() {
            stubReporter("reporter1");
            stubUserLookup("reporter1", ownerUserId);
            when(scanJobRepository.count(ownerUserId, null, null)).thenReturn(0L);
            when(scanJobRepository.findPage(ownerUserId, null, null, 1, 20)).thenReturn(List.of());

            // Should NOT throw
            resource.listScans(false, null, null, 1, 20);
        }
    }

    // =========================================================================
    // GET /scan/url/{urlId} — ownership 404
    // =========================================================================

    @Nested
    @DisplayName("GET /scan/url/{urlId}")
    class GetUrlView {

        @Test
        @DisplayName("REPORTER who has scanned the URL → 200 path (no exception)")
        void reporter_hasScannedUrl_ok() {
            stubReporter("reporter1");
            stubUserLookup("reporter1", ownerUserId);
            ScannedUrl su = scannedUrlWithId(urlId);
            when(scannedUrlRepository.findById(urlId)).thenReturn(Optional.of(su));
            when(scanJobRepository.existsByUrlIdAndSubmittedBy(urlId, ownerUserId)).thenReturn(true);
            when(scanResultRepository.findLatestByUrlId(urlId)).thenReturn(Optional.empty());

            // Should NOT throw
            resource.getUrlView(urlId);
        }

        @Test
        @DisplayName("REPORTER who has NOT scanned the URL → 404 (ownership-hidden, not 403)")
        void reporter_neverScannedUrl_returns404() {
            stubReporter("reporter1");
            stubUserLookup("reporter1", ownerUserId);
            ScannedUrl su = scannedUrlWithId(urlId);
            when(scannedUrlRepository.findById(urlId)).thenReturn(Optional.of(su));
            when(scanJobRepository.existsByUrlIdAndSubmittedBy(urlId, ownerUserId)).thenReturn(false);

            assertThatThrownBy(() -> resource.getUrlView(urlId))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .as("Must be 404 not 403 — ownership-hidden per §A.2 and §4");
        }

        @Test
        @DisplayName("ANALYST viewing any URL → 200 path (no exception)")
        void analyst_anyUrl_ok() {
            stubAnalyst("analyst1");
            stubUserLookup("analyst1", UUID.randomUUID());
            ScannedUrl su = scannedUrlWithId(urlId);
            when(scannedUrlRepository.findById(urlId)).thenReturn(Optional.of(su));
            when(scanResultRepository.findLatestByUrlId(urlId)).thenReturn(Optional.empty());

            // Should NOT throw
            resource.getUrlView(urlId);
        }
    }

    // =========================================================================
    // Helper stubs
    // =========================================================================

    private void stubReporter(String username) {
        Principal principal = () -> username;
        when(securityContext.getUserPrincipal()).thenReturn(principal);
        when(securityContext.isUserInRole("REPORTER")).thenReturn(true);
        when(securityContext.isUserInRole("ANALYST")).thenReturn(false);
        when(securityContext.isUserInRole("ADMIN")).thenReturn(false);
    }

    private void stubAnalyst(String username) {
        Principal principal = () -> username;
        when(securityContext.getUserPrincipal()).thenReturn(principal);
        when(securityContext.isUserInRole("REPORTER")).thenReturn(false);
        when(securityContext.isUserInRole("ANALYST")).thenReturn(true);
        when(securityContext.isUserInRole("ADMIN")).thenReturn(false);
    }

    private void stubUserLookup(String username, UUID userId) {
        SecBretUser user = userWithId(userId);
        user.setUsername(username);
        when(userRepository.findByUsername(username)).thenReturn(Optional.of(user));
    }

    private SecBretUser userWithId(UUID id) {
        // Reflectively set the id since there's no setter (generated by JPA).
        try {
            SecBretUser u = new SecBretUser();
            u.setUsername("user-" + id);
            java.lang.reflect.Field f = SecBretUser.class.getDeclaredField("id");
            f.setAccessible(true);
            f.set(u, id);
            return u;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private ScanJob buildJob(SecBretUser owner) {
        ScannedUrl url = new ScannedUrl();
        url.setOriginalUrl("https://example.test/other");
        ScanJob j = new ScanJob();
        j.setUrl(url);
        j.setScanDepth(ScanDepth.QUICK);
        j.setStatus(ScanJobStatus.PENDING);
        j.setSubmittedBy(owner);
        return j;
    }

    private ScannedUrl scannedUrlWithId(UUID id) {
        try {
            ScannedUrl su = new ScannedUrl();
            su.setOriginalUrl("https://example.test/scan-url");
            su.setNormalizedHash("abc123");
            java.lang.reflect.Field f = ScannedUrl.class.getDeclaredField("id");
            f.setAccessible(true);
            f.set(su, id);
            return su;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
