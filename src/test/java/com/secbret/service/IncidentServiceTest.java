package com.secbret.service;

import com.secbret.ai.AutoActionVerdict;
import com.secbret.ai.RuleInput;
import com.secbret.ai.RuleResult;
import com.secbret.ai.ScoringService;
import com.secbret.ai.TentativeVerdict;
import com.secbret.ai.ThreatDisposition;
import com.secbret.model.entity.ScannedUrl;
import com.secbret.model.entity.SecBretAnalysis;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.entity.UserReport;
import com.secbret.model.enums.CommunityVerdict;
import com.secbret.repository.SecBretAnalysisRepository;
import com.secbret.repository.ScannedUrlRepository;
import com.secbret.repository.UserReportRepository;
import com.secbret.repository.UserRepository;
import com.secbret.scanner.UrlNormalizer;
import jakarta.enterprise.concurrent.ManagedExecutorService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.math.BigDecimal;
import java.util.Optional;
import java.util.OptionalDouble;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for IncidentService.
 *
 * <p>Tests cover:
 * <ul>
 *   <li>Auto-resolution band: VERIFIED_MALICIOUS (combinedScore ≥ 0.95)</li>
 *   <li>Auto-resolution band: VERIFIED_BENIGN (combinedScore ≤ 0.05)</li>
 *   <li>PENDING_REVIEW band (0.05 &lt; combinedScore &lt; 0.95)</li>
 *   <li>§16.5 FAILED path when secbret_analysis INSERT fails</li>
 *   <li>C4 guard: secbret_analysis.verdict never receives VERIFIED_* values</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IncidentServiceTest {

    @Mock private ScoringService scoringService;
    @Mock private UrlNormalizer urlNormalizer;
    @Mock private ScannedUrlRepository scannedUrlRepository;
    @Mock private UserRepository userRepository;
    @Mock private UserReportRepository reportRepository;
    @Mock private SecBretAnalysisRepository analysisRepository;
    @Mock private ManagedExecutorService executor;

    private IncidentService service;

    private static final String HASH = "a".repeat(64);
    private UUID urlId;
    private UUID reportId;
    private ScannedUrl mockUrl;
    private UserReport mockReport;

    @BeforeEach
    void setUp() {
        service = new IncidentService();
        // Inject mocks via field injection (test-only; production uses @PersistenceContext)
        inject(service, "scoringService", scoringService);
        inject(service, "urlNormalizer", urlNormalizer);
        inject(service, "scannedUrlRepository", scannedUrlRepository);
        inject(service, "userRepository", userRepository);
        inject(service, "reportRepository", reportRepository);
        inject(service, "analysisRepository", analysisRepository);
        inject(service, "executor", executor);

        urlId = UUID.randomUUID();
        reportId = UUID.randomUUID();

        mockUrl = new ScannedUrl();
        setId(mockUrl, urlId);
        mockUrl.setOriginalUrl("https://phishing.example.com");

        mockReport = new UserReport();
        setId(mockReport, reportId);
        mockReport.setUrl(mockUrl);
        mockReport.setStatus("PENDING");

    }

    // =========================================================================
    // persistAnalysis — C4 guard
    // =========================================================================

    @Nested
    @DisplayName("C4 guard: secbret_analysis.verdict never receives VERIFIED_* values")
    class C4Guard {

        @Test
        @DisplayName("persistAnalysis writes BENIGN to secbret_analysis.verdict when score=0.0")
        void persistAnalysis_lowScore_writesBenign() {
            ThreatDisposition d = disposition(0.0, AutoActionVerdict.VERIFIED_BENIGN, TentativeVerdict.BENIGN, false);
            when(scoringService.score(anyString(), any(), any())).thenReturn(d);

            service.persistAnalysis(reportId, urlId, d);

            ArgumentCaptor<SecBretAnalysis> cap = ArgumentCaptor.forClass(SecBretAnalysis.class);
            verify(analysisRepository).persistForReport(org.mockito.ArgumentMatchers.eq(reportId), org.mockito.ArgumentMatchers.eq(urlId), cap.capture());
            SecBretAnalysis written = cap.getValue();

            // C4: MUST be BENIGN or SUSPICIOUS — never VERIFIED_*
            assertThat(written.getVerdict()).isIn("BENIGN", "SUSPICIOUS");
            assertThat(written.getVerdict()).doesNotContain("VERIFIED");
            assertThat(written.getVerdict()).isEqualTo("BENIGN"); // 0.0 ≤ 0.05 → BENIGN
        }

        @Test
        @DisplayName("persistAnalysis writes SUSPICIOUS to secbret_analysis.verdict when score=1.0")
        void persistAnalysis_highScore_writesSuspicious() {
            ThreatDisposition d = disposition(1.0, AutoActionVerdict.VERIFIED_MALICIOUS, TentativeVerdict.SUSPICIOUS, false);

            service.persistAnalysis(reportId, urlId, d);

            ArgumentCaptor<SecBretAnalysis> cap = ArgumentCaptor.forClass(SecBretAnalysis.class);
            verify(analysisRepository).persistForReport(org.mockito.ArgumentMatchers.eq(reportId), org.mockito.ArgumentMatchers.eq(urlId), cap.capture());
            SecBretAnalysis written = cap.getValue();

            // C4: even with VERIFIED_MALICIOUS autoAction, secbret_analysis.verdict = SUSPICIOUS
            assertThat(written.getVerdict()).isEqualTo("SUSPICIOUS");
            assertThat(written.getVerdict()).doesNotContain("VERIFIED");
        }

        @Test
        @DisplayName("persistAnalysis writes SUSPICIOUS when score=0.72 (PENDING_REVIEW band)")
        void persistAnalysis_midScore_writesSuspicious() {
            ThreatDisposition d = disposition(0.72, AutoActionVerdict.PENDING_REVIEW, TentativeVerdict.SUSPICIOUS, true);

            service.persistAnalysis(reportId, urlId, d);

            ArgumentCaptor<SecBretAnalysis> cap = ArgumentCaptor.forClass(SecBretAnalysis.class);
            verify(analysisRepository).persistForReport(org.mockito.ArgumentMatchers.eq(reportId), org.mockito.ArgumentMatchers.eq(urlId), cap.capture());
            assertThat(cap.getValue().getVerdict()).isEqualTo("SUSPICIOUS");
        }
    }

    // =========================================================================
    // resolveReport — auto-resolution bands
    // =========================================================================

    @Nested
    @DisplayName("Auto-resolution bands (delegated to UserReportRepository.resolveInTx)")
    class AutoResolutionBands {

        @Test
        @DisplayName("VERIFIED_MALICIOUS band → resolveInTx(status=VERIFIED, verdict=VERIFIED_MALICIOUS, community=MALICIOUS)")
        void resolveReport_maliciousBand_setsVerifiedMalicious() {
            service.resolveReport(reportId, urlId, UUID.randomUUID(), AutoActionVerdict.VERIFIED_MALICIOUS);

            verify(reportRepository).resolveInTx(reportId, urlId, "VERIFIED",
                    "VERIFIED_MALICIOUS", CommunityVerdict.MALICIOUS);
        }

        @Test
        @DisplayName("VERIFIED_BENIGN band → resolveInTx(status=VERIFIED, verdict=VERIFIED_BENIGN, community=BENIGN)")
        void resolveReport_benignBand_setsVerifiedBenign() {
            // §17 Open Question #2: auto-benign DOES set community_verdict=BENIGN
            service.resolveReport(reportId, urlId, UUID.randomUUID(), AutoActionVerdict.VERIFIED_BENIGN);

            verify(reportRepository).resolveInTx(reportId, urlId, "VERIFIED",
                    "VERIFIED_BENIGN", CommunityVerdict.BENIGN);
        }

        @Test
        @DisplayName("PENDING_REVIEW band → resolveInTx(status=PENDING_REVIEW, verdict=null, community=null)")
        void resolveReport_pendingReviewBand_setsPendingReview() {
            service.resolveReport(reportId, urlId, UUID.randomUUID(), AutoActionVerdict.PENDING_REVIEW);

            verify(reportRepository).resolveInTx(reportId, urlId, "PENDING_REVIEW", null, null);
        }
    }

    // =========================================================================
    // B5 audit sampling (AUTO_DECISION_SAMPLE_RATE, Known Gap #18)
    // =========================================================================

    @Nested
    @DisplayName("B5 audit sampling: auto-decisions diverted to human review")
    class B5AuditSampling {

        @Test
        @DisplayName("rate=1.0 → VERIFIED_MALICIOUS auto-block diverted to PENDING_REVIEW")
        void resolveReport_rateOne_maliciousDivertedToReview() {
            service.auditSampleRate = 1.0;

            service.resolveReport(reportId, urlId, UUID.randomUUID(), AutoActionVerdict.VERIFIED_MALICIOUS);

            verify(reportRepository).resolveInTx(reportId, urlId, "PENDING_REVIEW", null, null);
        }

        @Test
        @DisplayName("rate=1.0 → VERIFIED_BENIGN also sampled (spec §6: all auto-decided reports)")
        void resolveReport_rateOne_benignDivertedToReview() {
            service.auditSampleRate = 1.0;

            service.resolveReport(reportId, urlId, UUID.randomUUID(), AutoActionVerdict.VERIFIED_BENIGN);

            verify(reportRepository).resolveInTx(reportId, urlId, "PENDING_REVIEW", null, null);
        }

        @Test
        @DisplayName("rate=0.0 (default) → auto-decision publishes normally")
        void resolveReport_rateZero_autoDecisionUnaffected() {
            service.auditSampleRate = 0.0;

            service.resolveReport(reportId, urlId, UUID.randomUUID(), AutoActionVerdict.VERIFIED_MALICIOUS);

            verify(reportRepository).resolveInTx(reportId, urlId, "VERIFIED",
                    "VERIFIED_MALICIOUS", CommunityVerdict.MALICIOUS);
        }

        @Test
        @DisplayName("parseSampleRate: blank/garbage → 0.0, out-of-range clamped to [0,1]")
        void parseSampleRate_clampsAndDefaults() {
            assertThat(IncidentService.parseSampleRate(null)).isEqualTo(0.0);
            assertThat(IncidentService.parseSampleRate("  ")).isEqualTo(0.0);
            assertThat(IncidentService.parseSampleRate("nope")).isEqualTo(0.0);
            assertThat(IncidentService.parseSampleRate("0.05")).isEqualTo(0.05);
            assertThat(IncidentService.parseSampleRate("-3")).isEqualTo(0.0);
            assertThat(IncidentService.parseSampleRate("7")).isEqualTo(1.0);
        }
    }

    // =========================================================================
    // §16.5 FAILED path
    // =========================================================================

    @Nested
    @DisplayName("§16.5 FAILED path: analysis INSERT failure")
    class FailedPath {

        @Test
        @DisplayName("When secbret_analysis INSERT throws, user_report is marked FAILED with error_message")
        void runAnalysis_analysisInsertFails_marksReportFailed() {
            ThreatDisposition d = disposition(0.72, AutoActionVerdict.PENDING_REVIEW, TentativeVerdict.SUSPICIOUS, false);
            when(scoringService.score(anyString(), any(), any())).thenReturn(d);

            // Make persistAnalysis throw (simulates DB write failure)
            when(analysisRepository.persistForReport(any(), any(), any())).thenThrow(new RuntimeException("DB constraint violation"));

            // runAnalysis catches the exception and marks FAILED via repo (§16.5)
            service.runAnalysis(reportId, urlId);

            ArgumentCaptor<String> msg = ArgumentCaptor.forClass(String.class);
            verify(reportRepository).markFailedInTx(org.mockito.ArgumentMatchers.eq(reportId), msg.capture());
            assertThat(msg.getValue()).contains("Analysis persistence failed");
        }

        @Test
        @DisplayName("When scoring throws, user_report is marked FAILED")
        void runAnalysis_scoringFails_marksReportFailed() {
            when(scoringService.score(anyString(), any(), any()))
                    .thenThrow(new RuntimeException("ML sidecar connection refused"));

            service.runAnalysis(reportId, urlId);

            ArgumentCaptor<String> msg = ArgumentCaptor.forClass(String.class);
            verify(reportRepository).markFailedInTx(org.mockito.ArgumentMatchers.eq(reportId), msg.capture());
            assertThat(msg.getValue()).contains("Scoring error");
        }
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private ThreatDisposition disposition(double score, AutoActionVerdict autoAction,
                                           TentativeVerdict tentative, boolean mlConsulted) {
        RuleResult rr = new RuleResult(score, false, java.util.List.of());
        return new ThreatDisposition(rr, score, mlConsulted,
                mlConsulted ? OptionalDouble.of(score * 0.9) : OptionalDouble.empty(),
                autoAction, tentative, null);
    }

    /** Reflective field injector for package-private @Inject fields. */
    private static void inject(Object target, String fieldName, Object value) {
        try {
            var f = findField(target.getClass(), fieldName);
            f.setAccessible(true);
            f.set(target, value);
        } catch (Exception e) {
            throw new RuntimeException("Could not inject " + fieldName, e);
        }
    }

    private static java.lang.reflect.Field findField(Class<?> clazz, String name) throws NoSuchFieldException {
        try {
            return clazz.getDeclaredField(name);
        } catch (NoSuchFieldException e) {
            if (clazz.getSuperclass() != null) return findField(clazz.getSuperclass(), name);
            throw e;
        }
    }

    private static void setId(Object entity, UUID id) {
        try {
            var f = entity.getClass().getDeclaredField("id");
            f.setAccessible(true);
            f.set(entity, id);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
