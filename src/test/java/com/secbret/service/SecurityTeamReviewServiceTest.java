package com.secbret.service;

import com.secbret.exception.ConflictException;
import com.secbret.exception.ValidationException;
import com.secbret.model.entity.ScannedUrl;
import com.secbret.model.entity.SecBretAnalysis;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.entity.SecurityTeamReview;
import com.secbret.model.entity.UserReport;
import com.secbret.model.enums.CommunityVerdict;
import com.secbret.repository.AuditLogRepository;
import com.secbret.repository.SecBretAnalysisRepository;
import com.secbret.repository.SecurityTeamReviewRepository;
import com.secbret.repository.UserReportRepository;
import com.secbret.repository.UserRepository;
import jakarta.persistence.EntityManager;
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
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for SecurityTeamReviewService.
 *
 * <p><strong>C4 guard (the critical test):</strong>
 * MODIFY must write VERIFIED_* to final-verdict tables only —
 * secbret_analysis.verdict must NEVER be touched.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SecurityTeamReviewServiceTest {

    @Mock private UserReportRepository reportRepository;
    @Mock private SecBretAnalysisRepository analysisRepository;
    @Mock private SecurityTeamReviewRepository reviewRepository;
    @Mock private UserRepository userRepository;
    @Mock private AuditLogRepository auditLogRepository;
    @Mock private EntityManager em;

    private SecurityTeamReviewService service;

    private UUID reportId;
    private UUID reviewerId;
    private UUID analysisId;
    private UserReport mockReport;
    private ScannedUrl mockUrl;
    private SecBretAnalysis mockAnalysis;
    private SecBretUser mockReviewer;

    @BeforeEach
    void setUp() {
        service = new SecurityTeamReviewService();
        inject(service, "reportRepository", reportRepository);
        inject(service, "analysisRepository", analysisRepository);
        inject(service, "reviewRepository", reviewRepository);
        inject(service, "userRepository", userRepository);
        inject(service, "em", em);

        // Wire AuditLogService with its repo
        AuditLogService auditLogService = new AuditLogService(auditLogRepository);
        inject(service, "auditLogService", auditLogService);

        reportId = UUID.randomUUID();
        reviewerId = UUID.randomUUID();
        analysisId = UUID.randomUUID();

        mockUrl = new ScannedUrl();
        setId(mockUrl, UUID.randomUUID());

        mockReport = new UserReport();
        setId(mockReport, reportId);
        mockReport.setUrl(mockUrl);
        mockReport.setStatus("PENDING_REVIEW");

        mockAnalysis = new SecBretAnalysis();
        setId(mockAnalysis, analysisId);
        mockAnalysis.setVerdict("SUSPICIOUS");
        mockAnalysis.setThreatScore(new BigDecimal("0.72"));
        mockAnalysis.setUserReport(mockReport);

        mockReviewer = new SecBretUser();
        setId(mockReviewer, reviewerId);
        mockReviewer.setUsername("analyst_jane");

        when(em.find(UserReport.class, reportId)).thenReturn(mockReport);
        when(reviewRepository.findByUserReportId(reportId)).thenReturn(Optional.empty());
        when(analysisRepository.findByUserReportId(reportId)).thenReturn(Optional.of(mockAnalysis));
        when(userRepository.findById(reviewerId)).thenReturn(Optional.of(mockReviewer));
        when(reviewRepository.persist(any())).thenAnswer(i -> i.getArgument(0));
    }

    // =========================================================================
    // C4 — THE CRITICAL TEST
    // =========================================================================

    @Nested
    @DisplayName("C4: secbret_analysis.verdict is NEVER written by reviewer corrections")
    class C4AnalysisVerdictNotWritten {

        @Test
        @DisplayName("MODIFY action: secbret_analysis.verdict remains untouched (C4 proof)")
        void modify_doesNotWriteToSecbretAnalysisVerdict() {
            String originalAnalysisVerdict = mockAnalysis.getVerdict(); // SUSPICIOUS

            service.submitReview(reportId, reviewerId, "MODIFY", "VERIFIED_BENIGN", "False positive");

            // C4 PROOF: secbret_analysis.verdict must be UNCHANGED
            assertThat(mockAnalysis.getVerdict())
                    .as("C4 violation: secbret_analysis.verdict must not be written by reviewer MODIFY")
                    .isEqualTo(originalAnalysisVerdict);

            // Confirm that user_report.verdict was written (not secbret_analysis)
            assertThat(mockReport.getVerdict()).isEqualTo("VERIFIED_BENIGN");
            assertThat(mockReport.getStatus()).isEqualTo("VERIFIED");
        }

        @Test
        @DisplayName("APPROVE action: secbret_analysis.verdict remains untouched (C4 proof)")
        void approve_doesNotWriteToSecbretAnalysisVerdict() {
            String originalAnalysisVerdict = mockAnalysis.getVerdict();

            service.submitReview(reportId, reviewerId, "APPROVE", null, "Confirmed phishing");

            assertThat(mockAnalysis.getVerdict())
                    .as("C4: APPROVE must not touch secbret_analysis.verdict")
                    .isEqualTo(originalAnalysisVerdict);
        }

        @Test
        @DisplayName("REJECT action: secbret_analysis.verdict remains untouched (C4 proof)")
        void reject_doesNotWriteToSecbretAnalysisVerdict() {
            String originalAnalysisVerdict = mockAnalysis.getVerdict();

            service.submitReview(reportId, reviewerId, "REJECT", null, "Invalid report");

            assertThat(mockAnalysis.getVerdict())
                    .as("C4: REJECT must not touch secbret_analysis.verdict")
                    .isEqualTo(originalAnalysisVerdict);
        }
    }

    // =========================================================================
    // APPROVE action
    // =========================================================================

    @Nested
    @DisplayName("APPROVE action")
    class ApproveAction {

        @Test
        @DisplayName("score=0.72 (>= 0.50 threshold) → VERIFIED_MALICIOUS + community_verdict=MALICIOUS")
        void approve_highScore_verifiedMalicious() {
            mockAnalysis.setThreatScore(new BigDecimal("0.72"));

            service.submitReview(reportId, reviewerId, "APPROVE", null, "Confirmed");

            ArgumentCaptor<SecurityTeamReview> cap = ArgumentCaptor.forClass(SecurityTeamReview.class);
            verify(reviewRepository).persist(cap.capture());
            SecurityTeamReview review = cap.getValue();

            assertThat(review.getFinalVerdict()).isEqualTo("VERIFIED_MALICIOUS");
            assertThat(review.getStatus()).isEqualTo("APPROVED");
            assertThat(mockReport.getVerdict()).isEqualTo("VERIFIED_MALICIOUS");
            assertThat(mockUrl.getCommunityVerdict()).isEqualTo(CommunityVerdict.MALICIOUS);
        }

        @Test
        @DisplayName("score=0.30 (< 0.50 threshold) → VERIFIED_BENIGN + community_verdict=BENIGN")
        void approve_lowScore_verifiedBenign() {
            mockAnalysis.setThreatScore(new BigDecimal("0.30"));

            service.submitReview(reportId, reviewerId, "APPROVE", null, "Borderline but benign");

            assertThat(mockReport.getVerdict()).isEqualTo("VERIFIED_BENIGN");
            assertThat(mockUrl.getCommunityVerdict()).isEqualTo(CommunityVerdict.BENIGN);
        }
    }

    // =========================================================================
    // REJECT action (§8.5: community_verdict NOT modified)
    // =========================================================================

    @Nested
    @DisplayName("REJECT action")
    class RejectAction {

        @Test
        @DisplayName("REJECT: user_report.status=REJECTED, verdict=REJECTED, community_verdict unchanged")
        void reject_setsRejectedDoesNotChangeCommunityVerdict() {
            mockUrl.setCommunityVerdict(CommunityVerdict.MALICIOUS); // existing verdict

            service.submitReview(reportId, reviewerId, "REJECT", null, "Invalid evidence");

            assertThat(mockReport.getStatus()).isEqualTo("REJECTED");
            assertThat(mockReport.getVerdict()).isEqualTo("REJECTED");
            // §8.5: REJECT does NOT modify community_verdict
            assertThat(mockUrl.getCommunityVerdict())
                    .as("§8.5: REJECT must not modify scanned_url.community_verdict")
                    .isEqualTo(CommunityVerdict.MALICIOUS);
        }
    }

    // =========================================================================
    // MODIFY action
    // =========================================================================

    @Nested
    @DisplayName("MODIFY action")
    class ModifyAction {

        @Test
        @DisplayName("MODIFY with VERIFIED_BENIGN: community_verdict=BENIGN, report=VERIFIED")
        void modify_verifiedBenign() {
            service.submitReview(reportId, reviewerId, "MODIFY", "VERIFIED_BENIGN", "False positive");

            assertThat(mockReport.getVerdict()).isEqualTo("VERIFIED_BENIGN");
            assertThat(mockReport.getStatus()).isEqualTo("VERIFIED");
            assertThat(mockUrl.getCommunityVerdict()).isEqualTo(CommunityVerdict.BENIGN);
        }

        @Test
        @DisplayName("MODIFY without finalVerdict throws ValidationException")
        void modify_missingFinalVerdict_throws() {
            assertThatThrownBy(() ->
                    service.submitReview(reportId, reviewerId, "MODIFY", null, "note"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("finalVerdict");
        }

        @Test
        @DisplayName("MODIFY with AI-only verdict (BENIGN) throws ValidationException")
        void modify_aiOnlyVerdict_throws() {
            assertThatThrownBy(() ->
                    service.submitReview(reportId, reviewerId, "MODIFY", "BENIGN", "note"))
                    .isInstanceOf(ValidationException.class);
        }
    }

    // =========================================================================
    // Conflict: already reviewed
    // =========================================================================

    @Test
    @DisplayName("Submitting review on already-reviewed report throws ConflictException")
    void submitReview_alreadyReviewed_throwsConflict() {
        when(reviewRepository.findByUserReportId(reportId))
                .thenReturn(Optional.of(new SecurityTeamReview()));

        assertThatThrownBy(() ->
                service.submitReview(reportId, reviewerId, "APPROVE", null, ""))
                .isInstanceOf(ConflictException.class);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

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
