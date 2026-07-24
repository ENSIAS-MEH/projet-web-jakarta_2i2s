package com.secbret.integration;

import com.secbret.model.entity.AuditLog;
import com.secbret.model.entity.ScannedUrl;
import com.secbret.model.entity.SecBretAnalysis;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.entity.SecurityTeamReview;
import com.secbret.model.entity.UserReport;
import com.secbret.model.enums.CommunityVerdict;
import com.secbret.model.enums.UserRole;
import com.secbret.repository.AuditLogRepository;
import com.secbret.repository.SecBretAnalysisRepository;
import com.secbret.repository.SecurityTeamReviewRepository;
import com.secbret.repository.UserReportRepository;
import com.secbret.repository.ScannedUrlRepository;
import com.secbret.repository.UserRepository;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for the incident pipeline entities and full flow.
 *
 * <p>Scenarios:
 * <ol>
 *   <li>Entity round-trips (UserReport, SecBretAnalysis, SecurityTeamReview, AuditLog)</li>
 *   <li>Full submit → PENDING_REVIEW → analyst APPROVE → community_verdict flow</li>
 *   <li>Full submit → VERIFIED auto-resolve → community_verdict</li>
 *   <li>Audit log rows are written on review actions</li>
 *   <li>C4: secbret_analysis.verdict stays BENIGN/SUSPICIOUS after review insert</li>
 * </ol>
 */
class IncidentPipelineIT extends PostgresIntegrationSupport {

    private EntityManager em;
    private UserRepository userRepo;
    private ScannedUrlRepository urlRepo;
    private UserReportRepository reportRepo;
    private SecBretAnalysisRepository analysisRepo;
    private SecurityTeamReviewRepository reviewRepo;
    private AuditLogRepository auditRepo;

    @BeforeEach
    void open() {
        em = EMF.createEntityManager();
        userRepo = new UserRepository(em);
        urlRepo = new ScannedUrlRepository(em);
        reportRepo = new UserReportRepository(em);
        analysisRepo = new SecBretAnalysisRepository(em);
        reviewRepo = new SecurityTeamReviewRepository(em);
        auditRepo = new AuditLogRepository(em);
    }

    @AfterEach
    void close() {
        if (em.getTransaction().isActive()) em.getTransaction().rollback();
        em.close();
    }

    // =========================================================================
    // Entity round-trips
    // =========================================================================

    @Test
    @DisplayName("UserReport persists and reads back with status=PENDING")
    void userReport_roundTrip() {
        SecBretUser reporter = createUser("reporter-" + UUID.randomUUID());
        ScannedUrl url = createUrl();

        em.getTransaction().begin();
        UserReport report = new UserReport();
        report.setUrl(url);
        report.setReportedBy(reporter);
        report.setEvidenceDescription("This site steals bank credentials by mimicking BAC login.");
        report.setStatus("PENDING");
        reportRepo.persist(report);
        em.getTransaction().commit();
        em.clear();

        Optional<UserReport> found = reportRepo.findById(report.getId());
        assertThat(found).isPresent();
        assertThat(found.get().getStatus()).isEqualTo("PENDING");
        assertThat(found.get().getVersion()).isEqualTo(0L);
        assertThat(found.get().getDeletedAt()).isNull(); // no soft-delete in v1
    }

    @Test
    @DisplayName("SecBretAnalysis persists with BENIGN verdict (C4: never VERIFIED_*)")
    void secbretAnalysis_verdictBenign() {
        ScannedUrl url = createUrl();
        SecBretUser reporter = createUser("rep-" + UUID.randomUUID());
        UserReport report = createReport(url, reporter);

        em.getTransaction().begin();
        SecBretAnalysis analysis = new SecBretAnalysis();
        analysis.setUrl(url);
        analysis.setUserReport(report);
        analysis.setThreatScore(new BigDecimal("0.03"));
        analysis.setVerdict("BENIGN");
        analysis.setReasoningChain("All signals clean. No prior scan data.");
        analysis.setMlConsulted(false);
        analysisRepo.persist(analysis);
        em.getTransaction().commit();
        em.clear();

        SecBretAnalysis found = analysisRepo.findByUserReportId(report.getId()).orElseThrow();
        assertThat(found.getVerdict()).isEqualTo("BENIGN");
        assertThat(found.getVerdict()).doesNotContain("VERIFIED"); // C4
        assertThat(found.getThreatScore()).isEqualByComparingTo("0.03");
    }

    @Test
    @DisplayName("SecurityTeamReview persists with VERIFIED_MALICIOUS final_verdict (C4: never in secbret_analysis)")
    void securityTeamReview_roundTrip_c4Check() {
        ScannedUrl url = createUrl();
        SecBretUser reporter = createUser("rep-" + UUID.randomUUID());
        SecBretUser analyst = createUser("analyst-" + UUID.randomUUID());
        UserReport report = createReport(url, reporter);
        SecBretAnalysis analysis = createAnalysis(url, report, "0.88", "SUSPICIOUS");

        em.getTransaction().begin();
        report.setStatus("PENDING_REVIEW");
        SecurityTeamReview review = new SecurityTeamReview();
        review.setUserReport(report);
        review.setSecbretAnalysis(analysis);
        review.setReviewedBy(analyst);
        review.setStatus("APPROVED");
        review.setFinalVerdict("VERIFIED_MALICIOUS");
        reviewRepo.persist(review);
        em.getTransaction().commit();
        em.clear();

        // C4: analysis.verdict must still be SUSPICIOUS (unchanged)
        SecBretAnalysis reloaded = analysisRepo.findById(analysis.getId()).orElseThrow();
        assertThat(reloaded.getVerdict()).isEqualTo("SUSPICIOUS");
        assertThat(reloaded.getVerdict()).doesNotContain("VERIFIED"); // C4 proof

        SecurityTeamReview foundReview = reviewRepo.findByUserReportId(report.getId()).orElseThrow();
        assertThat(foundReview.getFinalVerdict()).isEqualTo("VERIFIED_MALICIOUS");
        assertThat(foundReview.getStatus()).isEqualTo("APPROVED");
    }

    @Test
    @DisplayName("AuditLog round-trip (append-only)")
    void auditLog_roundTrip() {
        SecBretUser analyst = createUser("audit-analyst-" + UUID.randomUUID());
        UUID targetId = UUID.randomUUID();

        em.getTransaction().begin();
        AuditLog entry = new AuditLog();
        entry.setActor(analyst);
        entry.setActorUsername(analyst.getUsername());
        entry.setAction("REVIEW_APPROVED");
        entry.setTargetType("user_report");
        entry.setTargetId(targetId);
        entry.setDetail("{\"reportId\":\"" + targetId + "\"}");
        auditRepo.append(entry);
        em.getTransaction().commit();

        assertThat(entry.getId()).isNotNull();
        assertThat(entry.getCreatedAt()).isNotNull();
    }

    // =========================================================================
    // Full flow: submit → PENDING_REVIEW → analyst APPROVE → community_verdict
    // =========================================================================

    @Test
    @DisplayName("Full flow: PENDING_REVIEW → APPROVE → VERIFIED_MALICIOUS, community_verdict=MALICIOUS, audit logged")
    void fullFlow_pendingReviewToApprove() {
        ScannedUrl url = createUrl();
        SecBretUser reporter = createUser("rep-" + UUID.randomUUID());
        SecBretUser analyst = createUser("analyst-" + UUID.randomUUID());

        // 1. Submit report (PENDING)
        UserReport report = createReport(url, reporter);

        // 2. Analysis written (PENDING_REVIEW)
        SecBretAnalysis analysis = createAnalysis(url, report, "0.72", "SUSPICIOUS");
        em.getTransaction().begin();
        report.setStatus("PENDING_REVIEW");
        em.getTransaction().commit();

        // 3. Analyst APPROVE
        em.getTransaction().begin();
        SecurityTeamReview review = new SecurityTeamReview();
        review.setUserReport(report);
        review.setSecbretAnalysis(analysis);
        review.setReviewedBy(analyst);
        review.setStatus("APPROVED");
        review.setFinalVerdict("VERIFIED_MALICIOUS");
        review.setReviewerNotes("Confirmed phishing kit");
        reviewRepo.persist(review);

        report.setVerdict("VERIFIED_MALICIOUS");
        report.setStatus("VERIFIED");
        report.setResolvedAt(LocalDateTime.now());

        url.setCommunityVerdict(CommunityVerdict.MALICIOUS);

        // 4. Audit log
        AuditLog auditEntry = new AuditLog();
        auditEntry.setActor(analyst);
        auditEntry.setActorUsername(analyst.getUsername());
        auditEntry.setAction("REVIEW_APPROVED");
        auditEntry.setTargetType("user_report");
        auditEntry.setTargetId(report.getId());
        auditRepo.append(auditEntry);

        em.getTransaction().commit();
        em.clear();

        // Verify
        UserReport finalReport = reportRepo.findById(report.getId()).orElseThrow();
        assertThat(finalReport.getStatus()).isEqualTo("VERIFIED");
        assertThat(finalReport.getVerdict()).isEqualTo("VERIFIED_MALICIOUS");
        assertThat(finalReport.getVerdict()).isNotIn("BENIGN", "SUSPICIOUS"); // C4

        ScannedUrl finalUrl = em.find(ScannedUrl.class, url.getId());
        assertThat(finalUrl.getCommunityVerdict()).isEqualTo(CommunityVerdict.MALICIOUS);

        // C4: secbret_analysis.verdict still SUSPICIOUS
        SecBretAnalysis finalAnalysis = analysisRepo.findById(analysis.getId()).orElseThrow();
        assertThat(finalAnalysis.getVerdict()).isEqualTo("SUSPICIOUS");
        assertThat(finalAnalysis.getVerdict()).doesNotContain("VERIFIED");
    }

    @Test
    @DisplayName("Auto-resolve VERIFIED_BENIGN: community_verdict=BENIGN (§17 Open Question #2)")
    void autoResolve_benign_setCommunityVerdictBenign() {
        ScannedUrl url = createUrl();
        SecBretUser reporter = createUser("rep-" + UUID.randomUUID());
        UserReport report = createReport(url, reporter);
        SecBretAnalysis analysis = createAnalysis(url, report, "0.02", "BENIGN");

        em.getTransaction().begin();
        // Auto-resolve: combinedScore ≤ 0.05 → VERIFIED_BENIGN
        report.setStatus("VERIFIED");
        report.setVerdict("VERIFIED_BENIGN");
        report.setResolvedAt(LocalDateTime.now());
        url.setCommunityVerdict(CommunityVerdict.BENIGN); // §17 #2
        em.getTransaction().commit();
        em.clear();

        UserReport finalReport = reportRepo.findById(report.getId()).orElseThrow();
        assertThat(finalReport.getVerdict()).isEqualTo("VERIFIED_BENIGN");

        ScannedUrl finalUrl = em.find(ScannedUrl.class, url.getId());
        assertThat(finalUrl.getCommunityVerdict()).isEqualTo(CommunityVerdict.BENIGN);

        // C4: analysis still BENIGN (AI-only verdict unchanged)
        SecBretAnalysis finalAnalysis = analysisRepo.findById(analysis.getId()).orElseThrow();
        assertThat(finalAnalysis.getVerdict()).isEqualTo("BENIGN");
    }

    @Test
    @DisplayName("REJECT: user_report=REJECTED, community_verdict NOT changed (§8.5)")
    void reject_doesNotChangeCommunityVerdict() {
        ScannedUrl url = createUrl();
        url.setCommunityVerdict(CommunityVerdict.MALICIOUS); // pre-existing verdict
        SecBretUser reporter = createUser("rep-" + UUID.randomUUID());
        SecBretUser analyst = createUser("analyst-" + UUID.randomUUID());
        UserReport report = createReport(url, reporter);
        SecBretAnalysis analysis = createAnalysis(url, report, "0.60", "SUSPICIOUS");

        em.getTransaction().begin();
        report.setStatus("PENDING_REVIEW");
        SecurityTeamReview review = new SecurityTeamReview();
        review.setUserReport(report);
        review.setSecbretAnalysis(analysis);
        review.setReviewedBy(analyst);
        review.setStatus("REJECTED");
        review.setFinalVerdict("REJECTED");
        reviewRepo.persist(review);

        report.setStatus("REJECTED");
        report.setVerdict("REJECTED");
        report.setResolvedAt(LocalDateTime.now());
        // §8.5: community_verdict NOT modified on REJECT
        em.getTransaction().commit();
        em.clear();

        ScannedUrl finalUrl = em.find(ScannedUrl.class, url.getId());
        assertThat(finalUrl.getCommunityVerdict())
                .as("§8.5: REJECT must not modify community_verdict")
                .isEqualTo(CommunityVerdict.MALICIOUS);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private SecBretUser createUser(String username) {
        SecBretUser user = new SecBretUser();
        user.setUsername(username);
        user.setEmail(username + "@test.example");
        user.setPasswordHash("$2a$12$0123456789012345678901uABCDEFGHIJKLMNOPQRSTUVWXYZ01234");
        user.setRole(UserRole.REPORTER);
        em.getTransaction().begin();
        userRepo.persist(user);
        em.getTransaction().commit();
        return user;
    }

    private ScannedUrl createUrl() {
        ScannedUrl url = new ScannedUrl();
        url.setOriginalUrl("https://phishing-" + UUID.randomUUID() + ".example.com");
        url.setNormalizedHash(randomHash());
        em.getTransaction().begin();
        urlRepo.persist(url);
        em.getTransaction().commit();
        return url;
    }

    private UserReport createReport(ScannedUrl url, SecBretUser reporter) {
        em.getTransaction().begin();
        UserReport report = new UserReport();
        report.setUrl(url);
        report.setReportedBy(reporter);
        report.setEvidenceDescription("This site steals credentials via a phishing kit.");
        report.setStatus("PENDING");
        reportRepo.persist(report);
        em.getTransaction().commit();
        return report;
    }

    private SecBretAnalysis createAnalysis(ScannedUrl url, UserReport report, String score, String verdict) {
        em.getTransaction().begin();
        SecBretAnalysis a = new SecBretAnalysis();
        a.setUrl(url);
        a.setUserReport(report);
        a.setThreatScore(new BigDecimal(score));
        a.setVerdict(verdict);
        a.setReasoningChain("Automated analysis.");
        a.setMlConsulted(false);
        analysisRepo.persist(a);
        em.getTransaction().commit();
        return a;
    }

    private static String randomHash() {
        return (UUID.randomUUID().toString() + UUID.randomUUID()).replace("-", "").substring(0, 64);
    }
}
