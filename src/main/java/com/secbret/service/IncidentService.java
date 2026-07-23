package com.secbret.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.secbret.ai.AutoActionVerdict;
import com.secbret.ai.RuleInput;
import com.secbret.filter.CorrelationContext;
import com.secbret.ai.ScoringService;
import com.secbret.ai.ThreatDisposition;
import com.secbret.exception.ResourceNotFoundException;
import com.secbret.model.entity.ScannedUrl;
import com.secbret.model.entity.SecBretAnalysis;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.entity.UserReport;
import com.secbret.model.enums.CommunityVerdict;
import com.secbret.repository.SecBretAnalysisRepository;
import com.secbret.repository.UserReportRepository;
import com.secbret.scanner.UrlNormalizer;
import com.secbret.repository.ScannedUrlRepository;
import com.secbret.repository.UserRepository;
import jakarta.annotation.Resource;
import jakarta.enterprise.concurrent.ManagedExecutorService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Incident reporting pipeline (Part III §3 / Part II §7 / Part II §16.5).
 *
 * <h2>Submit flow</h2>
 * <ol>
 *   <li>Normalize + find-or-create scanned_url.</li>
 *   <li>Persist user_report with status=PENDING.</li>
 *   <li>Kick off async analysis via ManagedExecutorService (mirror of ScanExecutor).</li>
 * </ol>
 *
 * <h2>Async analysis</h2>
 * Runs ScoringService (with no Tier 1/2/3 findings if no prior scan) and writes
 * secbret_analysis. On secbret_analysis INSERT failure → user_report FAILED (§16.5).
 * Auto-resolves to VERIFIED or leaves PENDING_REVIEW based on AUTO_APPROVE_LOW/HIGH bands.
 *
 * <h2>C4 guard</h2>
 * This service NEVER writes secbret_analysis.verdict with VERIFIED_* values.
 * It only writes BENIGN or SUSPICIOUS to secbret_analysis.verdict.
 * VERIFIED_* values go to user_report.verdict only.
 */
@ApplicationScoped
public class IncidentService {

    private static final Logger log = LoggerFactory.getLogger(IncidentService.class);

    // ponytail: reuse container default MES, same as ScanExecutor
    @Resource
    private ManagedExecutorService executor;

    @Inject
    private CorrelationContext correlationContext;

    @Inject
    private ScoringService scoringService;

    @Inject
    private UrlNormalizer urlNormalizer;

    @Inject
    private ScannedUrlRepository scannedUrlRepository;

    @Inject
    private UserRepository userRepository;

    @Inject
    private UserReportRepository reportRepository;

    @Inject
    private SecBretAnalysisRepository analysisRepository;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * B5 audit loop (§7 Precision monitoring, Known Gap #18): fraction of
     * auto-decided reports diverted to human review instead of auto-publishing.
     * From AUTO_DECISION_SAMPLE_RATE (§6), clamped to [0.0, 1.0], default 0.0.
     */
    double auditSampleRate = readAuditSampleRate();

    static double readAuditSampleRate() {
        return parseSampleRate(System.getenv("AUTO_DECISION_SAMPLE_RATE"));
    }

    static double parseSampleRate(String raw) {
        if (raw == null || raw.isBlank()) {
            return 0.0;
        }
        try {
            return Math.min(1.0, Math.max(0.0, Double.parseDouble(raw.trim())));
        } catch (NumberFormatException notANumber) {
            return 0.0;
        }
    }

    // =========================================================================
    // Submit report
    // =========================================================================

    /**
     * Submit an incident report for a URL. Returns the persisted UserReport.
     * Kicks off async analysis immediately.
     *
     * @param rawUrl              the user-supplied URL
     * @param evidenceDescription required, 10-2000 chars
     * @param evidenceUrlsJson    JSON array string of evidence URLs (may be null)
     * @param reporterId          the UUID of the reporting user
     */
    @Transactional
    public UserReport submitReport(String rawUrl, String evidenceDescription,
                                   String evidenceUrlsJson, UUID reporterId) {
        // Normalize URL and find/create scanned_url
        String normalizedUrl = urlNormalizer.normalize(rawUrl);
        String normalizedHash = urlNormalizer.hash(rawUrl);
        ScannedUrl scannedUrl = scannedUrlRepository.findByNormalizedHash(normalizedHash)
                .orElseGet(() -> {
                    ScannedUrl u = new ScannedUrl();
                    u.setOriginalUrl(normalizedUrl);
                    u.setNormalizedHash(normalizedHash);
                    scannedUrlRepository.persist(u);
                    return u;
                });

        SecBretUser reporter = userRepository.findById(reporterId)
                .orElseThrow(() -> new ResourceNotFoundException("user", reporterId));

        UserReport report = new UserReport();
        report.setUrl(scannedUrl);
        report.setReportedBy(reporter);
        report.setEvidenceDescription(evidenceDescription);
        report.setEvidenceUrls(evidenceUrlsJson);
        report.setStatus("PENDING");

        reportRepository.persist(report);
        log.info("user_report id={} PENDING for url={}", report.getId(), rawUrl);

        return report;
    }

    /**
     * Fire the async analysis task. MUST be called by the resource AFTER
     * {@link #submitReport} returns, so its @Transactional persist has committed and
     * the row is visible to the fresh EntityManager on the executor thread. Mirrors
     * how ScanResource calls ScanExecutor.submit after ScanPersistence.createJob.
     */
    public CompletableFuture<Void> triggerAnalysis(UUID reportId, UUID urlId) {
        // Capture correlation ID before async hop — @RequestScoped bean unavailable on worker thread.
        final String cid = correlationContext.getAsString();
        return CompletableFuture.runAsync(() -> {
            if (cid != null && !cid.isEmpty()) {
                MDC.put("correlationId", cid);
            }
            try {
                runAnalysis(reportId, urlId);
            } finally {
                MDC.remove("correlationId");
            }
        }, executor);
    }

    // =========================================================================
    // Async analysis (runs on managed executor thread)
    // =========================================================================

    /**
     * Run scoring, write secbret_analysis, then auto-resolve or leave PENDING_REVIEW.
     * On analysis DB write failure → mark user_report FAILED (§16.5). No retry.
     */
    void runAnalysis(UUID reportId, UUID urlId) {
        log.info("Starting async analysis for user_report id={}", reportId);

        // Score with no prior Tier 1/2/3 data — rules run with all-false signals
        // per spec §3 "If no scan_result exists, rules engine runs with empty findings".
        RuleInput ruleInput = RuleInput.allFalse();
        ThreatDisposition disposition;
        try {
            disposition = scoringService.score("report:" + reportId, ruleInput, null);
        } catch (Exception e) {
            log.error("ScoringService failed for user_report id={}", reportId, e);
            markReportFailed(reportId, "Scoring error: " + truncate(e.getMessage(), 900));
            return;
        }

        // Write secbret_analysis — if this fails → FAILED (§16.5)
        UUID analysisId;
        try {
            analysisId = persistAnalysis(reportId, urlId, disposition);
        } catch (Exception e) {
            log.error("secbret_analysis INSERT failed for user_report id={}; marking FAILED", reportId, e);
            markReportFailed(reportId, "Analysis persistence failed: " + truncate(e.getMessage(), 900));
            return;
        }

        // Auto-resolve or PENDING_REVIEW
        try {
            resolveReport(reportId, urlId, analysisId, disposition.autoAction());
        } catch (Exception e) {
            log.error("Auto-resolve failed for user_report id={}", reportId, e);
            // Don't re-mark FAILED; analysis was written — leave PENDING (stale) and log
        }
    }

    /**
     * Builds the analysis entity and persists it via
     * {@link SecBretAnalysisRepository#persistForReport} so the write (including
     * the report/url lookups) runs inside a repository-owned transaction on the
     * worker thread. A @Transactional here would be self-invoked from
     * {@link #runAnalysis} and silently bypassed by Weld.
     */
    UUID persistAnalysis(UUID reportId, UUID urlId, ThreatDisposition d) {
        String analysisVerdict = d.combinedScore() <= 0.05 ? "BENIGN" : "SUSPICIOUS";
        // C4 runtime assertion: secbret_analysis.verdict must only be BENIGN or SUSPICIOUS
        assert "BENIGN".equals(analysisVerdict) || "SUSPICIOUS".equals(analysisVerdict)
                : "C4 violation: attempted to write '" + analysisVerdict + "' to secbret_analysis.verdict";

        SecBretAnalysis analysis = new SecBretAnalysis();
        analysis.setThreatScore(BigDecimal.valueOf(d.combinedScore()).setScale(2, RoundingMode.HALF_UP));
        analysis.setVerdict(analysisVerdict);
        analysis.setReasoningChain(buildReasoningChain(d));
        analysis.setMlConsulted(d.mlConsulted());
        if (d.mlConsulted() && d.mlScore().isPresent()) {
            analysis.setMlScore(BigDecimal.valueOf(d.mlScore().getAsDouble()).setScale(2, RoundingMode.HALF_UP));
        }
        // model_version: the sidecar version when ML contributed, else NULL for
        // the rules-only path (§7 ML Model Version Tracking). ScoringService
        // attaches it to the disposition; a stub/breaker-OPEN scan leaves it null.
        analysis.setModelVersion(d.modelVersion());

        analysisRepository.persistForReport(reportId, urlId, analysis);
        log.info("secbret_analysis id={} written for user_report id={} threatScore={} verdict={}",
                analysis.getId(), reportId, analysis.getThreatScore(), analysis.getVerdict());
        return analysis.getId();
    }

    /**
     * Auto-resolve the report. Writes go through {@link UserReportRepository#resolveInTx}
     * so the mutation runs inside a real @Transactional boundary that flushes — a
     * self-invoked @Transactional on this @ApplicationScoped bean is bypassed by the
     * CDI interceptor (Weld self-invocation), so entity dirty-updates would be lost.
     */
    void resolveReport(UUID reportId, UUID urlId, UUID analysisId, AutoActionVerdict autoAction) {
        // B5 audit sampling: divert a fraction of would-be auto-decisions to the
        // human review queue. This is the ONLY auto-decision write path, so the
        // guard here covers dispositive auto-blocks and auto-benign alike.
        if (autoAction != AutoActionVerdict.PENDING_REVIEW
                && ThreadLocalRandom.current().nextDouble() < auditSampleRate) {
            reportRepository.resolveInTx(reportId, urlId, "PENDING_REVIEW", null, null);
            log.info("user_report id={} auto-decision {} diverted to human audit "
                    + "(AUTO_DECISION_SAMPLE_RATE={})", reportId, autoAction, auditSampleRate);
            return;
        }
        String finalVerdict;
        String status;
        CommunityVerdict communityVerdict; // null → leave unchanged
        switch (autoAction) {
            case VERIFIED_MALICIOUS -> {
                finalVerdict = "VERIFIED_MALICIOUS";
                status = "VERIFIED";
                communityVerdict = CommunityVerdict.MALICIOUS;
            }
            case VERIFIED_BENIGN -> {
                finalVerdict = "VERIFIED_BENIGN";
                status = "VERIFIED";
                // §17 Open Question #2: score <= 0.05 DOES set community_verdict = BENIGN
                communityVerdict = CommunityVerdict.BENIGN;
            }
            case PENDING_REVIEW -> {
                finalVerdict = null;
                status = "PENDING_REVIEW";
                communityVerdict = null;
            }
            default -> throw new IllegalStateException("unknown autoAction: " + autoAction);
        }
        // C4 precondition: never write AI-only values to user_report.verdict
        if ("BENIGN".equals(finalVerdict) || "SUSPICIOUS".equals(finalVerdict)) {
            throw new IllegalStateException("C4: AI-only value cannot be written to user_report.verdict");
        }
        reportRepository.resolveInTx(reportId, urlId, status, finalVerdict, communityVerdict);
        log.info("user_report id={} auto-resolved status={} verdict={}", reportId, status, finalVerdict);
    }

    void markReportFailed(UUID reportId, String errorMessage) {
        try {
            reportRepository.markFailedInTx(reportId, errorMessage);
            log.warn("user_report id={} marked FAILED: {}", reportId, errorMessage);
        } catch (Exception e) {
            log.error("user_report id={} — could not mark FAILED", reportId, e);
        }
    }

    // =========================================================================
    // Read
    // =========================================================================

    public UserReport getReportById(UUID reportId) {
        return reportRepository.findByIdEager(reportId)
                .orElseThrow(() -> new ResourceNotFoundException("user_report", reportId));
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private String buildReasoningChain(ThreatDisposition d) {
        StringBuilder sb = new StringBuilder();
        var result = d.ruleResult();
        sb.append("Rules score: ").append(String.format("%.4f", result.ruleScore()));
        if (result.dispositive()) {
            sb.append(" (dispositive override active)");
        }
        if (d.mlConsulted()) {
            sb.append(". ML consulted: ").append(
                    d.mlScore().isPresent() ? String.format("%.4f", d.mlScore().getAsDouble()) : "n/a");
        }
        sb.append(". Combined: ").append(String.format("%.4f", d.combinedScore()));
        sb.append(". No prior scan data available; analysis is based on user evidence only.");
        return sb.toString();
    }

    private static String truncate(String s, int max) {
        if (s == null) return "null";
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }
}
