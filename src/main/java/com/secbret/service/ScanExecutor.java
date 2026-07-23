package com.secbret.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.secbret.ai.RuleInput;
import com.secbret.ai.ScoringService;
import com.secbret.ai.ThreatDisposition;
import com.secbret.exception.ScanFailedException;
import com.secbret.model.entity.ScanJob;
import com.secbret.model.entity.ScanResult;
import com.secbret.model.entity.ScannedUrl;
import com.secbret.model.enums.ScanJobStatus;
import com.secbret.model.enums.ScanDepth;
import com.secbret.scanner.Tier1Scanner;
import com.secbret.scanner.Tier2Findings;
import com.secbret.scanner.Tier2Scanner;
import com.secbret.scanner.Tier3Findings;
import com.secbret.scanner.Tier3Scanner;
import com.secbret.filter.CorrelationContext;
import jakarta.annotation.Resource;
import jakarta.enterprise.concurrent.ManagedExecutorService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Async scan execution via {@link ManagedExecutorService} (Part II §1 Decision #9 /
 * Part II §B / Part III §2).
 *
 * <h2>Lifecycle of a scan</h2>
 * <ol>
 *   <li>Caller creates a PENDING {@link ScanJob} via {@link ScanPersistence#createJob}.
 *   <li>Caller submits it here via {@link #submit(UUID)}.</li>
 *   <li>The executor picks up the task on a managed thread:
 *       <ol type="a">
 *         <li>Transition job → RUNNING (own {@code @Transactional} boundary).</li>
 *         <li>Run {@link Tier1Scanner#scan(String)} on the managed thread (outside JTA).</li>
 *         <li>On success: persist {@link ScanResult} and transition job → COMPLETED.</li>
 *         <li>On failure: transition job → FAILED + set {@code errorMessage}; log ERROR.
 *             <strong>No retry</strong> (Decision #17).</li>
 *       </ol>
 *   </li>
 * </ol>
 *
 * <h2>Why the scan runs outside the JTA transaction</h2>
 * The HTTP/TLS/WHOIS calls in the Tier 1 scanner can take up to 30 seconds (3 × 10s
 * worst-case). Holding a JTA transaction open across that time would hold a JDBC
 * connection for the entire duration — with a max pool of 20 that would exhaust the
 * pool under even modest concurrency. Each of the three phases (RUNNING transition,
 * scan, COMPLETED/FAILED write) therefore runs in its own short {@code @Transactional}
 * boundary, with the slow I/O in the middle outside any transaction.
 *
 * <h2>Failure contract (Decision #17)</h2>
 * Scan failures: mark FAILED, log at ERROR, no retry. The user resubmits. No retry
 * loops, no DLQ, no backoff — the simplest policy for dead URLs.
 *
 * <h2>Thread pool</h2>
 * The scan executor uses the container's default {@code ManagedExecutorService}
 * (configured for 5 threads per Part II §14 thread pool table). Injection via
 * {@code @Resource} with the Payara default JNDI name.
 */
@ApplicationScoped
public class ScanExecutor {

    private static final Logger log = LoggerFactory.getLogger(ScanExecutor.class);

    /**
     * Payara's default ManagedExecutorService JNDI name (Jakarta Concurrency 2.x).
     * The spec names this pool the "Scan Executor" (5 threads, Part II §14).
     * In Payara 6, the default MES is available at this JNDI name.
     */
    @Resource
    private ManagedExecutorService executor;

    @Inject
    private CorrelationContext correlationContext;

    @Inject
    private Tier1Scanner tier1Scanner;

    @Inject
    private Tier2Scanner tier2Scanner;

    @Inject
    private Tier3Scanner tier3Scanner;

    @Inject
    private ScoringService scoringService;

    /** Shared ObjectMapper for tier1_findings JSON serialization. */
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @PersistenceContext(unitName = "SecBretPU")
    private EntityManager em;

    /**
     * Submit a PENDING scan job for asynchronous execution.
     *
     * @param jobId the ID of an existing PENDING {@link ScanJob}
     * @return a {@link CompletableFuture} that resolves when the scan finishes
     *         (COMPLETED or FAILED); callers may discard this future — it is never
     *         used for polling; the job status in the DB is the source of truth
     */
    public CompletableFuture<Void> submit(UUID jobId) {
        log.info("Submitting scan_job id={} for async execution", jobId);
        // Capture correlation ID from the request-scoped context BEFORE the async hop.
        // The CDI @RequestScoped bean is not accessible on the worker thread (Part II §9.5).
        final String cid = correlationContext.getAsString();
        return CompletableFuture.runAsync(() -> {
            if (cid != null && !cid.isEmpty()) {
                MDC.put("correlationId", cid);
            }
            try {
                executeJob(jobId);
            } finally {
                MDC.remove("correlationId");
            }
        }, executor);
    }

    // =========================================================================
    // Async execution core (runs on the managed executor thread)
    // =========================================================================

    /**
     * Execute one scan job from PENDING to terminal state.
     * Never throws — all exceptions are caught and mapped to FAILED (Decision #17).
     *
     * @param jobId the scan job to execute
     */
    private void executeJob(UUID jobId) {
        // --- Phase 1: transition to RUNNING ---
        String targetUrl;
        UUID urlId;
        ScanDepth scanDepth;
        try {
            RunningInfo info = markRunning(jobId);
            targetUrl = info.targetUrl();
            urlId = info.urlId();
            scanDepth = info.scanDepth();
        } catch (Exception e) {
            log.error("scan_job id={} — failed to transition to RUNNING; aborting", jobId, e);
            // Best-effort FAILED write; if this also fails the stale-job recovery will
            // clean it up at next restart.
            try {
                markFailed(jobId, "Pre-scan failure: " + e.getMessage());
            } catch (Exception inner) {
                log.error("scan_job id={} — could not even mark as FAILED: {}", jobId, inner.getMessage());
            }
            return;
        }

        // --- Phase 2: run Tier 1 (outside JTA to avoid holding a DB connection) ---
        Tier1Scanner.ScanOutcome tier1Outcome;
        try {
            log.debug("scan_job id={} — starting Tier 1 scan of '{}'", jobId, targetUrl);
            tier1Outcome = tier1Scanner.scan(targetUrl);
            log.info("scan_job id={} — Tier 1 scan completed; overallScore={}",
                    jobId, tier1Outcome.overallScore());
        } catch (ScanFailedException e) {
            log.error("scan_job id={} — Tier 1 scan FAILED: {}", jobId, e.getMessage(), e);
            markFailed(jobId, truncate(e.getMessage(), 1000));
            return;
        } catch (Exception e) {
            log.error("scan_job id={} — unexpected exception during Tier 1 scan", jobId, e);
            markFailed(jobId, "Unexpected scanner error: " + truncate(e.getMessage(), 900));
            return;
        }

        // --- Phase 2b: Tier 2 + Tier 3 for DEEP scans (Part III §2 / §7 ScanDepth) ---
        Tier2Scanner.ScanOutcome tier2Outcome = null;
        Tier3Scanner.ScanOutcome tier3Outcome = null;
        if (scanDepth == ScanDepth.DEEP) {
            try {
                log.debug("scan_job id={} — starting Tier 2 scan of '{}'", jobId, targetUrl);
                tier2Outcome = tier2Scanner.scan(targetUrl);
                log.info("scan_job id={} — Tier 2 scan completed", jobId);
            } catch (ScanFailedException e) {
                log.error("scan_job id={} — Tier 2 scan FAILED: {}", jobId, e.getMessage(), e);
                markFailed(jobId, "Tier 2 scan failed: " + truncate(e.getMessage(), 900));
                return;
            } catch (Exception e) {
                log.error("scan_job id={} — unexpected exception during Tier 2 scan", jobId, e);
                markFailed(jobId, "Tier 2 unexpected error: " + truncate(e.getMessage(), 900));
                return;
            }

            try {
                log.debug("scan_job id={} — starting Tier 3 scan of '{}'", jobId, targetUrl);
                // Pass empty pageHtml so Tier3Scanner re-fetches (Tier2 already ran its own fetch).
                // ponytail: double-fetch accepted for now; cache page HTML when latency measured.
                tier3Outcome = tier3Scanner.scan(targetUrl, "");
                log.info("scan_job id={} — Tier 3 scan completed; knownPhishingKit={}",
                        jobId, tier3Outcome.findings().isKnownPhishingKit());
            } catch (ScanFailedException e) {
                log.error("scan_job id={} — Tier 3 scan FAILED: {}", jobId, e.getMessage(), e);
                markFailed(jobId, "Tier 3 scan failed: " + truncate(e.getMessage(), 900));
                return;
            } catch (Exception e) {
                log.error("scan_job id={} — unexpected exception during Tier 3 scan", jobId, e);
                markFailed(jobId, "Tier 3 unexpected error: " + truncate(e.getMessage(), 900));
                return;
            }
        }

        // --- Phase 3: persist ScanResult and transition to COMPLETED ---
        try {
            persistResult(jobId, urlId, tier1Outcome, tier2Outcome, tier3Outcome);
        } catch (Exception e) {
            log.error("scan_job id={} — failed to persist scan result; marking FAILED", jobId, e);
            markFailed(jobId, "Result persistence failed: " + truncate(e.getMessage(), 900));
        }
    }

    // =========================================================================
    // Transactional helpers (each in its own @Transactional boundary)
    // =========================================================================

    /** Bundles the data extracted from the job row during the RUNNING transition. */
    record RunningInfo(String targetUrl, UUID urlId, ScanDepth scanDepth) {}

    /**
     * Transition the job from PENDING to RUNNING and return target URL, urlId, and depth.
     *
     * @throws ScanFailedException if the job no longer exists
     */
    @Transactional
    RunningInfo markRunning(UUID jobId) {
        ScanJob job = em.find(ScanJob.class, jobId);
        if (job == null) {
            throw new ScanFailedException("scan_job id=" + jobId + " not found; cannot mark RUNNING");
        }
        job.setStatus(ScanJobStatus.RUNNING);
        job.setStartedAt(LocalDateTime.now());
        return new RunningInfo(
                job.getUrl().getOriginalUrl(),
                job.getUrl().getId(),
                job.getScanDepth());
    }

    /**
     * Persist the {@link ScanResult} row and transition the job to COMPLETED.
     *
     * <p>For QUICK scans tier2Outcome and tier3Outcome are null; the JSON columns are left
     * null (Part III §2 / §7 NULL Tier Response Behavior). For DEEP scans all three tiers
     * are persisted and the full {@link RuleInput} is constructed (lighting up the Tier 2/3
     * signals that were stubbed false in Phase 3).
     *
     * <p>overall_score = mean(max_score(T) for T in non-empty tiers) per §7.
     */
    @Transactional
    void persistResult(UUID jobId, UUID urlId,
                       Tier1Scanner.ScanOutcome tier1Outcome,
                       Tier2Scanner.ScanOutcome tier2Outcome,
                       Tier3Scanner.ScanOutcome tier3Outcome) {
        ScanJob job = em.find(ScanJob.class, jobId);
        if (job == null) {
            throw new ScanFailedException("scan_job id=" + jobId + " not found; cannot complete");
        }
        ScannedUrl url = em.find(ScannedUrl.class, urlId);
        if (url == null) {
            throw new ScanFailedException("scanned_url id=" + urlId + " not found; cannot complete scan_job " + jobId);
        }

        // Serialize Tier 1 findings.
        String tier1Json;
        try {
            tier1Json = MAPPER.writeValueAsString(tier1Outcome.findings());
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new ScanFailedException("Failed to serialize tier1_findings for job " + jobId, e);
        }

        // Serialize Tier 2/3 findings (null for QUICK scans).
        String tier2Json = null;
        String tier3Json = null;
        if (tier2Outcome != null) {
            try {
                tier2Json = MAPPER.writeValueAsString(tier2Outcome.findings());
            } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
                throw new ScanFailedException("Failed to serialize tier2_findings for job " + jobId, e);
            }
        }
        if (tier3Outcome != null) {
            try {
                tier3Json = MAPPER.writeValueAsString(tier3Outcome.findings());
            } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
                throw new ScanFailedException("Failed to serialize tier3_findings for job " + jobId, e);
            }
        }

        // Build full RuleInput — light up Tier 2/3 signals when present.
        Tier2Findings t2 = tier2Outcome != null ? tier2Outcome.findings() : null;
        Tier3Findings t3 = tier3Outcome != null ? tier3Outcome.findings() : null;

        RuleInput ruleInput = new RuleInput(
                tier1Outcome.domainAgeBand(),
                tier1Outcome.sslValidity(),
                tier1Outcome.missingSecurityHeaders(),
                t3 != null && t3.isKnownPhishingKit(),       // dispositive — Tier 3
                t2 != null && t2.isSuspiciousFormAction(),   // Tier 2
                t2 != null && t2.isHomoglyphDetected(),      // Tier 2
                t2 != null && t2.isHasHiddenIframes(),       // Tier 2
                tier1Outcome.redirectAnomaly());

        // overall_score = mean(max_score(T)) for non-empty tiers (§7 Scan Result Overall Score).
        BigDecimal overallScore = computeOverallScore(tier1Outcome, t2, t3);

        // Run scoring pipeline.
        String targetUrl = url.getOriginalUrl();
        ThreatDisposition disposition;
        try {
            disposition = scoringService.score(targetUrl, ruleInput, tier1Json);
            log.info("scan_job id={} scoring: combinedScore={} autoAction={} mlConsulted={}",
                    jobId, disposition.combinedScore(), disposition.autoAction(), disposition.mlConsulted());
        } catch (Exception e) {
            log.warn("scan_job id={} — ScoringService failed ({}); falling back to tier score",
                    jobId, e.getMessage());
            disposition = null;
        }

        BigDecimal finalScore = disposition != null
                ? BigDecimal.valueOf(disposition.combinedScore()).setScale(2, java.math.RoundingMode.HALF_UP)
                : overallScore;

        ScanResult result = new ScanResult();
        result.setUrl(url);
        result.setScanJob(job);
        result.setTier1Findings(tier1Json);
        result.setTier2Findings(tier2Json);
        result.setTier3Findings(tier3Json);
        result.setOverallScore(finalScore);
        em.persist(result);

        job.setStatus(ScanJobStatus.COMPLETED);
        job.setCompletedAt(LocalDateTime.now());
        url.setLastScannedAt(LocalDateTime.now());

        log.info("scan_job id={} COMPLETED; scan_result id={} depth={}",
                jobId, result.getId(), job.getScanDepth());
    }

    /**
     * Compute overall_score = mean(max_score(T) for T in [Tier1, Tier2, Tier3] if non-empty).
     * A tier with no findings is excluded; all tiers empty → NULL.
     * Per §7 Scan Result Overall Score.
     */
    private static BigDecimal computeOverallScore(Tier1Scanner.ScanOutcome t1,
                                                   Tier2Findings t2,
                                                   Tier3Findings t3) {
        // Tier 1 always has findings (scanner throws on failure).
        double sum = t1.overallScore().doubleValue();
        int count = 1;

        if (t2 != null) {
            double t2Max = computeTier2MaxScore(t2);
            sum += t2Max;
            count++;
        }
        if (t3 != null) {
            double t3Max = computeTier3MaxScore(t3);
            sum += t3Max;
            count++;
        }

        return BigDecimal.valueOf(sum / count).setScale(2, java.math.RoundingMode.HALF_UP);
    }

    /**
     * Tier 2 max score: highest rule-weight signal value from the Tier 2 findings.
     * Maps to §7 rule values: suspiciousFormAction=0.8, homoglyph=0.9, hiddenIframes=0.7.
     */
    private static double computeTier2MaxScore(Tier2Findings f) {
        double max = 0.0;
        if (f.isSuspiciousFormAction()) max = Math.max(max, 0.8);
        if (f.isHomoglyphDetected())    max = Math.max(max, 0.9);
        if (f.isHasHiddenIframes())     max = Math.max(max, 0.7);
        return max;
    }

    /**
     * Tier 3 max score: known phishing kit → 1.0; CVE matches → 0.6; open redirect → 0.5.
     * ponytail: severity heuristic; calibrate against labeled dataset in Phase 7.
     */
    private static double computeTier3MaxScore(Tier3Findings f) {
        double max = 0.0;
        if (f.isKnownPhishingKit())           max = Math.max(max, 1.0);
        if (!f.getCveMatches().isEmpty())      max = Math.max(max, 0.6);
        if (f.isOpenRedirect())                max = Math.max(max, 0.5);
        return max;
    }

    /**
     * Mark a job FAILED with an error message. Decision #17: no retry.
     * Suppresses all exceptions from the DB write so this is always a best-effort call.
     */
    @Transactional
    void markFailed(UUID jobId, String errorMessage) {
        try {
            ScanJob job = em.find(ScanJob.class, jobId);
            if (job == null) {
                log.error("scan_job id={} not found; cannot mark FAILED", jobId);
                return;
            }
            job.setStatus(ScanJobStatus.FAILED);
            job.setCompletedAt(LocalDateTime.now());
            job.setErrorMessage(errorMessage);
            log.warn("scan_job id={} marked FAILED: {}", jobId, errorMessage);
        } catch (Exception e) {
            log.error("scan_job id={} — exception while marking FAILED", jobId, e);
        }
    }

    // =========================================================================
    // Utilities
    // =========================================================================

    /** Truncate a string to {@code maxLen} characters to avoid overflowing the DB TEXT column. */
    private static String truncate(String s, int maxLen) {
        if (s == null) {
            return "null";
        }
        return s.length() <= maxLen ? s : s.substring(0, maxLen) + "…";
    }
}
