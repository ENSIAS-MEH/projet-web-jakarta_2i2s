package com.secbret.service;

import com.secbret.exception.ResourceNotFoundException;
import com.secbret.filter.CorrelationContext;
import com.secbret.model.entity.ReportJob;
import com.secbret.model.entity.ScanResult;
import com.secbret.model.entity.ScannedUrl;
import com.secbret.model.entity.SecBretAnalysis;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.entity.SecurityTeamReview;
import com.secbret.model.entity.ShareLink;
import com.secbret.repository.ReportJobRepository;
import com.secbret.repository.ScannedUrlRepository;
import com.secbret.repository.SecBretAnalysisRepository;
import com.secbret.repository.SecurityTeamReviewRepository;
import com.secbret.repository.ShareLinkRepository;
import com.secbret.repository.ScanResultRepository;
import com.secbret.repository.UserRepository;
import jakarta.annotation.Resource;
import jakarta.enterprise.concurrent.ManagedExecutorService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.PersistenceException;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Report generation pipeline (Part III §4 / Part II §8 / decision #13).
 *
 * <h2>Submit flow</h2>
 * <ol>
 *   <li>Validate urlId exists.</li>
 *   <li>Persist ReportJob with status=PENDING inside @Transactional.</li>
 *   <li>On ConstraintViolationException (uq_report_job_active_per_url): return the
 *       existing active job (idempotent de-dup, same 202 — not 409).</li>
 *   <li>Return to caller. Caller MUST call {@link #triggerGeneration} AFTER this
 *       method returns so the persist tx has committed and the row is visible to
 *       the worker EM.</li>
 * </ol>
 *
 * <h2>Decision #13 — file_data written only on COMPLETED</h2>
 * The GENERATING transition does NOT write file_data. Only {@link #doGenerate}
 * writes file_data, and only via {@link ReportJobRepository#markCompletedInTx}.
 *
 * <h2>Auto-share-link</h2>
 * On COMPLETED, a share link with 30-day expiry is auto-created before the
 * worker thread exits (Part III §4 side-effect).
 */
@ApplicationScoped
public class ReportGenerationService {

    private static final Logger log = LoggerFactory.getLogger(ReportGenerationService.class);
    private static final int DEFAULT_SHARE_EXPIRY_DAYS = 30;

    @Resource
    private ManagedExecutorService executor;

    @Inject
    private CorrelationContext correlationContext;

    @Inject private ReportJobRepository reportJobRepository;
    @Inject private ShareLinkRepository shareLinkRepository;
    @Inject private ScannedUrlRepository scannedUrlRepository;
    @Inject private ScanResultRepository scanResultRepository;
    @Inject private SecBretAnalysisRepository analysisRepository;
    @Inject private SecurityTeamReviewRepository reviewRepository;
    @Inject private UserRepository userRepository;
    @Inject private PdfReportGenerator pdfGenerator;

    @PersistenceContext(unitName = "SecBretPU")
    private EntityManager em;

    // =========================================================================
    // Submit (called from REST resource, returns after persist tx commits)
    // =========================================================================

    /**
     * Create a PENDING report job for the given URL.
     * On uq_report_job_active_per_url violation: returns the existing active job.
     *
     * @param urlId       the scanned_url.id
     * @param requesterId the secbret_user.id of the requester
     * @return the (new or existing) ReportJob
     * @throws ResourceNotFoundException if urlId is unknown
     */
    @Transactional
    public ReportJob createJob(UUID urlId, UUID requesterId) {
        ScannedUrl url = scannedUrlRepository.findById(urlId)
                .orElseThrow(() -> new ResourceNotFoundException("scanned_url", urlId));
        SecBretUser requester = userRepository.findById(requesterId)
                .orElseThrow(() -> new ResourceNotFoundException("user", requesterId));

        ReportJob job = new ReportJob();
        job.setUrl(url);
        job.setRequestedBy(requester);
        job.setStatus("PENDING");

        try {
            reportJobRepository.persist(job);
            em.flush(); // trigger the unique constraint check immediately
            log.info("report_job id={} PENDING for url={}", job.getId(), url.getOriginalUrl());
            return job;
        } catch (PersistenceException e) {
            // uq_report_job_active_per_url violated → return existing active job
            if (isConstraintViolation(e)) {
                log.info("report_job already active for urlId={} — returning existing job", urlId);
                return reportJobRepository.findActiveByUrlId(urlId)
                        .orElseThrow(() -> {
                            log.error("Constraint fired but no active job found for urlId={}", urlId);
                            return e; // rethrow original
                        });
            }
            throw e;
        }
    }

    /**
     * Fire the async generation task. MUST be called by the resource AFTER
     * {@link #createJob} returns, so the PENDING row is committed and visible
     * to the worker thread's fresh EntityManager. Mirrors ScanResource→ScanExecutor.
     */
    public CompletableFuture<Void> triggerGeneration(UUID jobId, UUID urlId) {
        // Capture correlation ID before async hop — @RequestScoped bean unavailable on worker thread.
        final String cid = correlationContext.getAsString();
        return CompletableFuture.runAsync(() -> {
            if (cid != null && !cid.isEmpty()) {
                MDC.put("correlationId", cid);
            }
            try {
                doGenerate(jobId, urlId);
            } finally {
                MDC.remove("correlationId");
            }
        }, executor);
    }

    // =========================================================================
    // Async generation worker
    // =========================================================================

    void doGenerate(UUID jobId, UUID urlId) {
        log.info("Starting PDF generation for report_job id={}", jobId);

        // 1. Transition to GENERATING (no file_data — decision #13)
        try {
            reportJobRepository.markGeneratingInTx(jobId);
        } catch (Exception e) {
            log.error("Failed to mark report_job GENERATING id={}", jobId, e);
            markFailed(jobId, "Failed to mark GENERATING: " + truncate(e.getMessage(), 500));
            return;
        }

        // 2. Load supporting data for the PDF
        ScanResult scanResult;
        SecBretAnalysis analysis;
        SecurityTeamReview review;
        ReportJob job;
        try {
            job = reportJobRepository.findByIdEager(jobId)
                    .orElseThrow(() -> new IllegalStateException("job disappeared: " + jobId));
            scanResult = scanResultRepository.findLatestByUrlId(urlId).orElse(null);
            analysis   = analysisRepository.findLatestByUrlId(urlId).orElse(null);
            review     = reviewRepository.findLatestByUrlId(urlId).orElse(null);
        } catch (Exception e) {
            log.error("Data load failed for report_job id={}", jobId, e);
            markFailed(jobId, "Data load error: " + truncate(e.getMessage(), 500));
            return;
        }

        // 3. Generate PDF (shareToken is null at generation time; we fill it in after)
        byte[] pdfBytes;
        try {
            pdfBytes = pdfGenerator.generate(job, analysis, scanResult, review, null);
        } catch (Exception e) {
            log.error("PDF generation failed for report_job id={}", jobId, e);
            markFailed(jobId, "OpenPDF rendering error: " + truncate(e.getMessage(), 900));
            return;
        }

        // 4. Create share link BEFORE the COMPLETED update so we have the token for the footer.
        //    Build entity inline and call shareLinkRepository.persist (owns @Transactional, CDI proxy).
        //    Do NOT call private/package helpers on `this` — Weld bypasses @Transactional on self-calls.
        ShareLink shareLink;
        try {
            ShareLink link = new ShareLink();
            link.setReportJob(reportJobRepository.findByIdEager(jobId)
                    .orElseThrow(() -> new IllegalStateException("job disappeared building share link: " + jobId)));
            link.setUuidToken(UUID.randomUUID().toString());
            link.setExpiresAt(LocalDateTime.now().plusDays(DEFAULT_SHARE_EXPIRY_DAYS));
            if (job.getRequestedBy() != null) {
                link.setCreatedBy(job.getRequestedBy());
            }
            shareLink = shareLinkRepository.persist(link);
        } catch (Exception e) {
            log.error("Auto share-link creation failed for report_job id={}", jobId, e);
            // Non-fatal: mark completed without share link
            shareLink = null;
        }

        // 5. Optionally re-generate PDF with the share token in footer
        if (shareLink != null) {
            try {
                // Reload job (requestedBy may have been nulled post-GDPR; use cached reference)
                pdfBytes = pdfGenerator.generate(job, analysis, scanResult, review, shareLink.getUuidToken());
            } catch (Exception e) {
                log.warn("PDF re-render with share token failed for report_job id={}; using tokenless PDF", jobId, e);
                // Keep original pdfBytes
            }
        }

        // 6. Persist COMPLETED with file_data (decision #13: only here)
        try {
            reportJobRepository.markCompletedInTx(jobId, pdfBytes, pdfBytes.length);
            log.info("report_job id={} COMPLETED size={}b shareToken={}", jobId, pdfBytes.length,
                    shareLink != null ? shareLink.getUuidToken() : "none");
        } catch (Exception e) {
            log.error("Failed to persist COMPLETED for report_job id={}", jobId, e);
            markFailed(jobId, "COMPLETED persist failed: " + truncate(e.getMessage(), 500));
        }
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Public entry point for manual share link creation (POST /share).
     * Called from REST resource via CDI proxy — @Transactional is effective here.
     */
    @Transactional
    public ShareLink createShareLink(UUID jobId, UUID createdById, int expiryDays) {
        ReportJob job = reportJobRepository.findByIdEager(jobId)
                .orElseThrow(() -> new ResourceNotFoundException("report_job", jobId));
        if (!"COMPLETED".equals(job.getStatus())) {
            throw new ResourceNotFoundException("report_job (must be COMPLETED)", jobId);
        }

        ShareLink link = new ShareLink();
        link.setReportJob(job);
        link.setUuidToken(UUID.randomUUID().toString());
        link.setExpiresAt(LocalDateTime.now().plusDays(expiryDays));
        if (createdById != null) {
            SecBretUser creator = em.find(SecBretUser.class, createdById);
            link.setCreatedBy(creator);
        }
        shareLinkRepository.persist(link);
        return link;
    }

    void markFailed(UUID jobId, String msg) {
        try {
            reportJobRepository.markFailedInTx(jobId, msg);
            log.warn("report_job id={} marked FAILED: {}", jobId, msg);
        } catch (Exception e) {
            log.error("report_job id={} — could not mark FAILED", jobId, e);
        }
    }

    boolean isConstraintViolation(Throwable t) {
        Throwable cause = t;
        while (cause != null) {
            if (cause instanceof org.hibernate.exception.ConstraintViolationException) {
                return true;
            }
            if (cause instanceof java.sql.SQLException sql && sql.getMessage() != null
                    && sql.getMessage().contains("uq_report_job_active_per_url")) {
                return true;
            }
            // Check class name (covers packaging differences)
            if (cause.getClass().getName().contains("ConstraintViolation")) return true;
            // Check message for the specific constraint name (unit-test and some drivers surface this)
            if (cause.getMessage() != null
                    && cause.getMessage().contains("uq_report_job_active_per_url")) {
                return true;
            }
            cause = cause.getCause();
        }
        return false;
    }

    private static String truncate(String s, int max) {
        if (s == null) return "null";
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }
}
