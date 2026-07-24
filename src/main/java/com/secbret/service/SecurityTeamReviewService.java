package com.secbret.service;

import com.secbret.exception.ConflictException;
import com.secbret.exception.ResourceNotFoundException;
import com.secbret.exception.ValidationException;
import com.secbret.model.entity.ScannedUrl;
import com.secbret.model.entity.SecBretAnalysis;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.entity.SecurityTeamReview;
import com.secbret.model.entity.UserReport;
import com.secbret.model.enums.CommunityVerdict;
import com.secbret.repository.SecBretAnalysisRepository;
import com.secbret.repository.SecurityTeamReviewRepository;
import com.secbret.repository.UserReportRepository;
import com.secbret.repository.UserRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Security team review pipeline (Part III §6 / Part II §8.5).
 *
 * <h2>C4 — Critical rule (HANDOFF.md Known Traps)</h2>
 * Analyst MODIFY writes final-verdict tables ONLY — NEVER secbret_analysis.verdict.
 * This service:
 * <ul>
 *   <li>Writes security_team_review.final_verdict with VERIFIED_MALICIOUS/VERIFIED_BENIGN/REJECTED</li>
 *   <li>Writes user_report.verdict with the same final values</li>
 *   <li>Writes scanned_url.community_verdict (MALICIOUS/BENIGN) on APPROVE/MODIFY only</li>
 *   <li>NEVER touches secbret_analysis.verdict — it stays BENIGN/SUSPICIOUS forever</li>
 * </ul>
 *
 * <h2>APPROVE threshold</h2>
 * threatScore >= AUTO_APPROVE_ANALYST_THRESHOLD (default 0.50) → VERIFIED_MALICIOUS;
 * otherwise → VERIFIED_BENIGN (Part II §8 APPROVE Threshold Note).
 *
 * <h2>REJECT behavior (§8.5)</h2>
 * user_report.status = REJECTED, user_report.verdict = REJECTED.
 * scanned_url.community_verdict is NOT modified.
 */
@ApplicationScoped
public class SecurityTeamReviewService {

    private static final Logger log = LoggerFactory.getLogger(SecurityTeamReviewService.class);

    /** Default APPROVE threshold — score >= this → VERIFIED_MALICIOUS on APPROVE. */
    private static final double DEFAULT_ANALYST_THRESHOLD = 0.50;
    private static final String ENV_ANALYST_THRESHOLD = "AUTO_APPROVE_ANALYST_THRESHOLD";

    private final double analystThreshold;

    @Inject
    private UserReportRepository reportRepository;

    @Inject
    private SecBretAnalysisRepository analysisRepository;

    @Inject
    private SecurityTeamReviewRepository reviewRepository;

    @Inject
    private AuditLogService auditLogService;

    @Inject
    private UserRepository userRepository;

    @PersistenceContext(unitName = "SecBretPU")
    private EntityManager em;

    public SecurityTeamReviewService() {
        this.analystThreshold = parseEnvThreshold();
    }

    private static double parseEnvThreshold() {
        String raw = System.getenv(ENV_ANALYST_THRESHOLD);
        if (raw == null || raw.isBlank()) return DEFAULT_ANALYST_THRESHOLD;
        try {
            double v = Double.parseDouble(raw.trim());
            if (v < 0.0 || v > 1.0) {
                LoggerFactory.getLogger(SecurityTeamReviewService.class)
                        .warn("AUTO_APPROVE_ANALYST_THRESHOLD={} out of [0,1]; using default {}", raw, DEFAULT_ANALYST_THRESHOLD);
                return DEFAULT_ANALYST_THRESHOLD;
            }
            return v;
        } catch (NumberFormatException e) {
            return DEFAULT_ANALYST_THRESHOLD;
        }
    }

    // =========================================================================
    // Submit a review
    // =========================================================================

    /**
     * Submit an analyst review for a PENDING_REVIEW report.
     *
     * @param reportId      the user_report UUID
     * @param reviewerId    the analyst's user UUID
     * @param action        APPROVE, REJECT, or MODIFY
     * @param finalVerdict  required for MODIFY (VERIFIED_MALICIOUS or VERIFIED_BENIGN);
     *                      ignored for REJECT; derived for APPROVE
     * @param reviewerNotes optional (max 5000 chars)
     * @return the persisted SecurityTeamReview
     */
    @Transactional
    public SecurityTeamReview submitReview(UUID reportId, UUID reviewerId,
                                           String action, String finalVerdict, String reviewerNotes) {
        // Load report with URL for community_verdict update
        UserReport report = em.find(UserReport.class, reportId);
        if (report == null) {
            throw new ResourceNotFoundException("user_report", reportId);
        }
        if (!"PENDING_REVIEW".equals(report.getStatus())) {
            throw new ConflictException("user_report id=" + reportId
                    + " is not in PENDING_REVIEW state (current: " + report.getStatus() + ")");
        }

        // Exactly one review per report (UNIQUE constraint on security_team_review.user_report_id)
        if (reviewRepository.findByUserReportId(reportId).isPresent()) {
            throw new ConflictException("user_report id=" + reportId + " has already been reviewed");
        }

        SecBretAnalysis analysis = analysisRepository.findByUserReportId(reportId)
                .orElseThrow(() -> new ResourceNotFoundException("secbret_analysis for report", reportId));

        SecBretUser reviewer = userRepository.findById(reviewerId)
                .orElseThrow(() -> new ResourceNotFoundException("user", reviewerId));

        String resolvedFinalVerdict = resolveVerdict(action, finalVerdict, analysis);

        // C4 runtime precondition: final-verdict values must NEVER be AI-only values
        if ("BENIGN".equals(resolvedFinalVerdict) || "SUSPICIOUS".equals(resolvedFinalVerdict)) {
            throw new IllegalStateException("C4 violation: attempted to write AI-only verdict '"
                    + resolvedFinalVerdict + "' to security_team_review.final_verdict");
        }

        String reviewStatus = mapActionToReviewStatus(action);
        String reportVerdict = resolvedFinalVerdict;
        String reportStatus = "REJECT".equals(action) ? "REJECTED" : "VERIFIED";

        // C4 runtime precondition for user_report.verdict too
        if ("BENIGN".equals(reportVerdict) || "SUSPICIOUS".equals(reportVerdict)) {
            throw new IllegalStateException("C4 violation: AI-only verdict cannot be written to user_report.verdict");
        }

        // Write security_team_review
        SecurityTeamReview review = new SecurityTeamReview();
        review.setUserReport(report);
        review.setSecbretAnalysis(analysis);
        review.setReviewedBy(reviewer);
        review.setStatus(reviewStatus);
        review.setFinalVerdict(resolvedFinalVerdict);
        review.setReviewerNotes(reviewerNotes);
        // @PrePersist sets created_at = reviewed_at (v1: no draft state)
        reviewRepository.persist(review);

        // Write user_report.verdict + status (C4: final-verdict tables only)
        report.setVerdict(reportVerdict);
        report.setStatus(reportStatus);
        report.setResolvedAt(LocalDateTime.now());

        // Update scanned_url.community_verdict (REJECT does NOT modify — §8.5)
        if (!"REJECT".equals(action)) {
            ScannedUrl url = report.getUrl();
            if (url != null) {
                url.setCommunityVerdict(
                        "VERIFIED_MALICIOUS".equals(resolvedFinalVerdict)
                                ? CommunityVerdict.MALICIOUS
                                : CommunityVerdict.BENIGN);
            }
        }

        // Audit log
        String auditAction = switch (action) {
            case "APPROVE" -> "REVIEW_APPROVED";
            case "REJECT" -> "REVIEW_REJECTED";
            default -> "REVIEW_MODIFIED";
        };
        String detail = "{\"reportId\":\"" + reportId + "\",\"finalVerdict\":\"" + resolvedFinalVerdict + "\"}";
        auditLogService.log(reviewer, auditAction, "user_report", reportId, detail);

        log.info("security_team_review id={} submitted for user_report id={} action={} finalVerdict={}",
                review.getId(), reportId, action, resolvedFinalVerdict);
        return review;
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private String resolveVerdict(String action, String suppliedFinalVerdict, SecBretAnalysis analysis) {
        return switch (action) {
            case "APPROVE" -> {
                // threatScore >= analystThreshold → VERIFIED_MALICIOUS, else VERIFIED_BENIGN
                double score = analysis.getThreatScore().doubleValue();
                yield score >= analystThreshold ? "VERIFIED_MALICIOUS" : "VERIFIED_BENIGN";
            }
            case "REJECT" -> "REJECTED";
            case "MODIFY" -> {
                if (suppliedFinalVerdict == null || suppliedFinalVerdict.isBlank()) {
                    throw new ValidationException("finalVerdict is required for MODIFY action");
                }
                if (!"VERIFIED_MALICIOUS".equals(suppliedFinalVerdict)
                        && !"VERIFIED_BENIGN".equals(suppliedFinalVerdict)) {
                    throw new ValidationException(
                            "finalVerdict must be VERIFIED_MALICIOUS or VERIFIED_BENIGN for MODIFY; got: "
                                    + suppliedFinalVerdict);
                }
                yield suppliedFinalVerdict;
            }
            default -> throw new ValidationException("action must be APPROVE, REJECT, or MODIFY; got: " + action);
        };
    }

    private String mapActionToReviewStatus(String action) {
        return switch (action) {
            case "APPROVE" -> "APPROVED";
            case "REJECT" -> "REJECTED";
            case "MODIFY" -> "MODIFIED";
            default -> throw new ValidationException("Unknown action: " + action);
        };
    }
}
