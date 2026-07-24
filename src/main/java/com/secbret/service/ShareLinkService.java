package com.secbret.service;

import com.secbret.exception.ResourceNotFoundException;
import com.secbret.model.entity.ReportJob;
import com.secbret.model.entity.ShareLink;
import com.secbret.repository.ReportJobRepository;
import com.secbret.repository.ShareLinkRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Share-link operations: access (with validity check), list, revoke.
 *
 * Ownership semantics: REPORTER may only revoke own links.
 * Anti-enumeration: not-found and not-owned both return 404.
 * Expired or revoked → 410 (caller must differentiate).
 */
@ApplicationScoped
public class ShareLinkService {

    @Inject private ShareLinkRepository shareLinkRepository;
    @Inject private ReportJobRepository reportJobRepository;

    // -----------------------------------------------------------------------
    // Access (anonymous GET /share/{uuid})
    // -----------------------------------------------------------------------

    /**
     * Look up a share link by UUID token for anonymous access.
     *
     * @param uuidToken  the token from the URL
     * @return the ShareLink if found; empty if not found at all
     */
    public Optional<ShareLink> findByToken(String uuidToken) {
        return shareLinkRepository.findByToken(uuidToken);
    }

    /**
     * Record an anonymous access atomically (access_count + 1, last_accessed_at = NOW()).
     * Uses the atomic SQL UPDATE in the repository — never ORM read-modify-write.
     */
    public void recordAccess(UUID linkId) {
        shareLinkRepository.incrementAccessCountInTx(linkId);
    }

    /**
     * True if the link is currently valid (not revoked, not expired).
     */
    public boolean isValid(ShareLink link) {
        return !link.isRevoked() && link.getExpiresAt().isAfter(LocalDateTime.now());
    }

    // -----------------------------------------------------------------------
    // List (GET /share — authenticated)
    // -----------------------------------------------------------------------

    public List<ShareLink> listOwn(UUID userId, int page, int size) {
        return shareLinkRepository.findByCreatedByPage(userId, page, size);
    }

    public long countOwn(UUID userId) {
        return shareLinkRepository.countByCreatedBy(userId);
    }

    // -----------------------------------------------------------------------
    // Revoke (DELETE /share/{uuid})
    // -----------------------------------------------------------------------

    /**
     * Revoke a share link.
     *
     * <p>Ownership rules (§5 / anti-enumeration):
     * <ul>
     *   <li>REPORTER: may only revoke own (created_by = userId); 404 for not-found or not-theirs.</li>
     *   <li>ANALYST, ADMIN: may revoke any link.</li>
     * </ul>
     *
     * @param uuidToken  the share link token
     * @param callerId   the authenticated user's ID
     * @param isReporter true if caller is REPORTER (not ANALYST/ADMIN)
     */
    public void revoke(String uuidToken, UUID callerId, boolean isReporter) {
        ShareLink link = shareLinkRepository.findByToken(uuidToken)
                .orElseThrow(() -> new ResourceNotFoundException("share_link", uuidToken));

        if (isReporter) {
            // Anti-enumeration: not-owned → 404, not 403
            boolean isOwner = link.getCreatedBy() != null
                    && callerId.equals(link.getCreatedBy().getId());
            if (!isOwner) {
                throw new ResourceNotFoundException("share_link", uuidToken);
            }
        }

        shareLinkRepository.revokeInTx(link.getId());
    }

    // -----------------------------------------------------------------------
    // Find by token for revoke by UUID (DELETE uses token path param)
    // -----------------------------------------------------------------------

    public Optional<ShareLink> findByTokenEager(String uuidToken) {
        return shareLinkRepository.findByToken(uuidToken);
    }

    // -----------------------------------------------------------------------
    // Find the auto-created share link for a completed job (GET /report-jobs/{jobId})
    // -----------------------------------------------------------------------

    public Optional<ShareLink> findActiveShareForJob(UUID reportJobId) {
        return shareLinkRepository.findFirstByReportJobId(reportJobId);
    }
}
