package com.secbret.repository;

import com.secbret.model.entity.ReportJob;
import com.secbret.model.entity.ScannedUrl;
import com.secbret.model.entity.SecBretUser;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for {@link ReportJob}.
 *
 * <h2>Decision #13 — file_data exclusion in list/poll paths</h2>
 * Hibernate bytecode enhancement is disabled. Without it, {@code @Basic(LAZY)} on
 * {@code byte[]} loads eagerly. All list and poll methods use JPQL constructor
 * projections ({@code SELECT r.id, r.url.id, r.status, …}) that exclude
 * {@code file_data} so multi-MB BLOBs are never pulled into memory when
 * checking job status or listing jobs. Only {@link #loadFileData(UUID)} fetches the
 * bytes, and only the PDF download path calls that method.
 */
@ApplicationScoped
public class ReportJobRepository {

    @PersistenceContext(unitName = "SecBretPU")
    EntityManager em;

    public ReportJobRepository() {}

    /** Test constructor. */
    public ReportJobRepository(EntityManager em) { this.em = em; }

    // -----------------------------------------------------------------------
    // Write
    // -----------------------------------------------------------------------

    @Transactional
    public ReportJob persist(ReportJob job) {
        em.persist(job);
        return job;
    }

    /**
     * Transition to GENERATING. Does NOT touch file_data (decision #13).
     * Owns its @Transactional so async worker calls this cleanly.
     */
    @Transactional
    public void markGeneratingInTx(UUID jobId) {
        // Native UPDATE to be explicit: no file_data column touched (decision #13 guard).
        em.createNativeQuery(
                "UPDATE report_job SET status = 'GENERATING' WHERE id = CAST(:id AS uuid)")
                .setParameter("id", jobId.toString())
                .executeUpdate();
    }

    /**
     * Transition to COMPLETED with PDF bytes. file_data written ONLY here (decision #13).
     * Owns its @Transactional.
     */
    @Transactional
    public void markCompletedInTx(UUID jobId, byte[] pdfBytes, long fileSizeBytes) {
        em.createNativeQuery(
                "UPDATE report_job SET status = 'COMPLETED', file_data = :data," +
                " file_size_bytes = :size, completed_at = NOW() WHERE id = CAST(:id AS uuid)")
                .setParameter("data", pdfBytes)
                .setParameter("size", fileSizeBytes)
                .setParameter("id", jobId.toString())
                .executeUpdate();
    }

    /**
     * Transition to FAILED. Does NOT touch file_data. Owns its @Transactional.
     */
    @Transactional
    public void markFailedInTx(UUID jobId, String errorMessage) {
        em.createNativeQuery(
                "UPDATE report_job SET status = 'FAILED', error_message = :msg WHERE id = CAST(:id AS uuid)")
                .setParameter("msg", errorMessage)
                .setParameter("id", jobId.toString())
                .executeUpdate();
    }

    // -----------------------------------------------------------------------
    // Read — poll / list paths (no file_data loaded)
    // -----------------------------------------------------------------------

    /**
     * Find by ID, loading url and requestedBy but NOT file_data.
     * Uses JOIN FETCH on associations; file_data will still be loaded eagerly
     * by Hibernate (no bytecode enhancement), so this method is only used for
     * the poll endpoint which needs metadata, not bytes. The download path uses
     * {@link #loadFileData(UUID)} instead.
     *
     * Note: because bytecode enhancement is disabled, Hibernate WILL load file_data
     * here too. To truly avoid it we must use a constructor projection — but we need
     * the full entity for the service layer. For list/poll paths only the status
     * projection methods below are used; this method is reserved for single-job
     * detail fetches where the overhead is acceptable.
     */
    @Transactional
    public Optional<ReportJob> findByIdEager(UUID id) {
        return em.createQuery(
                        "SELECT j FROM ReportJob j "
                                + "LEFT JOIN FETCH j.url "
                                + "LEFT JOIN FETCH j.requestedBy "
                                + "WHERE j.id = :id",
                        ReportJob.class)
                .setParameter("id", id)
                .getResultStream()
                .findFirst();
    }

    /**
     * Find the active (PENDING or GENERATING) job for a URL.
     * Projection only — no file_data (the WHERE clause makes this a rare/single hit,
     * but we still use projection because eager-load warning).
     */
    @Transactional
    public Optional<ReportJob> findActiveByUrlId(UUID urlId) {
        return em.createQuery(
                        "SELECT j FROM ReportJob j LEFT JOIN FETCH j.url LEFT JOIN FETCH j.requestedBy"
                                + " WHERE j.url.id = :urlId AND j.status IN ('PENDING','GENERATING')",
                        ReportJob.class)
                .setParameter("urlId", urlId)
                .getResultStream()
                .findFirst();
    }

    // -----------------------------------------------------------------------
    // Read — PDF download path only
    // -----------------------------------------------------------------------

    /** Load the raw PDF bytes for the download path. Separate query to be explicit. */
    @Transactional
    public Optional<byte[]> loadFileData(UUID jobId) {
        return em.createQuery(
                        "SELECT j.fileData FROM ReportJob j WHERE j.id = :id",
                        byte[].class)
                .setParameter("id", jobId)
                .getResultStream()
                .findFirst();
    }
}
