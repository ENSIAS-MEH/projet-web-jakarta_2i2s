package com.secbret.service;

import com.secbret.exception.ConflictException;
import com.secbret.model.entity.ScanJob;
import com.secbret.model.entity.ScannedUrl;
import com.secbret.model.entity.SecBretUser;
import com.secbret.model.enums.ScanDepth;
import com.secbret.model.enums.ScanJobStatus;
import com.secbret.scanner.UrlNormalizer;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.PersistenceException;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.UUID;

/**
 * Transactional scan-job creation core (Part II §1 decision #2 — the C2 race-condition fix).
 *
 * <h2>Contract (the whole point of this class)</h2>
 * A single {@code @Transactional} boundary that turns a raw URL into a fresh
 * {@code PENDING} {@code scan_job}, preserving the invariant <em>at most one active
 * (PENDING/RUNNING) job per URL</em> — enforced at the DB level by the partial
 * unique index {@code uq_scan_job_active_per_url}.
 *
 * <h2>Sequence inside the transaction (Part IV scan_job note, verbatim)</h2>
 * <ol>
 *   <li>Normalize + hash the URL (Part II §C, delegated to {@link UrlNormalizer}).</li>
 *   <li>Find-or-create the {@code scanned_url} row by {@code normalized_hash}; the
 *       concurrent-insert race on {@code uq_scanned_url_normalized_hash} is caught
 *       and resolved by re-selecting the winner's row.</li>
 *   <li><b>Acquire the row lock:</b> {@code em.find(ScannedUrl, id, PESSIMISTIC_WRITE)}
 *       ⇒ {@code SELECT ... FOR UPDATE} on the {@code scanned_url} row, serialising
 *       all concurrent submits for this URL <em>before</em> any {@code scan_job} read
 *       or write.</li>
 *   <li>Mark every active ({@code PENDING}/{@code RUNNING}) job for the URL
 *       {@code SUPERSEDED}.</li>
 *   <li>Insert the new {@code PENDING} {@code scan_job}.</li>
 * </ol>
 *
 * <h2>The trap (Part II §1 decision #2 / V20)</h2>
 * There is <strong>no step 4 UPDATE writing {@code superseded_by}</strong>. The V20
 * {@code link_superseded_scan_job} AFTER INSERT trigger sets that back-pointer
 * atomically with the INSERT. Application code must contain no write to that column;
 * the {@link ScanJob} entity mapping ({@code insertable=false, updatable=false})
 * blocks JPA writes, and this class adds no native UPDATE either. Grep this file for
 * {@code superseded_by} — it does not appear.
 *
 * <h2>Lock choice — {@code PESSIMISTIC_WRITE} over a native {@code FOR UPDATE}</h2>
 * {@code em.find(ScannedUrl.class, id, LockModeType.PESSIMISTIC_WRITE)} compiles to
 * PostgreSQL {@code SELECT ... FOR UPDATE} (Hibernate's PostgreSQLDialect maps
 * PESSIMISTIC_WRITE to {@code FOR UPDATE}). It is chosen over a hand-written native
 * query because it (a) keeps the locked row managed in the persistence context so a
 * later flush sees a consistent snapshot, (b) avoids an entity/native identity split,
 * and (c) is portable JPA. The DB-level effect is identical to the spec's literal
 * {@code SELECT * FROM scanned_url WHERE id = :urlId FOR UPDATE}.
 *
 * <h2>Testability under RESOURCE_LOCAL</h2>
 * The test persistence unit is {@code RESOURCE_LOCAL}, where {@code @Transactional} is
 * inert. All real work therefore lives in the package-private {@link
 * #createJobInTx(EntityManager, String, UUID, ScanDepth)}, which takes an explicit
 * {@link EntityManager} and assumes an <em>already-open</em> transaction. Production
 * calls it through the public {@code @Transactional} {@link #createJob} on the JTA
 * unit; the IT calls it directly inside an explicit {@code em.getTransaction()} block.
 * The production path is still exactly one JTA transaction.
 *
 * <p>Complexity: O(k) DB round-trips where k is the (tiny, ≤2) number of active jobs
 * for the URL; the {@code FOR UPDATE} lock bounds concurrency to one submit per URL.
 */
@ApplicationScoped
public class ScanPersistence {

    private static final Logger log = LoggerFactory.getLogger(ScanPersistence.class);

    @PersistenceContext(unitName = "SecBretPU")
    EntityManager em;

    @Inject
    UrlNormalizer urlNormalizer;

    public ScanPersistence() {
    }

    /** Test constructor — production uses the container-injected {@code @PersistenceContext}. */
    public ScanPersistence(EntityManager em, UrlNormalizer urlNormalizer) {
        this.em = em;
        this.urlNormalizer = urlNormalizer;
    }

    /**
     * Production entry point: create a fresh PENDING scan job for {@code rawUrl} inside
     * one JTA transaction, superseding any active job for the same URL.
     *
     * @param rawUrl            the raw URL as submitted; normalized + hashed here
     * @param submittedByUserId the submitting user's id, or {@code null} for anonymous
     * @param depth             requested scan depth (QUICK/DEEP)
     * @return the newly-inserted PENDING {@link ScanJob}
     * @throws com.secbret.exception.ValidationException if the URL is invalid
     * @throws ConflictException if the DB one-active-job constraint is violated despite
     *                           the lock (last-resort safety net; logged ERROR)
     */
    @Transactional
    public ScanJob createJob(String rawUrl, UUID submittedByUserId, ScanDepth depth) {
        return createJobInTx(em, rawUrl, submittedByUserId, depth);
    }

    /**
     * Transactional core, decoupled from JTA so it is exercisable under a RESOURCE_LOCAL
     * EntityManager. <b>Pre-condition:</b> {@code entityManager} is enlisted in an active
     * transaction. This method never begins/commits — the caller owns the boundary.
     *
     * @param entityManager     an EntityManager with an already-open transaction
     * @param rawUrl            raw URL to normalize + scan
     * @param submittedByUserId submitting user's id, or {@code null}
     * @param depth             requested scan depth
     * @return the newly-inserted PENDING {@link ScanJob}
     */
    public ScanJob createJobInTx(EntityManager entityManager, String rawUrl, UUID submittedByUserId, ScanDepth depth) {
        // Step 1: normalize + hash (Part II §C). Throws ValidationException on bad input.
        String normalizedUrl = urlNormalizer.normalize(rawUrl);
        String hash = urlNormalizer.hash(rawUrl);

        // Step 2: find-or-create the scanned_url row by normalized_hash, racing safely
        // on uq_scanned_url_normalized_hash.
        ScannedUrl scannedUrl = findOrCreateScannedUrl(entityManager, rawUrl, normalizedUrl, hash);

        // Step 3: acquire the row lock (SELECT ... FOR UPDATE) BEFORE any scan_job
        // read/write. This serialises concurrent submits for this URL.
        ScannedUrl locked = entityManager.find(
                ScannedUrl.class, scannedUrl.getId(), LockModeType.PESSIMISTIC_WRITE);

        // Step 4: mark any active job for this URL SUPERSEDED. (This is the supersede
        // UPDATE — NOT the forbidden superseded_by back-pointer UPDATE.)
        supersedeActiveJobs(entityManager, locked.getId());

        // Step 5: insert the new PENDING job. The V20 AFTER INSERT trigger sets the
        // superseded_by back-pointer on the superseded row atomically — no application
        // UPDATE of that column exists anywhere in this class.
        ScanJob newJob = new ScanJob();
        newJob.setUrl(locked);
        newJob.setScanDepth(depth == null ? ScanDepth.QUICK : depth);
        newJob.setStatus(ScanJobStatus.PENDING);
        if (submittedByUserId != null) {
            newJob.setSubmittedBy(entityManager.getReference(SecBretUser.class, submittedByUserId));
        }

        try {
            entityManager.persist(newJob);
            entityManager.flush(); // force the INSERT (and the trigger) inside this try
        } catch (PersistenceException ex) {
            // Last-resort safety net on uq_scan_job_active_per_url. With the FOR UPDATE
            // lock in place this should never fire; if it does we LOG ERROR (never
            // silently swallow — Part II §1 #2) and map to a 409 Conflict.
            log.error(
                    "uq_scan_job_active_per_url violated for urlId={} despite the FOR UPDATE lock; "
                            + "another active job already exists for this URL.",
                    locked.getId(), ex);
            throw new ConflictException("An active scan already exists for this URL.");
        }

        log.info("Created PENDING scan_job id={} urlId={} depth={}",
                newJob.getId(), locked.getId(), newJob.getScanDepth());
        return newJob;
    }

    /**
     * Find-or-create the {@code scanned_url} row for {@code hash}. On the concurrent-insert
     * race (two submits for a brand-new URL both miss the SELECT and both INSERT), the
     * loser catches the {@code uq_scanned_url_normalized_hash} violation and re-selects the
     * winner's row.
     *
     * <p>Loop-free: at most one retry is possible because after a unique-constraint failure
     * the winning row is guaranteed to exist.
     */
    private ScannedUrl findOrCreateScannedUrl(
            EntityManager entityManager, String rawUrl, String normalizedUrl, String hash) {
        ScannedUrl existing = selectByHash(entityManager, hash);
        if (existing != null) {
            return existing;
        }

        ScannedUrl fresh = new ScannedUrl();
        fresh.setOriginalUrl(rawUrl);
        fresh.setNormalizedHash(hash);
        try {
            entityManager.persist(fresh);
            entityManager.flush(); // surface the unique-constraint race now
            return fresh;
        } catch (PersistenceException ex) {
            // Another transaction inserted the same normalized_hash first. Detach our
            // failed instance and re-select the winner. If it is genuinely absent the
            // failure was something else, so rethrow.
            log.debug("scanned_url insert race on normalized_hash={} — re-selecting winner.", hash);
            entityManager.detach(fresh);
            ScannedUrl winner = selectByHash(entityManager, hash);
            if (winner == null) {
                throw ex;
            }
            return winner;
        }
    }

    private ScannedUrl selectByHash(EntityManager entityManager, String hash) {
        return entityManager.createQuery(
                        "SELECT s FROM ScannedUrl s WHERE s.normalizedHash = :hash", ScannedUrl.class)
                .setParameter("hash", hash)
                .getResultStream()
                .findFirst()
                .orElse(null);
    }

    /**
     * Marks every active (PENDING/RUNNING) job for {@code urlId} as SUPERSEDED. Uses a bulk
     * JPQL UPDATE, then clears the managed state so the subsequent INSERT + trigger see the
     * committed status transition. Does NOT touch {@code superseded_by}.
     */
    private void supersedeActiveJobs(EntityManager entityManager, UUID urlId) {
        List<ScanJob> active = entityManager.createQuery(
                        "SELECT j FROM ScanJob j WHERE j.url.id = :urlId "
                                + "AND j.status IN (:pending, :running)", ScanJob.class)
                .setParameter("urlId", urlId)
                .setParameter("pending", ScanJobStatus.PENDING)
                .setParameter("running", ScanJobStatus.RUNNING)
                .getResultList();

        for (ScanJob job : active) {
            job.setStatus(ScanJobStatus.SUPERSEDED);
        }
        // Flush the status transition so the partial unique index no longer sees these
        // rows as active when the new PENDING row is inserted (avoids a spurious
        // uq_scan_job_active_per_url violation), and so the V20 AFTER INSERT trigger
        // finds them as SUPERSEDED with superseded_by IS NULL.
        entityManager.flush();
    }
}
