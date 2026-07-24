package com.secbret.integration;

import com.secbret.exception.ConflictException;
import com.secbret.model.entity.ScanJob;
import com.secbret.model.entity.ScannedUrl;
import com.secbret.model.enums.ScanDepth;
import com.secbret.model.enums.ScanJobStatus;
import com.secbret.scanner.UrlNormalizer;
import com.secbret.service.ScanPersistence;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The spec-mandated integration test for the C2 race-condition fix (Part II §1
 * decision #2). Proves against the real Flyway V1–V20 schema that:
 *
 * <ol>
 *   <li>after a supersede-then-insert cycle, {@code superseded_by} is set on the old
 *       job <b>by the V20 trigger alone</b> — zero application-level writes to that
 *       column;</li>
 *   <li>concurrent submits for the same URL from two threads leave exactly one active
 *       PENDING job, no constraint violation escapes, and both threads get a job back;</li>
 *   <li>the partial unique index {@code uq_scan_job_active_per_url} holds — a second
 *       direct PENDING insert for the same URL fails;</li>
 *   <li>(source-scan) {@code ScanPersistence.java} contains no write to
 *       {@code superseded_by}: the code-review checklist item, enforced as a test.</li>
 * </ol>
 *
 * <p>Runs on the RESOURCE_LOCAL {@code SecBretTestPU} where {@code @Transactional} is
 * inert, so it drives the package-private {@link ScanPersistence#createJobInTx} inside
 * an explicit {@code em.getTransaction()} block. The production path remains one JTA
 * transaction through {@link ScanPersistence#createJob}.
 */
class ScanPersistenceIT extends PostgresIntegrationSupport {

    private static final UrlNormalizer NORMALIZER = new UrlNormalizer();

    private ScanPersistence newService(EntityManager em) {
        return new ScanPersistence(em, NORMALIZER);
    }

    /** A distinct raw URL per test so tests don't collide on the shared container. */
    private static String uniqueUrl() {
        return "https://example.test/" + UUID.randomUUID().toString().replace("-", "");
    }

    private ScanJob createJob(EntityManager em, String rawUrl) {
        em.getTransaction().begin();
        ScanJob job = newService(em).createJobInTx(em, rawUrl, null, ScanDepth.QUICK);
        em.getTransaction().commit();
        return job;
    }

    @Test
    void supersededByIsSetByTriggerAloneAfterSupersedeThenInsert() {
        String rawUrl = uniqueUrl();

        EntityManager em = EMF.createEntityManager();
        try {
            // Persist URL + job A (PENDING).
            ScanJob jobA = createJob(em, rawUrl);
            assertThat(jobA.getStatus()).isEqualTo(ScanJobStatus.PENDING);
            assertThat(jobA.getSupersededBy()).isNull();

            // createJob again for the same URL → job B supersedes A.
            ScanJob jobB = createJob(em, rawUrl);
            assertThat(jobB.getStatus()).isEqualTo(ScanJobStatus.PENDING);

            // Refresh A from the DB: the trigger must have flipped it to SUPERSEDED and
            // set superseded_by = B.id — without any application UPDATE of that column.
            em.clear();
            ScanJob refreshedA = em.find(ScanJob.class, jobA.getId());
            assertThat(refreshedA.getStatus()).isEqualTo(ScanJobStatus.SUPERSEDED);
            assertThat(refreshedA.getSupersededBy())
                    .as("superseded_by must be written by the V20 trigger, not application code")
                    .isEqualTo(jobB.getId());

            // And B, the active job, has a null back-pointer.
            ScanJob refreshedB = em.find(ScanJob.class, jobB.getId());
            assertThat(refreshedB.getStatus()).isEqualTo(ScanJobStatus.PENDING);
            assertThat(refreshedB.getSupersededBy()).isNull();

            // Exactly one active job survives for this URL.
            assertThat(activeJobCount(em, refreshedB.getUrl().getId())).isEqualTo(1L);
        } finally {
            em.close();
        }
    }

    @Test
    void concurrentSubmitsLeaveExactlyOneActiveJobAndBothThreadsGetAJob() throws Exception {
        String rawUrl = uniqueUrl();

        // Seed the scanned_url + first job so both threads race on an existing URL row
        // (the FOR UPDATE lock is on that row).
        EntityManager seedEm = EMF.createEntityManager();
        UUID urlId;
        try {
            ScanJob seed = createJob(seedEm, rawUrl);
            urlId = seed.getUrl().getId();
        } finally {
            seedEm.close();
        }

        int threads = 2;
        CountDownLatch startGate = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        AtomicReference<Throwable> escaped = new AtomicReference<>();

        Future<UUID> f1 = pool.submit(() -> submitOnOwnEm(rawUrl, startGate, escaped));
        Future<UUID> f2 = pool.submit(() -> submitOnOwnEm(rawUrl, startGate, escaped));

        startGate.countDown(); // release both threads simultaneously
        UUID job1 = f1.get(30, TimeUnit.SECONDS);
        UUID job2 = f2.get(30, TimeUnit.SECONDS);
        pool.shutdown();
        assertThat(pool.awaitTermination(10, TimeUnit.SECONDS)).isTrue();

        // No constraint violation escaped either thread (the FOR UPDATE lock serialised them).
        assertThat(escaped.get()).as("no exception should escape a serialised submit").isNull();

        // Both threads got a job back (one may be the superseder of the other).
        assertThat(job1).isNotNull();
        assertThat(job2).isNotNull();
        assertThat(job1).isNotEqualTo(job2);

        // Exactly one active PENDING job survives for the URL.
        EntityManager verifyEm = EMF.createEntityManager();
        try {
            assertThat(activeJobCount(verifyEm, urlId)).isEqualTo(1L);
        } finally {
            verifyEm.close();
        }
    }

    private UUID submitOnOwnEm(String rawUrl, CountDownLatch gate, AtomicReference<Throwable> escaped) {
        EntityManager em = EMF.createEntityManager();
        try {
            gate.await();
            em.getTransaction().begin();
            ScanJob job = newService(em).createJobInTx(em, rawUrl, null, ScanDepth.QUICK);
            em.getTransaction().commit();
            return job.getId();
        } catch (Throwable t) {
            escaped.compareAndSet(null, t);
            if (em.getTransaction().isActive()) {
                em.getTransaction().rollback();
            }
            return null;
        } finally {
            em.close();
        }
    }

    @Test
    void partialUniqueIndexRejectsASecondDirectPendingInsertForSameUrl() {
        String rawUrl = uniqueUrl();

        EntityManager em = EMF.createEntityManager();
        try {
            ScanJob first = createJob(em, rawUrl);
            ScannedUrl url = em.find(ScannedUrl.class, first.getUrl().getId());

            // Bypass ScanPersistence entirely: insert a second PENDING job directly via
            // the EM. uq_scan_job_active_per_url must reject it.
            em.getTransaction().begin();
            ScanJob dup = new ScanJob();
            dup.setUrl(url);
            dup.setScanDepth(ScanDepth.QUICK);
            dup.setStatus(ScanJobStatus.PENDING);
            em.persist(dup);
            assertThatThrownBy(() -> em.flush())
                    .as("uq_scan_job_active_per_url must reject a second active job for the URL")
                    .isInstanceOf(Exception.class);
            em.getTransaction().rollback();
        } finally {
            em.close();
        }
    }

    @Test
    void createJobViaServiceNeverThrowsConflictUnderNormalSequentialUse() {
        // Sanity: sequential creates for the same URL supersede cleanly (the ConflictException
        // safety net stays dormant when the lock does its job).
        String rawUrl = uniqueUrl();
        EntityManager em = EMF.createEntityManager();
        try {
            for (int i = 0; i < 3; i++) {
                ScanJob job = createJob(em, rawUrl);
                assertThat(job.getStatus()).isEqualTo(ScanJobStatus.PENDING);
            }
            assertThat(activeJobCount(em, em.find(ScanJob.class,
                    createJob(em, rawUrl).getId()).getUrl().getId())).isEqualTo(1L);
        } catch (ConflictException e) {
            throw new AssertionError("Sequential supersede must not trigger the ConflictException net", e);
        } finally {
            em.close();
        }
    }

    @Test
    void scanPersistenceSourceContainsNoSupersededByWrite() throws Exception {
        // Code-review checklist item as a test: the step-4 UPDATE must be absent.
        Path src = Path.of("src/main/java/com/secbret/service/ScanPersistence.java");
        assertThat(Files.exists(src)).as("ScanPersistence source must be present").isTrue();

        List<String> writeLines = Files.readAllLines(src).stream()
                .map(String::trim)
                // Ignore comment/javadoc lines — only real code lines matter for the trap.
                .filter(l -> !l.startsWith("*") && !l.startsWith("//") && !l.startsWith("/*"))
                .filter(l -> l.toLowerCase().contains("superseded_by"))
                .filter(l -> l.toUpperCase().contains("UPDATE") || l.contains("="))
                .toList();

        assertThat(writeLines)
                .as("ScanPersistence must contain no write to superseded_by (V20 trigger owns it)")
                .isEmpty();
    }

    private static long activeJobCount(EntityManager em, UUID urlId) {
        return em.createQuery(
                        "SELECT COUNT(j) FROM ScanJob j WHERE j.url.id = :urlId "
                                + "AND j.status IN (:pending, :running)", Long.class)
                .setParameter("urlId", urlId)
                .setParameter("pending", ScanJobStatus.PENDING)
                .setParameter("running", ScanJobStatus.RUNNING)
                .getSingleResult();
    }
}
