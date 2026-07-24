package com.secbret.service;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Application-level stale-job recovery (Part II §10.4 / Part IV "Application-Level
 * Stale Job Recovery").
 *
 * <p>SecBret runs no cron scheduler, so if the JVM or host crashes while a
 * {@code scan_job} or {@code report_job} is in a non-terminal state, those rows would
 * otherwise stay stuck forever. On every Payara start this bean marks all interrupted
 * jobs {@code FAILED} and purges expired idempotency keys, exactly per the spec's SQL:
 *
 * <pre>
 *   UPDATE scan_job   SET status='FAILED', error_message=COALESCE(error_message,'')||'; server restart'
 *     WHERE status IN ('PENDING','RUNNING');
 *   UPDATE report_job SET status='FAILED', error_message=COALESCE(error_message,'')||'; server restart'
 *     WHERE status IN ('PENDING','GENERATING');
 *   DELETE FROM idempotency_key WHERE expires_at < NOW();
 * </pre>
 *
 * <p>The statements are native SQL against the Flyway-owned tables rather than JPQL:
 * {@code report_job} and {@code idempotency_key} have no JPA entities in this phase
 * (Task 9 scope is scan-persistence), and the spec quotes this SQL verbatim. There is
 * no age threshold — the single-instance deployment (Part II §10.4 caution) means every
 * non-terminal job at boot is by definition orphaned by the crash.
 *
 * <p>{@link StartupStaleJobRecovery} invokes {@link #recover()} eagerly at deploy time.
 * The work lives here (not in the {@code @Singleton}) so it is unit/integration testable
 * without an EJB container: {@link #recoverInTx(EntityManager)} takes an explicit
 * EntityManager and assumes an already-open transaction, matching the RESOURCE_LOCAL
 * test unit where {@code @Transactional} is inert.
 */
@ApplicationScoped
public class StaleJobRecovery {

    private static final Logger log = LoggerFactory.getLogger(StaleJobRecovery.class);

    private static final String FAIL_INTERRUPTED_SCAN_JOBS =
            "UPDATE scan_job "
                    + "SET status = 'FAILED', "
                    + "    error_message = COALESCE(error_message, '') || '; server restart' "
                    + "WHERE status IN ('PENDING', 'RUNNING')";

    private static final String FAIL_INTERRUPTED_REPORT_JOBS =
            "UPDATE report_job "
                    + "SET status = 'FAILED', "
                    + "    error_message = COALESCE(error_message, '') || '; server restart' "
                    + "WHERE status IN ('PENDING', 'GENERATING')";

    private static final String PURGE_EXPIRED_IDEMPOTENCY_KEYS =
            "DELETE FROM idempotency_key WHERE expires_at < NOW()";

    @PersistenceContext(unitName = "SecBretPU")
    EntityManager em;

    public StaleJobRecovery() {
    }

    /** Test constructor — production uses the container-injected {@code @PersistenceContext}. */
    public StaleJobRecovery(EntityManager em) {
        this.em = em;
    }

    /** Production entry point: recover orphaned jobs inside one JTA transaction. */
    @Transactional
    public void recover() {
        recoverInTx(em);
    }

    /**
     * Transactional core, decoupled from JTA so it runs under a RESOURCE_LOCAL
     * EntityManager. <b>Pre-condition:</b> {@code entityManager} is enlisted in an active
     * transaction; this method never begins/commits.
     *
     * @param entityManager an EntityManager with an already-open transaction
     */
    public void recoverInTx(EntityManager entityManager) {
        int failedScans = entityManager.createNativeQuery(FAIL_INTERRUPTED_SCAN_JOBS).executeUpdate();
        int failedReports = entityManager.createNativeQuery(FAIL_INTERRUPTED_REPORT_JOBS).executeUpdate();
        int purgedKeys = entityManager.createNativeQuery(PURGE_EXPIRED_IDEMPOTENCY_KEYS).executeUpdate();

        if (failedScans > 0 || failedReports > 0 || purgedKeys > 0) {
            log.warn("Stale-job recovery at startup: {} scan_job and {} report_job rows marked FAILED "
                            + "(server restart), {} expired idempotency_key rows purged.",
                    failedScans, failedReports, purgedKeys);
        } else {
            log.info("Stale-job recovery at startup: no interrupted jobs or expired idempotency keys found.");
        }
    }
}
