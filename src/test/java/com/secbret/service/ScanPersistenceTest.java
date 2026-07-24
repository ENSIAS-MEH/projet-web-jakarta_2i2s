package com.secbret.service;

import com.secbret.exception.ConflictException;
import com.secbret.model.entity.ScanJob;
import com.secbret.model.entity.ScannedUrl;
import com.secbret.model.enums.ScanDepth;
import com.secbret.model.enums.ScanJobStatus;
import com.secbret.scanner.UrlNormalizer;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.persistence.PersistenceException;
import jakarta.persistence.TypedQuery;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ScanPersistence}'s find-or-create race handling and the
 * ConstraintViolation safety net (Part II §1 decision #2). The EntityManager is mocked;
 * the DB-integration behaviour (trigger, FOR UPDATE, partial unique index) lives in
 * {@code ScanPersistenceIT}.
 */
@ExtendWith(MockitoExtension.class)
class ScanPersistenceTest {

    private static final String RAW_URL = "https://example.test/login";
    private static final String NORM_URL = "https://example.test/login";
    private static final String HASH = "a".repeat(64);

    @Mock
    EntityManager em;

    @Mock
    UrlNormalizer normalizer;

    private ScanPersistence service;

    @BeforeEach
    void setUp() {
        service = new ScanPersistence(em, normalizer);
        lenient().when(normalizer.normalize(RAW_URL)).thenReturn(NORM_URL);
        lenient().when(normalizer.hash(RAW_URL)).thenReturn(HASH);
    }

    @Test
    @DisplayName("reuses existing scanned_url and does not persist a new one when hash already present")
    void findOrCreate_existingUrl_noInsert() {
        ScannedUrl existing = urlWithId(UUID.randomUUID());
        stubSelectByHash(existing);
        stubSupersedeSelectEmpty();
        when(em.find(eq(ScannedUrl.class), any(), any(LockModeType.class))).thenReturn(existing);

        service.createJobInTx(em, RAW_URL, null, ScanDepth.QUICK);

        // The only persist is the new ScanJob — never a new ScannedUrl.
        verify(em, never()).persist(any(ScannedUrl.class));
        verify(em).persist(any(ScanJob.class));
    }

    @Test
    @DisplayName("on scanned_url insert race, detaches the loser and re-selects the winner")
    void findOrCreate_insertRace_reselectsWinner() {
        UUID winnerId = UUID.randomUUID();
        ScannedUrl winner = urlWithId(winnerId);

        // First select: none. After the failed insert, re-select returns the winner.
        stubSelectByHashSequence(null, winner);
        stubSupersedeSelectEmpty();

        // persist(ScannedUrl) then flush() throws → race; job persist+flush succeeds.
        doThrow(new PersistenceException("uq_scanned_url_normalized_hash"))
                .doNothing() // subsequent flush (job) succeeds
                .when(em).flush();
        when(em.find(eq(ScannedUrl.class), eq(winnerId), any(LockModeType.class))).thenReturn(winner);

        ScanJob job = service.createJobInTx(em, RAW_URL, null, ScanDepth.QUICK);

        assertThat(job).isNotNull();
        verify(em).detach(any(ScannedUrl.class));
        verify(em).persist(any(ScanJob.class));
    }

    @Test
    @DisplayName("rethrows the original exception when the insert failure is not a hash race")
    void findOrCreate_genuineFailure_rethrows() {
        // Select returns null both times → the failure was NOT a lost hash race.
        stubSelectByHashSequence(null, null);
        PersistenceException boom = new PersistenceException("disk full");
        doThrow(boom).when(em).flush();

        assertThatThrownBy(() -> service.createJobInTx(em, RAW_URL, null, ScanDepth.QUICK))
                .isSameAs(boom);
        verify(em, never()).persist(any(ScanJob.class));
    }

    @Test
    @DisplayName("maps a scan_job unique-constraint violation to ConflictException (logged, not swallowed)")
    void jobInsert_uniqueViolation_throwsConflict() {
        ScannedUrl existing = urlWithId(UUID.randomUUID());
        stubSelectByHash(existing);
        stubSupersedeSelectEmpty();
        when(em.find(eq(ScannedUrl.class), any(), any(LockModeType.class))).thenReturn(existing);

        // First flush (supersedeActiveJobs, empty list) succeeds; the second flush
        // (after the job persist) throws the uq_scan_job_active_per_url violation.
        doNothing()
                .doThrow(new PersistenceException("uq_scan_job_active_per_url"))
                .when(em).flush();

        assertThatThrownBy(() -> service.createJobInTx(em, RAW_URL, null, ScanDepth.QUICK))
                .isInstanceOf(ConflictException.class)
                .hasMessageContaining("active scan");
    }

    @Test
    @DisplayName("supersedes active jobs before inserting the new one")
    void supersedesActiveJobsBeforeInsert() {
        ScannedUrl existing = urlWithId(UUID.randomUUID());
        stubSelectByHash(existing);
        when(em.find(eq(ScannedUrl.class), any(), any(LockModeType.class))).thenReturn(existing);

        ScanJob active = new ScanJob();
        active.setStatus(ScanJobStatus.PENDING);
        stubSupersedeSelect(List.of(active));

        service.createJobInTx(em, RAW_URL, null, ScanDepth.QUICK);

        assertThat(active.getStatus()).isEqualTo(ScanJobStatus.SUPERSEDED);
        verify(em).persist(any(ScanJob.class));
    }

    // ---- stubbing helpers -------------------------------------------------

    private ScannedUrl urlWithId(UUID id) {
        ScannedUrl url = mock(ScannedUrl.class);
        lenient().when(url.getId()).thenReturn(id);
        return url;
    }

    @SuppressWarnings("unchecked")
    private void stubSelectByHash(ScannedUrl result) {
        TypedQuery<ScannedUrl> q = mock(TypedQuery.class);
        lenient().when(em.createQuery(anyString(), eq(ScannedUrl.class))).thenReturn(q);
        lenient().when(q.setParameter(anyString(), any())).thenReturn(q);
        lenient().when(q.getResultStream()).thenReturn(Stream.of(result));
    }

    @SuppressWarnings("unchecked")
    private void stubSelectByHashSequence(ScannedUrl first, ScannedUrl second) {
        TypedQuery<ScannedUrl> q = mock(TypedQuery.class);
        lenient().when(em.createQuery(anyString(), eq(ScannedUrl.class))).thenReturn(q);
        lenient().when(q.setParameter(anyString(), any())).thenReturn(q);
        lenient().when(q.getResultStream())
                .thenReturn(first == null ? Stream.empty() : Stream.of(first))
                .thenReturn(second == null ? Stream.empty() : Stream.of(second));
    }

    @SuppressWarnings("unchecked")
    private void stubSupersedeSelectEmpty() {
        stubSupersedeSelect(List.of());
    }

    @SuppressWarnings("unchecked")
    private void stubSupersedeSelect(List<ScanJob> active) {
        TypedQuery<ScanJob> q = mock(TypedQuery.class);
        lenient().when(em.createQuery(anyString(), eq(ScanJob.class))).thenReturn(q);
        lenient().when(q.setParameter(anyString(), any())).thenReturn(q);
        lenient().when(q.getResultList()).thenReturn(active);
    }
}
