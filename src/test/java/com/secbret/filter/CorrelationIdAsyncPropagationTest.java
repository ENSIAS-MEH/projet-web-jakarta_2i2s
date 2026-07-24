package com.secbret.filter;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Proves the async correlation-ID propagation pattern (Part II §9.5).
 *
 * <p>The CDI {@code @RequestScoped} {@link CorrelationContext} is not accessible on
 * a {@code ManagedExecutorService} worker thread. The fix: capture the ID string
 * BEFORE the async hop and set it in MDC on the worker thread.
 *
 * <p>This test verifies that pattern works correctly and that without it, MDC
 * would be empty on the worker thread.
 */
class CorrelationIdAsyncPropagationTest {

    private static final String MDC_KEY = CorrelationIdFilter.MDC_KEY;

    @Test
    @DisplayName("MDC correlationId is propagated to async worker when captured before hop")
    void capturedCidPropagatedToWorker() throws Exception {
        // Simulate the request-thread setting MDC (as CorrelationIdFilter does)
        String cid = UUID.randomUUID().toString();
        MDC.put(MDC_KEY, cid);

        AtomicReference<String> workerMdcValue = new AtomicReference<>();

        // Pattern: capture the cid string, then set on worker thread
        final String capturedCid = MDC.get(MDC_KEY);
        CompletableFuture.runAsync(() -> {
            if (capturedCid != null && !capturedCid.isEmpty()) {
                MDC.put(MDC_KEY, capturedCid);
            }
            try {
                workerMdcValue.set(MDC.get(MDC_KEY));
            } finally {
                MDC.remove(MDC_KEY);
            }
        }, Executors.newSingleThreadExecutor()).get(5, TimeUnit.SECONDS);

        MDC.remove(MDC_KEY); // clean up request thread

        assertThat(workerMdcValue.get())
                .as("correlationId must be set in MDC on the worker thread")
                .isEqualTo(cid);
    }

    @Test
    @DisplayName("without propagation, MDC correlationId is absent on worker thread")
    void withoutPropagation_mdcEmptyOnWorker() throws Exception {
        String cid = UUID.randomUUID().toString();
        MDC.put(MDC_KEY, cid);

        AtomicReference<String> workerMdcValue = new AtomicReference<>("SENTINEL");

        // No capture — worker thread has no MDC value
        CompletableFuture.runAsync(() -> {
            workerMdcValue.set(MDC.get(MDC_KEY));
        }, Executors.newSingleThreadExecutor()).get(5, TimeUnit.SECONDS);

        MDC.remove(MDC_KEY);

        // MDC is thread-local: the worker thread has no correlationId unless explicitly set
        assertThat(workerMdcValue.get())
                .as("without propagation, MDC is null on a fresh worker thread")
                .isNull();
    }

    @Test
    @DisplayName("ScanExecutor/IncidentService pattern: cid set on worker, cleared on finally")
    void cidClearedFromWorkerAfterCompletion() throws Exception {
        String cid = UUID.randomUUID().toString();
        AtomicReference<String> duringWork = new AtomicReference<>();
        AtomicReference<String> afterWork = new AtomicReference<>("SENTINEL");

        CompletableFuture.runAsync(() -> {
            MDC.put(MDC_KEY, cid);
            try {
                duringWork.set(MDC.get(MDC_KEY));
            } finally {
                MDC.remove(MDC_KEY);
                afterWork.set(MDC.get(MDC_KEY));
            }
        }, Executors.newSingleThreadExecutor()).get(5, TimeUnit.SECONDS);

        assertThat(duringWork.get()).isEqualTo(cid);
        assertThat(afterWork.get())
                .as("MDC must be cleared in finally block to avoid thread-pool leakage")
                .isNull();
    }
}
