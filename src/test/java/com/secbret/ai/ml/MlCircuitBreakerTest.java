package com.secbret.ai.ml;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the §15 circuit-breaker state machine.
 *
 * <p>All time-dependent transitions use {@link MutableClock} — no Thread.sleep.
 * The breaker is constructed with a threshold of 3, window of 10 000 ms, and
 * open duration of 5 000 ms unless a test overrides these for a tighter scenario.
 */
@DisplayName("MlCircuitBreaker — §15 state machine")
class MlCircuitBreakerTest {

    // small config values to keep tests readable
    static final int  THRESHOLD  = 3;
    static final long WINDOW_MS  = 10_000L;
    static final long OPEN_MS    = 5_000L;

    MutableClock  clock;
    MlCircuitBreaker breaker;

    @BeforeEach
    void setUp() {
        clock   = new MutableClock(1_000_000L); // arbitrary start
        breaker = new MlCircuitBreaker(clock, THRESHOLD, WINDOW_MS, OPEN_MS);
    }

    // ── helpers ────────────────────────────────────────────────────────────────

    /** A delegate that succeeds by returning a String. */
    private static Supplier<Optional<String>> succeedWith(String value) {
        return () -> Optional.of(value);
    }

    /** A delegate that fails by throwing. */
    private static Supplier<Optional<String>> alwaysFail() {
        return () -> { throw new RuntimeException("sidecar error"); };
    }

    /** Fire N failures against the breaker. */
    private void fireFailures(int count) {
        for (int i = 0; i < count; i++) {
            breaker.execute(alwaysFail());
        }
    }

    // ── CLOSED baseline ────────────────────────────────────────────────────────

    @Nested
    @DisplayName("CLOSED state")
    class Closed {

        @Test
        @DisplayName("initial state is CLOSED")
        void initialIsClosed() {
            assertThat(breaker.currentState()).isEqualTo(MlCircuitBreaker.State.CLOSED);
        }

        @Test
        @DisplayName("success in CLOSED returns result")
        void closedSuccess() {
            Optional<String> r = breaker.execute(succeedWith("ok"));
            assertThat(r).contains("ok");
            assertThat(breaker.currentState()).isEqualTo(MlCircuitBreaker.State.CLOSED);
        }

        @Test
        @DisplayName("failures below threshold keep breaker CLOSED")
        void belowThreshold_staysClosed() {
            fireFailures(THRESHOLD - 1);
            assertThat(breaker.currentState()).isEqualTo(MlCircuitBreaker.State.CLOSED);
        }

        @Test
        @DisplayName("exactly threshold failures in window → OPEN")
        void atThreshold_opensBreaker() {
            fireFailures(THRESHOLD);
            assertThat(breaker.currentState()).isEqualTo(MlCircuitBreaker.State.OPEN);
        }

        @Test
        @DisplayName("failures returned as empty in CLOSED (no propagation)")
        void closedFailureReturnsEmpty() {
            Optional<String> r = breaker.execute(alwaysFail());
            assertThat(r).isEmpty();
        }
    }

    // ── Window expiry ──────────────────────────────────────────────────────────

    @Nested
    @DisplayName("failure window expiry resets count")
    class WindowExpiry {

        @Test
        @DisplayName("failures outside window do not count toward threshold")
        void expiredFailuresDontCount() {
            // Fire THRESHOLD-1 failures.
            fireFailures(THRESHOLD - 1);
            assertThat(breaker.currentState()).isEqualTo(MlCircuitBreaker.State.CLOSED);

            // Advance past the full window so all those failures expire.
            clock.advance(WINDOW_MS + 1);

            // One more failure — but the count restarted so we're still below threshold.
            fireFailures(1);
            assertThat(breaker.currentState()).isEqualTo(MlCircuitBreaker.State.CLOSED);
            assertThat(breaker.windowFailureCount(clock.millis())).isEqualTo(1);
        }

        @Test
        @DisplayName("failures split across window boundary: only recent ones count")
        void splitAcrossBoundary() {
            // 2 failures at t=0
            fireFailures(2);
            // Advance so those 2 fall outside the window
            clock.advance(WINDOW_MS + 1);
            // 2 more failures at t=window+1 — threshold=3, only 2 in window
            fireFailures(2);
            assertThat(breaker.currentState()).isEqualTo(MlCircuitBreaker.State.CLOSED);
            // One more tips it over
            fireFailures(1);
            assertThat(breaker.currentState()).isEqualTo(MlCircuitBreaker.State.OPEN);
        }
    }

    // ── OPEN state ─────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("OPEN state")
    class Open {

        @BeforeEach
        void openBreaker() {
            fireFailures(THRESHOLD);
            assertThat(breaker.currentState()).isEqualTo(MlCircuitBreaker.State.OPEN);
        }

        @Test
        @DisplayName("OPEN short-circuits without calling delegate")
        void openShortCircuits() {
            AtomicInteger calls = new AtomicInteger(0);
            Supplier<Optional<String>> spy = () -> { calls.incrementAndGet(); return Optional.of("x"); };

            Optional<String> r = breaker.execute(spy);

            assertThat(r).isEmpty();
            assertThat(calls.get()).isEqualTo(0); // delegate must NOT be called
        }

        @Test
        @DisplayName("OPEN stays OPEN while cooldown has not elapsed")
        void openBeforeCooldown() {
            clock.advance(OPEN_MS - 1);
            breaker.execute(succeedWith("nope")); // would succeed if called
            assertThat(breaker.currentState()).isEqualTo(MlCircuitBreaker.State.OPEN);
        }

        @Test
        @DisplayName("after OPEN_MS the next call transitions to HALF_OPEN")
        void openAfterCooldown_transitionsToHalfOpen() {
            clock.advance(OPEN_MS);
            // Execute a call: the breaker should allow it as the probe
            // (OPEN → HALF_OPEN → HALF_OPEN_PROBING → success → CLOSED)
            breaker.execute(succeedWith("probe"));
            assertThat(breaker.currentState()).isEqualTo(MlCircuitBreaker.State.CLOSED);
        }
    }

    // ── HALF_OPEN / probe transitions ──────────────────────────────────────────

    @Nested
    @DisplayName("HALF_OPEN probe semantics (B6)")
    class HalfOpen {

        /** Put breaker in OPEN then advance past cooldown (ready for probe). */
        @BeforeEach
        void openAndCoolDown() {
            fireFailures(THRESHOLD);
            clock.advance(OPEN_MS); // cooldown elapsed
        }

        @Test
        @DisplayName("successful probe → CLOSED, failure count reset")
        void successfulProbe_closes() {
            Optional<String> r = breaker.execute(succeedWith("ok"));
            assertThat(r).contains("ok");
            assertThat(breaker.currentState()).isEqualTo(MlCircuitBreaker.State.CLOSED);
        }

        @Test
        @DisplayName("failing probe → OPEN with restarted 30s timer")
        void failingProbe_reopens() {
            breaker.execute(alwaysFail()); // probe fails
            assertThat(breaker.currentState()).isEqualTo(MlCircuitBreaker.State.OPEN);

            // Should stay OPEN until another OPEN_MS elapses.
            clock.advance(OPEN_MS - 1);
            AtomicInteger calls2 = new AtomicInteger(0);
            breaker.execute(() -> { calls2.incrementAndGet(); return Optional.empty(); });
            assertThat(calls2.get()).isEqualTo(0); // still open, short-circuited
        }

        @Test
        @DisplayName("after a failed probe the new cooldown must fully expire before HALF_OPEN again")
        void failedProbe_coolingDownAgain() {
            breaker.execute(alwaysFail()); // first probe → OPEN
            // Advance exactly OPEN_MS and try a second probe
            clock.advance(OPEN_MS);
            Optional<String> r = breaker.execute(succeedWith("second"));
            assertThat(r).contains("second");
            assertThat(breaker.currentState()).isEqualTo(MlCircuitBreaker.State.CLOSED);
        }

        @Test
        @DisplayName("exactly ONE probe is admitted under 50 concurrent threads (B6 atomicity)")
        void exactlyOneProbe_underConcurrency() throws Exception {
            int threadCount = 50;
            AtomicInteger delegateCalls = new AtomicInteger(0);

            // Two latches:
            // 1. `start`   — releases all threads simultaneously so they race on the CAS.
            // 2. `probeHold` — holds the probe delegate until all threads have made their
            //    CAS decision. This prevents the probe from finishing and transitioning to
            //    CLOSED before the other 49 threads arrive (which would make them see CLOSED
            //    instead of HALF_OPEN_PROBING and call the delegate as a normal CLOSED call).
            CountDownLatch start     = new CountDownLatch(1);
            CountDownLatch probeHold = new CountDownLatch(1); // released after all threads submit

            Supplier<Optional<String>> probeSpy = () -> {
                delegateCalls.incrementAndGet();
                try {
                    // Hold the probe until the main thread releases it — by that point all
                    // 50 threads have made their execute() call and the CAS winner is blocking
                    // here; all others have already returned empty.
                    probeHold.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return Optional.of("probe-result");
            };

            ExecutorService pool = Executors.newFixedThreadPool(threadCount);
            List<Future<Optional<String>>> futures = new ArrayList<>(threadCount);
            for (int i = 0; i < threadCount; i++) {
                futures.add(pool.submit(() -> {
                    start.await();
                    return breaker.execute(probeSpy);
                }));
            }

            start.countDown(); // release all 50 threads simultaneously

            // Wait until the probe has been claimed (delegateCalls goes to 1) and
            // all other threads have returned (which they do immediately since they
            // get empty from the CAS-loss path). Give a generous timeout.
            long deadline = System.currentTimeMillis() + 5_000L;
            while (delegateCalls.get() == 0 && System.currentTimeMillis() < deadline) {
                Thread.yield();
            }
            // Allow a brief moment for all non-probe threads to finish their execute() call.
            Thread.sleep(50);

            // Now release the probe — it can finish and close the breaker.
            probeHold.countDown();
            pool.shutdown();

            // Collect results
            List<Optional<String>> results = new ArrayList<>(threadCount);
            for (Future<Optional<String>> f : futures) {
                results.add(f.get());
            }

            // Exactly one thread should have reached the delegate
            assertThat(delegateCalls.get())
                    .as("exactly one probe must reach the sidecar under 50 concurrent threads (B6)")
                    .isEqualTo(1);

            // Exactly one thread gets the probe result; the rest get empty
            long presentCount = results.stream().filter(Optional::isPresent).count();
            assertThat(presentCount)
                    .as("exactly one thread gets the probe result")
                    .isEqualTo(1);

            // Breaker should now be CLOSED (probe succeeded)
            assertThat(breaker.currentState()).isEqualTo(MlCircuitBreaker.State.CLOSED);
        }
    }

    // ── Config defaults ────────────────────────────────────────────────────────

    @Nested
    @DisplayName("spec default values")
    class Defaults {

        @Test
        @DisplayName("default constants match §6 env-var table")
        void specDefaults() {
            assertThat(MlCircuitBreaker.DEFAULT_FAILURE_THRESHOLD).isEqualTo(5);
            assertThat(MlCircuitBreaker.DEFAULT_WINDOW_MS).isEqualTo(60_000L);
            assertThat(MlCircuitBreaker.DEFAULT_OPEN_MS).isEqualTo(30_000L);
        }
    }
}
