package com.secbret.ai.ml;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import java.time.Clock;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import java.util.logging.Logger;

/**
 * Circuit breaker for the ML sidecar gRPC client (Part II §7 "Circuit Breaker (ML
 * Sidecar)" and §15 normative state machine).
 *
 * <h2>State machine</h2>
 * <pre>
 * CLOSED ──(≥ ML_CB_FAILURE_THRESHOLD failures in ML_CB_WINDOW_MS)──► OPEN
 *                                                                         │
 *                                                     (ML_CB_OPEN_MS passes)
 *                                                                         │
 *                                                                    HALF_OPEN
 *                                                                         │
 *                                         (one thread wins CAS → HALF_OPEN_PROBING)
 *                                                            ┌──────────┘
 *                                                            ▼ probe result
 *                                              success ──► CLOSED (reset count)
 *                                              failure ──► OPEN   (restart timer)
 * </pre>
 *
 * <h2>Env-var config (Part II §6 "Additional Environment Variables")</h2>
 * <ul>
 *   <li>{@code ML_CB_FAILURE_THRESHOLD} — failures before OPEN (default 5)</li>
 *   <li>{@code ML_CB_WINDOW_MS}         — failure-counting window (default 60 000 ms)</li>
 *   <li>{@code ML_CB_OPEN_MS}           — OPEN state duration before HALF_OPEN (default 30 000 ms)</li>
 * </ul>
 *
 * <h2>Thread safety (B6)</h2>
 * State is held in a single {@link AtomicReference}. The OPEN→HALF_OPEN transition is
 * observed by all threads when the cooldown elapses; only the one thread that wins
 * {@code compareAndSet(HALF_OPEN, HALF_OPEN_PROBING)} gets to send the probe. All
 * others take the rules-only fallback (return empty) while the probe is in flight.
 *
 * <h2>Clock injection</h2>
 * The constructor accepts a {@link Clock} so tests can advance time deterministically
 * without {@code Thread.sleep}. The CDI no-arg constructor uses {@link Clock#systemUTC()}.
 * Complexity: {@code O(f)} per call where {@code f ≤ ML_CB_FAILURE_THRESHOLD} (window
 * scan); {@code Θ(1)} amortized over a long run (entries evicted on every call).
 */
@ApplicationScoped
public class MlCircuitBreaker {

    private static final Logger LOG = Logger.getLogger(MlCircuitBreaker.class.getName());

    // ── env-var names ──────────────────────────────────────────────────────────
    private static final String ENV_FAILURE_THRESHOLD = "ML_CB_FAILURE_THRESHOLD";
    private static final String ENV_WINDOW_MS         = "ML_CB_WINDOW_MS";
    private static final String ENV_OPEN_MS           = "ML_CB_OPEN_MS";

    // ── spec defaults ──────────────────────────────────────────────────────────
    static final int    DEFAULT_FAILURE_THRESHOLD = 5;
    static final long   DEFAULT_WINDOW_MS         = 60_000L;
    static final long   DEFAULT_OPEN_MS           = 30_000L;

    /**
     * Internal states. {@code HALF_OPEN_PROBING} is not visible outside this class
     * — callers observe only CLOSED / OPEN / HALF_OPEN via {@link #currentState()}.
     */
    enum InternalState {
        CLOSED,
        OPEN,
        HALF_OPEN,
        HALF_OPEN_PROBING   // exactly one thread holds the probe token
    }

    /** Externally visible state (exposed for testing / health checks). */
    public enum State { CLOSED, OPEN, HALF_OPEN }

    // ── config (final after @PostConstruct) ────────────────────────────────────
    private final int  failureThreshold;
    private final long windowMs;
    private final long openMs;

    // ── time source (swappable for tests) ─────────────────────────────────────
    private final Clock clock;

    // ── mutable state (all access is either under `this` lock or via CAS) ─────
    private final AtomicReference<InternalState> state =
            new AtomicReference<>(InternalState.CLOSED);

    /**
     * Timestamps (millis) of failures that are still inside the counting window.
     * Access is guarded by {@code synchronized(failureTimes)}.
     */
    private final Deque<Long> failureTimes = new ArrayDeque<>();

    /**
     * The wall-clock time at which the breaker entered OPEN, used to compute when
     * the ML_CB_OPEN_MS cooldown expires. Guarded by {@code synchronized(failureTimes)}.
     */
    private volatile long openedAtMs = 0L;

    // ── CDI lifecycle ──────────────────────────────────────────────────────────

    /** CDI no-arg constructor — uses system UTC clock and env-var config. */
    public MlCircuitBreaker() {
        this(Clock.systemUTC(),
                resolveInt(ENV_FAILURE_THRESHOLD, DEFAULT_FAILURE_THRESHOLD),
                resolveLong(ENV_WINDOW_MS,        DEFAULT_WINDOW_MS),
                resolveLong(ENV_OPEN_MS,          DEFAULT_OPEN_MS));
    }

    /**
     * Test / deterministic constructor with an injectable clock.
     *
     * @param clock            time source; use a {@link java.time.Clock#fixed fixed clock}
     *                         or a mutable wrapper to advance time in tests
     * @param failureThreshold failures before OPEN
     * @param windowMs         failure-counting window duration in ms
     * @param openMs           OPEN state duration before HALF_OPEN in ms
     */
    public MlCircuitBreaker(Clock clock, int failureThreshold, long windowMs, long openMs) {
        if (clock == null) {
            throw new IllegalArgumentException("clock must not be null");
        }
        if (failureThreshold < 1) {
            throw new IllegalArgumentException("failureThreshold must be >= 1, got " + failureThreshold);
        }
        if (windowMs <= 0) {
            throw new IllegalArgumentException("windowMs must be > 0, got " + windowMs);
        }
        if (openMs <= 0) {
            throw new IllegalArgumentException("openMs must be > 0, got " + openMs);
        }
        this.clock            = clock;
        this.failureThreshold = failureThreshold;
        this.windowMs         = windowMs;
        this.openMs           = openMs;
    }

    @PostConstruct
    void init() {
        LOG.info(String.format(
                "MlCircuitBreaker initialised: failureThreshold=%d window=%dms open=%dms",
                failureThreshold, windowMs, openMs));
    }

    // ── public API ─────────────────────────────────────────────────────────────

    /**
     * Execute {@code delegate} through the circuit breaker.
     *
     * <p>When the breaker is CLOSED it calls the delegate and records success or failure.
     * When OPEN it short-circuits and returns {@link Optional#empty()} immediately.
     * When HALF_OPEN it allows exactly one probe via CAS; all concurrent threads
     * get empty while the probe is in flight.
     *
     * @param delegate the ML call; must not be null; may throw to signal failure
     * @param <T>      the result type
     * @return the delegate result, or empty when the breaker short-circuits
     * @throws NullPointerException if delegate is null
     */
    public <T> Optional<T> execute(Supplier<Optional<T>> delegate) {
        if (delegate == null) {
            throw new NullPointerException("delegate must not be null");
        }
        long nowMs = clock.millis();

        // Fast-path: check OPEN / cooldown-elapsed atomically.
        InternalState s = state.get();
        if (s == InternalState.OPEN) {
            if (!cooldownElapsed(nowMs)) {
                return Optional.empty(); // still OPEN — short-circuit
            }
            // Cooldown has elapsed: exactly one thread may claim the HALF_OPEN state.
            // B6: use CAS so only the winning thread attempts to probe; all other
            // threads that observe OPEN+cooldownElapsed simultaneously must return empty.
            if (!state.compareAndSet(InternalState.OPEN, InternalState.HALF_OPEN_PROBING)) {
                // Another thread already moved the state (to HALF_OPEN_PROBING or
                // back to CLOSED/OPEN via probe resolution). Return empty.
                return Optional.empty();
            }
            // This thread won the OPEN→HALF_OPEN_PROBING CAS: run the probe.
            return runProbe(delegate, nowMs);
        }

        if (s == InternalState.HALF_OPEN || s == InternalState.HALF_OPEN_PROBING) {
            // A probe is already in flight (or has just been claimed). All threads
            // that see either HALF_OPEN state take the rules-only fallback.
            return Optional.empty();
        }

        // CLOSED — normal path.
        return runClosed(delegate, nowMs);
    }

    /** The externally-visible state (collapses HALF_OPEN_PROBING → HALF_OPEN). */
    public State currentState() {
        return switch (state.get()) {
            case CLOSED            -> State.CLOSED;
            case OPEN              -> State.OPEN;
            case HALF_OPEN,
                 HALF_OPEN_PROBING -> State.HALF_OPEN;
        };
    }

    // ── internal helpers ───────────────────────────────────────────────────────

    /** Run the delegate in CLOSED state. */
    private <T> Optional<T> runClosed(Supplier<Optional<T>> delegate, long nowMs) {
        try {
            Optional<T> result = delegate.get();
            // A successful call when CLOSED resets accumulated failures (optional
            // but avoids carrying stale entries to the next window).
            // We do NOT reset on closed success — the window-expiry already handles it.
            return result;
        } catch (Exception ex) {
            recordFailure(nowMs);
            return Optional.empty();
        }
    }

    /** Run the single probe in HALF_OPEN_PROBING state, then transition. */
    private <T> Optional<T> runProbe(Supplier<Optional<T>> delegate, long nowMs) {
        try {
            Optional<T> result = delegate.get();
            // Probe succeeded → back to CLOSED.
            transitionToClosed();
            LOG.info("MlCircuitBreaker probe SUCCESS → CLOSED");
            return result;
        } catch (Exception ex) {
            // Probe failed → re-open with fresh cooldown.
            transitionToOpen(nowMs);
            LOG.warning("MlCircuitBreaker probe FAILURE → OPEN (restart 30s timer)");
            return Optional.empty();
        }
    }

    /**
     * Record a failure timestamp and open the breaker if the threshold is reached
     * within the counting window.
     */
    private void recordFailure(long nowMs) {
        synchronized (failureTimes) {
            failureTimes.addLast(nowMs);
            evictExpired(nowMs);
            if (failureTimes.size() >= failureThreshold) {
                transitionToOpenLocked(nowMs);
            }
        }
    }

    /**
     * Evict failure timestamps that have fallen outside the counting window.
     * Must be called under {@code synchronized(failureTimes)}.
     */
    private void evictExpired(long nowMs) {
        long cutoff = nowMs - windowMs;
        while (!failureTimes.isEmpty() && failureTimes.peekFirst() <= cutoff) {
            failureTimes.pollFirst();
        }
    }

    private boolean cooldownElapsed(long nowMs) {
        return nowMs - openedAtMs >= openMs;
    }

    /**
     * Transition to OPEN and record the open timestamp. May be called from either
     * the failure-recording path (under {@code synchronized(failureTimes)}) or from
     * the probe-failure path (not under the lock — uses a separate {@code openedAtMs}
     * volatile write which is safe: only one thread can be probing at a time).
     */
    private void transitionToOpenLocked(long nowMs) {
        openedAtMs = nowMs;
        state.set(InternalState.OPEN);
        LOG.warning(String.format(
                "MlCircuitBreaker OPEN after %d failures in %dms window",
                failureThreshold, windowMs));
    }

    private void transitionToOpen(long nowMs) {
        synchronized (failureTimes) {
            failureTimes.clear();
            transitionToOpenLocked(nowMs);
        }
    }

    private void transitionToClosed() {
        synchronized (failureTimes) {
            failureTimes.clear();
        }
        openedAtMs = 0L;
        state.set(InternalState.CLOSED);
    }

    // ── env-var helpers ────────────────────────────────────────────────────────

    private static int resolveInt(String name, int defaultValue) {
        String raw = System.getenv(name);
        if (raw == null || raw.isBlank()) {
            return defaultValue;
        }
        try {
            int v = Integer.parseInt(raw.trim());
            return v > 0 ? v : defaultValue;
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private static long resolveLong(String name, long defaultValue) {
        String raw = System.getenv(name);
        if (raw == null || raw.isBlank()) {
            return defaultValue;
        }
        try {
            long v = Long.parseLong(raw.trim());
            return v > 0 ? v : defaultValue;
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    // ── accessors for testing ──────────────────────────────────────────────────

    /** Failure threshold — exposed for white-box tests. */
    int failureThreshold() {
        return failureThreshold;
    }

    /** Window duration in ms — exposed for white-box tests. */
    long windowMs() {
        return windowMs;
    }

    /** OPEN duration in ms — exposed for white-box tests. */
    long openMs() {
        return openMs;
    }

    /**
     * Current failure-queue size inside the window — exposed for white-box tests.
     * The count may include an entry recorded in the same ms, so callers should
     * compare with {@link #failureThreshold()}.
     */
    int windowFailureCount(long nowMs) {
        synchronized (failureTimes) {
            evictExpired(nowMs);
            return failureTimes.size();
        }
    }
}
