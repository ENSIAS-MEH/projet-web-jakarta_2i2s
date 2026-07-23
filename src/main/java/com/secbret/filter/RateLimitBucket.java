package com.secbret.filter;

/**
 * Token-bucket state for one rate-limit key.
 *
 * <p>All fields are plain primitives — mutation happens exclusively inside
 * {@link RateLimiter#tryConsume}, which wraps every access in
 * {@code ConcurrentHashMap.compute} so the entire read-modify-write is atomic.
 *
 * <p>Stampede protection (Part II §5): on the first request of a new window the
 * bucket is pre-filled to {@code capacity * 0.30} tokens rather than {@code capacity},
 * bounding the burst that can be consumed immediately after a restart or quiet period.
 *
 * ponytail: floating-point tokens — negligible drift at these scales; switch to
 * long-milligrams if sub-token granularity becomes relevant.
 */
public final class RateLimitBucket {

    public static final double STAMPEDE_THRESHOLD = 0.30;

    final double capacity;
    final long   windowMillis;

    double tokens;      // current available tokens
    long   lastRefill;  // epoch-millis of last window start

    RateLimitBucket(double capacity, long windowMillis, long nowMillis) {
        this.capacity     = capacity;
        this.windowMillis = windowMillis;
        // Stampede protection: start at 30 % of capacity, not 100 %.
        this.tokens       = capacity * STAMPEDE_THRESHOLD;
        this.lastRefill   = nowMillis;
    }

    /**
     * Copy constructor used by the eviction sweep to snapshot current state
     * without holding the compute lock.
     */
    RateLimitBucket(RateLimitBucket src) {
        this.capacity     = src.capacity;
        this.windowMillis = src.windowMillis;
        this.tokens       = src.tokens;
        this.lastRefill   = src.lastRefill;
    }

    /** Returns true if this bucket's last-refill time is older than one window. */
    boolean isExpired(long nowMillis) {
        return nowMillis - lastRefill > windowMillis;
    }
}
