package com.secbret.filter;

import java.util.concurrent.ConcurrentHashMap;

/**
 * In-JVM token-bucket rate limiter backed by a {@link ConcurrentHashMap}.
 *
 * <p>All state lives in one map: {@code key → RateLimitBucket}. Every request calls
 * {@link #tryConsume}; the entire read-modify-write is atomic via
 * {@code ConcurrentHashMap.compute} so no external locking is needed.
 *
 * <p>Window expiry: if the elapsed time since {@code lastRefill} exceeds
 * {@code windowMillis} the bucket is treated as fresh (re-initialised with stampede
 * protection), preventing stale tokens from accumulating during quiet periods.
 *
 * <p>Eviction: idle entries are removed by {@link RateLimitEvictionTimer}. The map
 * size is therefore bounded to recently-active callers; it cannot grow without bound
 * during long-running deployments. (Part II §5)
 *
 * ponytail: global lock on ConcurrentHashMap.compute per-key — per-account locks if
 * throughput ever exceeds single-JVM capacity.
 */
public class RateLimiter {

    private final ConcurrentHashMap<String, RateLimitBucket> buckets = new ConcurrentHashMap<>();

    /**
     * Attempt to consume one token from the bucket identified by {@code key}.
     *
     * @param key          rate-limit key (user-id or client-IP + endpoint class)
     * @param capacity     maximum tokens per window
     * @param windowMillis duration of the rate-limit window in milliseconds
     * @param nowMillis    current epoch time in milliseconds (injectable for testing)
     * @return a snapshot of the bucket state after the attempt; {@link ConsumeResult#allowed}
     *         is {@code false} when the bucket is exhausted.
     */
    public ConsumeResult tryConsume(String key, double capacity, long windowMillis, long nowMillis) {
        ConsumeResult[] result = new ConsumeResult[1];

        buckets.compute(key, (k, existing) -> {
            RateLimitBucket bucket;

            if (existing == null || existing.isExpired(nowMillis)) {
                // New window: create a fresh bucket with stampede protection.
                bucket = new RateLimitBucket(capacity, windowMillis, nowMillis);
            } else {
                bucket = existing;
            }

            boolean allowed = bucket.tokens >= 1.0;
            if (allowed) {
                bucket.tokens -= 1.0;
            }

            long resetMillis = bucket.lastRefill + bucket.windowMillis;
            result[0] = new ConsumeResult(allowed, (long) Math.max(0, bucket.tokens),
                    (long) capacity, resetMillis);
            return bucket;
        });

        return result[0];
    }

    /**
     * Remove all entries whose last-refill timestamp is older than one window.
     * Called by {@link RateLimitEvictionTimer} at startup and every {@code window×2}.
     */
    public void evictExpired(long nowMillis) {
        buckets.entrySet().removeIf(e -> e.getValue().isExpired(nowMillis));
    }

    /** Exposed for tests only. */
    int bucketCount() {
        return buckets.size();
    }

    // -----------------------------------------------------------------------

    /** Immutable result of one {@link #tryConsume} call. */
    public static final class ConsumeResult {
        public final boolean allowed;
        public final long    remaining;  // tokens left after this request
        public final long    limit;      // window capacity
        public final long    resetEpochMillis; // when the current window expires

        ConsumeResult(boolean allowed, long remaining, long limit, long resetEpochMillis) {
            this.allowed          = allowed;
            this.remaining        = remaining;
            this.limit            = limit;
            this.resetEpochMillis = resetEpochMillis;
        }

        /** Seconds until the window resets (used for Retry-After header). */
        public long retryAfterSeconds(long nowMillis) {
            return Math.max(0, (resetEpochMillis - nowMillis + 999) / 1000);
        }
    }
}
