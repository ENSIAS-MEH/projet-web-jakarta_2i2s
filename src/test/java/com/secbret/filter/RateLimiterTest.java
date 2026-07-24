package com.secbret.filter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link RateLimiter} and {@link RateLimitBucket}.
 *
 * Covers: keying isolation, window expiry, stampede jitter bounds, 429 emission logic.
 * All tests use an injectable {@code nowMillis} — no wall-clock dependency.
 */
class RateLimiterTest {

    private RateLimiter limiter;
    private static final long T0 = 1_000_000_000L; // arbitrary epoch base
    private static final long WINDOW = 60_000L;     // 1-minute window
    private static final int  CAPACITY = 10;

    @BeforeEach
    void setUp() {
        limiter = new RateLimiter();
    }

    // ---------------------------------------------------------------- stampede protection

    @Nested
    @DisplayName("Stampede protection (30 % pre-fill)")
    class StampedeProtection {

        @Test
        @DisplayName("first request of a new window is allowed (30 % of capacity = 3 tokens available)")
        void firstRequest_allowed() {
            var result = limiter.tryConsume("key", CAPACITY, WINDOW, T0);
            assertThat(result.allowed).isTrue();
        }

        @Test
        @DisplayName("only capacity×0.30 tokens available at window start — 4th request is rejected")
        void stampede_fourthRequest_rejected() {
            // 30 % of 10 = 3.0 → consume 3 should succeed, 4th should fail
            limiter.tryConsume("key", CAPACITY, WINDOW, T0);
            limiter.tryConsume("key", CAPACITY, WINDOW, T0);
            limiter.tryConsume("key", CAPACITY, WINDOW, T0);
            var fourth = limiter.tryConsume("key", CAPACITY, WINDOW, T0);
            assertThat(fourth.allowed).isFalse();
        }

        @Test
        @DisplayName("stampede threshold is exactly 30 % — remaining after first is capacity×0.30 − 1")
        void stampede_remaining_boundsExact() {
            // capacity=10 → initial tokens=3.0 → after consuming 1, remaining=2
            var r = limiter.tryConsume("key", CAPACITY, WINDOW, T0);
            assertThat(r.remaining).isEqualTo(2L);
        }
    }

    // ---------------------------------------------------------------- keying isolation

    @Nested
    @DisplayName("Keying matrix — bucket isolation")
    class KeyingIsolation {

        @Test
        @DisplayName("different keys have independent buckets")
        void differentKeys_independent() {
            // Exhaust user-A's bucket
            for (int i = 0; i < (int)(CAPACITY * RateLimitBucket.STAMPEDE_THRESHOLD); i++) {
                limiter.tryConsume("user:A", CAPACITY, WINDOW, T0);
            }
            // User-B is unaffected
            var resultB = limiter.tryConsume("user:B", CAPACITY, WINDOW, T0);
            assertThat(resultB.allowed).isTrue();
        }

        @Test
        @DisplayName("same key accumulates consumption across calls")
        void sameKey_accumulatesConsumption() {
            // Fill all stampede-protected slots
            for (int i = 0; i < (int)(CAPACITY * RateLimitBucket.STAMPEDE_THRESHOLD); i++) {
                assertThat(limiter.tryConsume("key", CAPACITY, WINDOW, T0).allowed).isTrue();
            }
            // Next one must be rejected
            assertThat(limiter.tryConsume("key", CAPACITY, WINDOW, T0).allowed).isFalse();
        }
    }

    // ---------------------------------------------------------------- window expiry

    @Nested
    @DisplayName("Window expiry")
    class WindowExpiry {

        @Test
        @DisplayName("after window elapses, bucket resets and request is allowed again")
        void windowExpiry_resetsTokens() {
            // Exhaust the bucket
            for (int i = 0; i < (int)(CAPACITY * RateLimitBucket.STAMPEDE_THRESHOLD); i++) {
                limiter.tryConsume("key", CAPACITY, WINDOW, T0);
            }
            assertThat(limiter.tryConsume("key", CAPACITY, WINDOW, T0).allowed).isFalse();

            // Advance time past one full window
            long T1 = T0 + WINDOW + 1;
            var result = limiter.tryConsume("key", CAPACITY, WINDOW, T1);
            assertThat(result.allowed).isTrue();
        }

        @Test
        @DisplayName("bucket just before window end is still exhausted")
        void windowExpiry_beforeEnd_stillExhausted() {
            // Exhaust
            for (int i = 0; i < (int)(CAPACITY * RateLimitBucket.STAMPEDE_THRESHOLD); i++) {
                limiter.tryConsume("key", CAPACITY, WINDOW, T0);
            }
            // One millisecond before window end
            long justBefore = T0 + WINDOW - 1;
            var result = limiter.tryConsume("key", CAPACITY, WINDOW, justBefore);
            assertThat(result.allowed).isFalse();
        }
    }

    // ---------------------------------------------------------------- response headers

    @Nested
    @DisplayName("ConsumeResult header values")
    class HeaderValues {

        @Test
        @DisplayName("X-RateLimit-Limit equals capacity")
        void result_limit_equalsCapacity() {
            var r = limiter.tryConsume("key", CAPACITY, WINDOW, T0);
            assertThat(r.limit).isEqualTo(CAPACITY);
        }

        @Test
        @DisplayName("X-RateLimit-Reset epoch is lastRefill + windowMillis")
        void result_resetEpoch_correct() {
            var r = limiter.tryConsume("key", CAPACITY, WINDOW, T0);
            assertThat(r.resetEpochMillis).isEqualTo(T0 + WINDOW);
        }

        @Test
        @DisplayName("retryAfterSeconds rounds up to nearest second")
        void retryAfterSeconds_roundsUp() {
            // Exhaust
            for (int i = 0; i < (int)(CAPACITY * RateLimitBucket.STAMPEDE_THRESHOLD); i++) {
                limiter.tryConsume("key", CAPACITY, WINDOW, T0);
            }
            var r = limiter.tryConsume("key", CAPACITY, WINDOW, T0);
            // Window resets at T0 + WINDOW; now is T0 → retryAfter = WINDOW/1000 seconds
            assertThat(r.retryAfterSeconds(T0)).isEqualTo(WINDOW / 1000);
        }
    }

    // ---------------------------------------------------------------- eviction

    @Nested
    @DisplayName("Bucket eviction")
    class Eviction {

        @Test
        @DisplayName("evictExpired removes idle buckets older than one window")
        void eviction_removesExpiredBuckets() {
            limiter.tryConsume("active",  CAPACITY, WINDOW, T0);
            limiter.tryConsume("expired", CAPACITY, WINDOW, T0);

            // Advance time so "expired" is stale but "active" has a fresh request.
            long T1 = T0 + WINDOW + 1;
            limiter.tryConsume("active", CAPACITY, WINDOW, T1); // refreshes active's lastRefill to T1

            // Now evict at T1 — expired bucket's lastRefill=T0, WINDOW elapsed → removed.
            limiter.evictExpired(T1);

            // bucketCount should be 1 (just "active")
            assertThat(limiter.bucketCount()).isEqualTo(1);
        }

        @Test
        @DisplayName("eviction does not remove buckets with a recent request")
        void eviction_keepsActiveBuckets() {
            limiter.tryConsume("key", CAPACITY, WINDOW, T0);
            limiter.evictExpired(T0 + WINDOW / 2); // only half window elapsed → not expired
            assertThat(limiter.bucketCount()).isEqualTo(1);
        }
    }
}
