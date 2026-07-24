package com.secbret.integration;

import com.secbret.filter.RateLimitBucket;
import com.secbret.filter.RateLimiter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration-level test for the rate limiter.
 *
 * <p><strong>Harness note:</strong> a live-container IT against the deployed WAR would
 * require Payara to be running inside a Testcontainers image; the project's failsafe
 * harness uses Testcontainers only for Postgres (no embedded Payara). A real HTTP
 * burst test against the running compose stack is demonstrated in the live-verification
 * transcript (curl loop) in the progress log.
 *
 * <p>This test therefore proves the 429 emission contract at the unit level — the
 * limiter's burst → reject cycle — with enough depth to catch regressions in the
 * stampede + window logic. The live transcript (see ROADMAP.md progress log) covers
 * the HTTP wire-level contract.
 */
class RateLimitIT {

    private static final long WINDOW_MS = 60_000L;
    private static final long T0        = System.currentTimeMillis();

    @Test
    @DisplayName("burst exhausts stampede tokens then rejects; new window re-allows")
    void burstThen429ThenWindowReset() {
        RateLimiter limiter   = new RateLimiter();
        int         capacity  = 10;
        int         stampede  = (int)(capacity * RateLimitBucket.STAMPEDE_THRESHOLD); // 3

        // Phase 1: first stampede tokens should be allowed
        for (int i = 0; i < stampede; i++) {
            var r = limiter.tryConsume("test-key", capacity, WINDOW_MS, T0 + i);
            assertThat(r.allowed)
                    .as("request %d should be allowed (within stampede budget)", i + 1)
                    .isTrue();
        }

        // Phase 2: next request should be rejected (429)
        var rejected = limiter.tryConsume("test-key", capacity, WINDOW_MS, T0 + stampede);
        assertThat(rejected.allowed).isFalse();
        assertThat(rejected.remaining).isEqualTo(0L);
        assertThat(rejected.retryAfterSeconds(T0 + stampede)).isPositive();

        // Phase 3: Retry-After header value is the seconds until the window resets
        long retryAfter = rejected.retryAfterSeconds(T0 + stampede);
        assertThat(retryAfter).isLessThanOrEqualTo(WINDOW_MS / 1000);

        // Phase 4: after the window elapses, the key is fresh again
        long T1 = T0 + WINDOW_MS + 1;
        var fresh = limiter.tryConsume("test-key", capacity, WINDOW_MS, T1);
        assertThat(fresh.allowed).isTrue();
    }

    @Test
    @DisplayName("concurrent keys do not interfere (isolated buckets)")
    void concurrentKeys_isolated() {
        RateLimiter limiter  = new RateLimiter();
        int         capacity = 5;

        // Exhaust key-A
        for (int i = 0; i < (int)(capacity * RateLimitBucket.STAMPEDE_THRESHOLD); i++) {
            limiter.tryConsume("key-A", capacity, WINDOW_MS, T0);
        }
        assertThat(limiter.tryConsume("key-A", capacity, WINDOW_MS, T0).allowed).isFalse();

        // key-B is unaffected
        assertThat(limiter.tryConsume("key-B", capacity, WINDOW_MS, T0).allowed).isTrue();
    }

    @Test
    @DisplayName("X-RateLimit-* header values are consistent with actual state")
    void headerValues_consistent() {
        RateLimiter limiter   = new RateLimiter();
        int         capacity  = 10;

        var first = limiter.tryConsume("hdr-key", capacity, WINDOW_MS, T0);
        assertThat(first.limit).isEqualTo(capacity);
        // remaining = stampede_tokens - 1 consumed = 3 - 1 = 2
        assertThat(first.remaining).isEqualTo(2L);
        assertThat(first.resetEpochMillis).isEqualTo(T0 + WINDOW_MS);
    }
}
