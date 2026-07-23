package com.secbret.filter;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.Resource;
import jakarta.ejb.Singleton;
import jakarta.ejb.Startup;
import jakarta.ejb.Timeout;
import jakarta.ejb.Timer;
import jakarta.ejb.TimerConfig;
import jakarta.ejb.TimerService;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * EJB timer that sweeps expired entries from the rate-limit map.
 *
 * <p>Runs at startup and every {@code window × 2} thereafter (using the default
 * window — 1 minute — so the sweep fires every 2 minutes). This bounds the map
 * to the set of recently active callers and prevents unbounded growth.
 *
 * <p><strong>Decision #21:</strong> this is its own independent {@code @Singleton}
 * {@code TimerService} bean, deliberately separate from the 24h maintenance batch
 * timer that Task 23 will add. Do NOT merge them.
 *
 * ponytail: uses the default (shortest) window (1 minute × 2 = 2 min sweep interval)
 * — all bucket types are evictable at this cadence since eviction is by lastRefill age,
 * not by window duration.
 */
@Singleton
@Startup
@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
public class RateLimitEvictionTimer {

    private static final Logger log = LoggerFactory.getLogger(RateLimitEvictionTimer.class);

    // Sweep every 2 × the shortest window (1-minute default window → 2 minutes).
    // This is long enough to avoid busy sweeping, short enough to bound map growth.
    private static final long SWEEP_INTERVAL_MS = RateLimitFilter.WINDOW_MINUTE * 2;

    @Resource
    TimerService timerService;

    @PostConstruct
    public void start() {
        // Initial sweep at startup to clear any map state from a previous deployment
        // (unlikely in single-JVM but safe).
        sweep();
        timerService.createIntervalTimer(
                SWEEP_INTERVAL_MS,
                SWEEP_INTERVAL_MS,
                new TimerConfig("rate-limit-eviction", false));
        log.info("RateLimitEvictionTimer started; sweep interval={}ms", SWEEP_INTERVAL_MS);
    }

    @Timeout
    public void onTimeout(Timer timer) {
        sweep();
    }

    private void sweep() {
        long before = RateLimitFilter.LIMITER.bucketCount();
        RateLimitFilter.LIMITER.evictExpired(System.currentTimeMillis());
        long after = RateLimitFilter.LIMITER.bucketCount();
        if (before > 0 || after > 0) {
            log.debug("Rate-limit eviction sweep: {} → {} buckets", before, after);
        }
    }
}
