package com.secbret.ai.ml;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A {@link Clock} whose current time can be advanced deterministically by tests.
 * Using this instead of {@code Thread.sleep} makes circuit-breaker time-advancement
 * tests fast and deterministic.
 *
 * <p>The underlying counter is an {@link AtomicLong} so concurrent tests can
 * advance time without data races.
 */
public final class MutableClock extends Clock {

    private final AtomicLong epochMillis;
    private final ZoneId     zone;

    public MutableClock(long startEpochMs) {
        this.epochMillis = new AtomicLong(startEpochMs);
        this.zone        = ZoneId.of("UTC");
    }

    /** Advance the clock by {@code deltaMs} milliseconds and return new millis. */
    public long advance(long deltaMs) {
        return epochMillis.addAndGet(deltaMs);
    }

    /** Set the clock to an absolute epoch-ms value. */
    public void setTo(long epochMs) {
        epochMillis.set(epochMs);
    }

    @Override
    public ZoneId getZone() {
        return zone;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        throw new UnsupportedOperationException("MutableClock does not support withZone");
    }

    @Override
    public Instant instant() {
        return Instant.ofEpochMilli(epochMillis.get());
    }
}
