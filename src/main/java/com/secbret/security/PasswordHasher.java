package com.secbret.security;

import jakarta.enterprise.context.ApplicationScoped;
import org.mindrot.jbcrypt.BCrypt;

/**
 * BCrypt password hashing utility (spec §B: BCrypt cost factor 12; plaintext
 * never stored). Wraps jBCrypt behind a CDI bean so the cost factor is centrally
 * configured and the {@link SecBretIdentityStore} / {@code UserService} depend on
 * an injectable abstraction rather than a static call.
 *
 * <p>The cost factor is read once from the {@code BCRYPT_COST} environment
 * variable (default 12). BCrypt work is O(2^cost) — cost 12 is ~250 ms per hash
 * on commodity hardware, the spec's chosen balance of resistance vs. latency.
 */
@ApplicationScoped
public class PasswordHasher {

    private static final int DEFAULT_COST = 12;
    private static final int MIN_COST = 4;   // BCrypt lower bound
    private static final int MAX_COST = 31;  // BCrypt upper bound

    private final int cost;

    public PasswordHasher() {
        this.cost = resolveCost();
    }

    /** Test/DI constructor allowing an explicit cost. */
    public PasswordHasher(int cost) {
        if (cost < MIN_COST || cost > MAX_COST) {
            throw new IllegalArgumentException("BCrypt cost must be in [" + MIN_COST + ", " + MAX_COST + "]");
        }
        this.cost = cost;
    }

    /** @return a salted BCrypt hash of {@code rawPassword} at the configured cost. */
    public String hash(String rawPassword) {
        if (rawPassword == null) {
            throw new IllegalArgumentException("rawPassword must not be null");
        }
        return BCrypt.hashpw(rawPassword, BCrypt.gensalt(cost));
    }

    /**
     * Constant-time-ish verification (BCrypt.checkpw compares the recomputed
     * hash). Returns false for a null/blank stored hash rather than throwing, so
     * a malformed record cannot authenticate but also cannot crash the login path.
     */
    public boolean verify(String rawPassword, String storedHash) {
        if (rawPassword == null || storedHash == null || storedHash.isBlank()) {
            return false;
        }
        try {
            return BCrypt.checkpw(rawPassword, storedHash);
        } catch (IllegalArgumentException malformedHash) {
            // storedHash is not a valid BCrypt string — treat as non-matching.
            return false;
        }
    }

    public int cost() {
        return cost;
    }

    private static int resolveCost() {
        String raw = System.getenv("BCRYPT_COST");
        if (raw == null || raw.isBlank()) {
            return DEFAULT_COST;
        }
        try {
            int parsed = Integer.parseInt(raw.trim());
            if (parsed < MIN_COST || parsed > MAX_COST) {
                return DEFAULT_COST;
            }
            return parsed;
        } catch (NumberFormatException notANumber) {
            return DEFAULT_COST;
        }
    }
}
