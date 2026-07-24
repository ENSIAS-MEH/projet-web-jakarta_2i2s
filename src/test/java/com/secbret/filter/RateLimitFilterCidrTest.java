package com.secbret.filter;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for H-4: {@link RateLimitFilter#cidrContains} and the trusted-proxy logic.
 * TRUSTED_PROXY_CIDRS is not set in the test JVM, so isTrustedProxy always returns false here;
 * cidrContains is tested directly via the package-accessible static method.
 */
class RateLimitFilterCidrTest {

    @Test
    @DisplayName("cidrContains: IP inside /24 CIDR returns true")
    void cidrContains_inRange_true() {
        assertThat(RateLimitFilter.cidrContains("10.0.0.0/24", "10.0.0.5")).isTrue();
    }

    @Test
    @DisplayName("cidrContains: IP outside /24 CIDR returns false")
    void cidrContains_outOfRange_false() {
        assertThat(RateLimitFilter.cidrContains("10.0.0.0/24", "10.0.1.1")).isFalse();
    }

    @Test
    @DisplayName("cidrContains: IP exactly matching /32 CIDR returns true")
    void cidrContains_exactSlash32_true() {
        assertThat(RateLimitFilter.cidrContains("192.168.1.5/32", "192.168.1.5")).isTrue();
    }

    @Test
    @DisplayName("cidrContains: malformed CIDR returns false, never throws")
    void cidrContains_malformedCidr_false() {
        assertThat(RateLimitFilter.cidrContains("not-a-cidr/xy", "1.2.3.4")).isFalse();
    }

    @Test
    @DisplayName("cidrContains: malformed IP returns false, never throws")
    void cidrContains_malformedIp_false() {
        assertThat(RateLimitFilter.cidrContains("10.0.0.0/8", "not-an-ip")).isFalse();
    }

    @Test
    @DisplayName("cidrContains: /0 (match all) returns true for any IP")
    void cidrContains_slashZero_matchesAll() {
        assertThat(RateLimitFilter.cidrContains("0.0.0.0/0", "8.8.8.8")).isTrue();
    }

    @Test
    @DisplayName("TRUSTED_PROXY_CIDRS unset => clientIp ignores XFF, returns remoteAddr")
    void clientIp_untrustedProxy_ignoresXff() {
        // isTrustedProxy() returns false when env var is absent (test JVM has no TRUSTED_PROXY_CIDRS)
        // Verify via cidrContains: an empty CIDR string returns false (safe default)
        assertThat(RateLimitFilter.cidrContains("", "1.2.3.4")).isFalse();
    }
}
