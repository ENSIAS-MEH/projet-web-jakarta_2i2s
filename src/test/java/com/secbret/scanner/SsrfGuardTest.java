package com.secbret.scanner;

import com.secbret.exception.ValidationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.InetAddress;
import java.net.UnknownHostException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link SsrfGuard} — scheme allowlist (§B3 item 5) and
 * private-range deny-set (§B3 item 1).
 *
 * <p>Tests do NOT make real DNS calls; addresses are constructed directly via
 * {@link InetAddress#getByAddress(byte[])} for deterministic coverage of every
 * deny-set entry.
 */
@DisplayName("SsrfGuard")
class SsrfGuardTest {

    private SsrfGuard guard;

    @BeforeEach
    void setUp() {
        guard = new SsrfGuard();
    }

    // =========================================================================
    // §B3 item 5 — scheme allowlist
    // =========================================================================

    @Nested
    @DisplayName("scheme allowlist (§B3 item 5)")
    class SchemeAllowlist {

        @ParameterizedTest(name = "allowed: {0}")
        @ValueSource(strings = {"http", "https", "HTTP", "HTTPS"})
        @DisplayName("http and https (case-insensitive) are permitted")
        void allowsHttpAndHttps(String scheme) {
            // Must not throw
            guard.requireAllowedScheme(scheme);
        }

        @ParameterizedTest(name = "blocked: {0}")
        @ValueSource(strings = {"file", "ftp", "gopher", "dict", "ldap", "jar", "data", ""})
        @DisplayName("non-http/https schemes are rejected")
        void blocksOtherSchemes(String scheme) {
            assertThatThrownBy(() -> guard.requireAllowedScheme(scheme))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("not permitted");
        }

        @Test
        @DisplayName("null scheme is rejected")
        void blocksNullScheme() {
            assertThatThrownBy(() -> guard.requireAllowedScheme(null))
                    .isInstanceOf(ValidationException.class);
        }
    }

    // =========================================================================
    // §B3 item 1 — private-range deny-set (IPv4)
    // =========================================================================

    @Nested
    @DisplayName("IPv4 private-range deny-set (§B3 item 1)")
    class Ipv4DenySet {

        @Test
        @DisplayName("10.0.0.0/8 is blocked")
        void blocks_10_x_x_x() throws Exception {
            assertPrivate("10.0.0.1");
            assertPrivate("10.255.255.255");
            assertPrivate("10.1.2.3");
        }

        @Test
        @DisplayName("172.16.0.0/12 is blocked")
        void blocks_172_16_to_31() throws Exception {
            assertPrivate("172.16.0.1");
            assertPrivate("172.31.255.255");
            assertPrivate("172.20.5.6");
        }

        @Test
        @DisplayName("172.32.0.0 is outside 172.16.0.0/12 — should be allowed")
        void allows_172_32() throws Exception {
            assertPublic("172.32.0.1");
        }

        @Test
        @DisplayName("192.168.0.0/16 is blocked")
        void blocks_192_168() throws Exception {
            assertPrivate("192.168.0.1");
            assertPrivate("192.168.255.254");
        }

        @Test
        @DisplayName("127.0.0.0/8 (loopback) is blocked")
        void blocks_loopback() throws Exception {
            assertPrivate("127.0.0.1");
            assertPrivate("127.255.255.255");
        }

        @Test
        @DisplayName("169.254.0.0/16 (link-local / cloud metadata) is blocked")
        void blocks_link_local_including_metadata_endpoint() throws Exception {
            assertPrivate("169.254.169.254"); // AWS/GCP/Azure metadata
            assertPrivate("169.254.0.1");
            assertPrivate("169.254.255.255");
        }

        @Test
        @DisplayName("0.0.0.0/8 is blocked")
        void blocks_zero_net() throws Exception {
            assertPrivate("0.0.0.1");
            assertPrivate("0.255.255.255");
        }

        @Test
        @DisplayName("100.64.0.0/10 (CGNAT) is blocked")
        void blocks_cgnat() throws Exception {
            assertPrivate("100.64.0.1");
            assertPrivate("100.127.255.255");
        }

        @Test
        @DisplayName("100.128.0.0 is outside CGNAT range — should be allowed")
        void allows_100_128() throws Exception {
            assertPublic("100.128.0.1");
        }

        @Test
        @DisplayName("public IP addresses are allowed")
        void allows_public_addresses() throws Exception {
            assertPublic("8.8.8.8");
            assertPublic("1.1.1.1");
            assertPublic("93.184.216.34"); // example.com
            assertPublic("151.101.1.140"); // fastly
        }
    }

    // =========================================================================
    // §B3 item 1 — private-range deny-set (IPv6)
    // =========================================================================

    @Nested
    @DisplayName("IPv6 private-range deny-set (§B3 item 1)")
    class Ipv6DenySet {

        @Test
        @DisplayName("::1 (IPv6 loopback) is blocked")
        void blocks_ipv6_loopback() throws Exception {
            InetAddress loopback = InetAddress.getByName("::1");
            assertThat(guard.isPrivate(loopback)).isTrue();
        }

        @Test
        @DisplayName(":: (IPv6 unspecified) is blocked")
        void blocks_ipv6_unspecified() throws Exception {
            byte[] raw = new byte[16]; // all zeros
            InetAddress unspecified = InetAddress.getByAddress(raw);
            assertThat(guard.isPrivate(unspecified)).isTrue();
        }

        @Test
        @DisplayName("fc00::/7 (ULA) is blocked")
        void blocks_ula() throws Exception {
            // fc00:: — starts with 0xFC
            byte[] raw = new byte[16];
            raw[0] = (byte) 0xFC;
            raw[15] = 1;
            assertThat(guard.isPrivate(InetAddress.getByAddress(raw))).isTrue();

            // fd00:: — starts with 0xFD (also in fc00::/7 because bit 7 of byte 0 == 1)
            byte[] fd = new byte[16];
            fd[0] = (byte) 0xFD;
            fd[15] = 1;
            assertThat(guard.isPrivate(InetAddress.getByAddress(fd))).isTrue();
        }

        @Test
        @DisplayName("fe80::/10 (IPv6 link-local) is blocked")
        void blocks_link_local_v6() throws Exception {
            // fe80:: — raw[0]=0xFE, raw[1]=0x80
            byte[] raw = new byte[16];
            raw[0] = (byte) 0xFE;
            raw[1] = (byte) 0x80;
            raw[15] = 1;
            assertThat(guard.isPrivate(InetAddress.getByAddress(raw))).isTrue();
        }

        @Test
        @DisplayName("::ffff:0:0/96 (IPv4-mapped) embedding private IPv4 is blocked")
        void blocks_ipv4_mapped_private() throws Exception {
            // ::ffff:10.0.0.1 — bytes 10-11 = 0xFF, bytes 12-15 = 10.0.0.1
            byte[] raw = new byte[16];
            raw[10] = (byte) 0xFF;
            raw[11] = (byte) 0xFF;
            raw[12] = 10;
            raw[13] = 0;
            raw[14] = 0;
            raw[15] = 1;
            assertThat(guard.isPrivate(InetAddress.getByAddress(raw))).isTrue();
        }

        @Test
        @DisplayName("public IPv6 address is allowed")
        void allows_public_ipv6() throws Exception {
            // 2001:db8:: is technically documentation, but has no private meaning in §B3
            // Use 2606:4700:4700::1111 (Cloudflare) as a clearly public global unicast.
            InetAddress pub = InetAddress.getByName("2606:4700:4700::1111");
            assertThat(guard.isPrivate(pub)).isFalse();
        }
    }

    // =========================================================================
    // resolveAndValidate — DNS failure path
    // =========================================================================

    @Nested
    @DisplayName("resolveAndValidate failure paths")
    class ResolveAndValidate {

        @Test
        @DisplayName("NXDOMAIN / unresolvable host throws ValidationException")
        void throwsOnUnresolvableHost() {
            // This hostname is guaranteed not to resolve.
            assertThatThrownBy(() -> guard.resolveAndValidate("this-host-does-not-exist.invalid"))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("resolve");
        }
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private void assertPrivate(String dotted) throws Exception {
        InetAddress addr = InetAddress.getByName(dotted);
        assertThat(guard.isPrivate(addr))
                .as("expected %s to be classified as private", dotted)
                .isTrue();
    }

    private void assertPublic(String dotted) throws Exception {
        InetAddress addr = InetAddress.getByName(dotted);
        assertThat(guard.isPrivate(addr))
                .as("expected %s to be classified as public (not private)", dotted)
                .isFalse();
    }
}
