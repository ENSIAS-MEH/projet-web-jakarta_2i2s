package com.secbret.scanner;

import com.secbret.exception.ValidationException;
import jakarta.enterprise.context.ApplicationScoped;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * SSRF deny-set guard implementing Part II §B3 items 1 and 5 (Task 10 scope).
 *
 * <p>Task 10 covers the <em>basic</em> SSRF guard: scheme allowlist (http/https) and
 * deny-by-default address validation — reject if any resolved A/AAAA address falls
 * inside a reserved range. Full TOCTOU/DNS-rebinding defense (pin-and-connect, per-hop
 * re-validation, integer/octal/hex encoding normalization) is Task 24 (§B3 conformance).
 *
 * <h2>Deny-set (§B3 item 1)</h2>
 * <ul>
 *   <li>{@code 10.0.0.0/8} — RFC 1918 private</li>
 *   <li>{@code 172.16.0.0/12} — RFC 1918 private</li>
 *   <li>{@code 192.168.0.0/16} — RFC 1918 private</li>
 *   <li>{@code 127.0.0.0/8} — loopback</li>
 *   <li>{@code 169.254.0.0/16} — link-local / cloud metadata (incl. 169.254.169.254)</li>
 *   <li>{@code 0.0.0.0/8} — "this" network (also used by SSRF payloads)</li>
 *   <li>{@code 100.64.0.0/10} — CGNAT shared address space</li>
 *   <li>{@code ::1} — IPv6 loopback</li>
 *   <li>{@code ::} — unspecified IPv6</li>
 *   <li>{@code fc00::/7} — IPv6 ULA</li>
 *   <li>{@code fe80::/10} — IPv6 link-local</li>
 *   <li>{@code ::ffff:0:0/96} — IPv4-mapped IPv6</li>
 * </ul>
 *
 * <h2>Complexity</h2>
 * O(a × c) where a = number of A/AAAA records (bounded by DNS), c = number of CIDR
 * blocks (fixed = 12). Effectively O(1) for any realistic DNS response.
 */
@ApplicationScoped
public class SsrfGuard {

    private static final Logger log = LoggerFactory.getLogger(SsrfGuard.class);

    /** Permitted URI schemes at submission time (§B3 item 5). */
    private static final java.util.Set<String> ALLOWED_SCHEMES =
            java.util.Set.of("http", "https");

    /**
     * DNS resolution seam. Production uses {@link InetAddress#getAllByName(String)}; tests
     * inject a stub to make DNS-rebinding / TOCTOU behaviour deterministic (a resolver that
     * flips its answer between validation and connect). Never null.
     */
    @FunctionalInterface
    public interface HostResolver {
        InetAddress[] resolve(String host) throws UnknownHostException;
    }

    private final HostResolver resolver;

    /** Production constructor: real system DNS. */
    public SsrfGuard() {
        this(InetAddress::getAllByName);
    }

    /** Test/seam constructor: inject a deterministic resolver. */
    public SsrfGuard(HostResolver resolver) {
        this.resolver = resolver;
    }

    // -------------------------------------------------------------------------
    // Private-range CIDR blocks (§B3 item 1)
    // Each entry: { network_byte_array, prefix_length }
    // -------------------------------------------------------------------------
    private static final byte[][] DENY_NETS_V4 = {
        // 10.0.0.0/8
        new byte[]{10, 0, 0, 0},
        // 172.16.0.0/12
        new byte[]{(byte) 172, 16, 0, 0},
        // 192.168.0.0/16
        new byte[]{(byte) 192, (byte) 168, 0, 0},
        // 127.0.0.0/8
        new byte[]{127, 0, 0, 0},
        // 169.254.0.0/16
        new byte[]{(byte) 169, (byte) 254, 0, 0},
        // 0.0.0.0/8
        new byte[]{0, 0, 0, 0},
        // 100.64.0.0/10
        new byte[]{100, 64, 0, 0},
    };

    private static final int[] DENY_PREFIX_V4 = {8, 12, 16, 8, 16, 8, 10};

    /**
     * Validate that {@code scheme} is in the allowlist (§B3 item 5).
     *
     * @param scheme the URI scheme (lower-cased)
     * @throws ValidationException if the scheme is not http or https
     */
    public void requireAllowedScheme(String scheme) {
        if (scheme == null || !ALLOWED_SCHEMES.contains(scheme.toLowerCase(java.util.Locale.ROOT))) {
            throw new ValidationException(
                    "URL scheme '" + scheme + "' is not permitted; only http and https are allowed.");
        }
    }

    /**
     * Resolve {@code host} and reject the request if any A/AAAA address falls inside
     * the §B3 deny-set (item 1). A single private address in the result set rejects the
     * whole URL — deny-by-default.
     *
     * <p><b>Pre-condition:</b> the caller has already validated the scheme. This method
     * does not check the scheme.
     *
     * @param host the hostname or IP literal to resolve and validate
     * @throws ValidationException  if any resolved address is in the deny-set, or if the
     *                              host cannot be resolved (NXDOMAIN / DNS failure)
     */
    public InetAddress[] resolveAndValidate(String host) {
        // §B3 item 4: reject ambiguous IP encodings (integer, octal, hex, shorthand) BEFORE
        // resolution. The JVM's own parser is inconsistent about these — e.g. "0177.0.0.1" is
        // meant to be octal 127.0.0.1 but Java reads it as decimal 177.0.0.1 (a *public* IP),
        // which would slip past the deny-set. The spec permits "canonicalize OR reject"; we
        // reject, because canonicalizing every historical IP-literal form is error-prone and no
        // legitimate scan target uses them.
        rejectAmbiguousIpEncoding(host);

        InetAddress[] addresses;
        try {
            addresses = resolver.resolve(host);
        } catch (UnknownHostException e) {
            log.warn("SSRF guard: DNS resolution failed for host='{}': {}", host, e.getMessage());
            throw new ValidationException("Cannot resolve host '" + host + "': " + e.getMessage());
        }

        for (InetAddress addr : addresses) {
            if (isPrivate(addr)) {
                log.warn("SSRF guard: blocked request to private/reserved address host='{}' ip='{}'",
                        host, addr.getHostAddress());
                throw new ValidationException(
                        "The target URL resolves to a private or reserved address and cannot be scanned.");
            }
        }
        return addresses;
    }

    /**
     * §B3 item 4 — reject non-canonical / ambiguous IPv4-literal encodings.
     *
     * <p>Rejects (throws) when {@code host} is an attempt at an IPv4 literal in a form other
     * than plain canonical dotted-decimal with exactly four octets each in {@code 0..255} and
     * without leading zeros:
     * <ul>
     *   <li>pure integer — {@code 2130706433}</li>
     *   <li>hex — {@code 0x7f000001}, {@code 0x7f.0.0.1}</li>
     *   <li>octal (leading zero on any octet) — {@code 0177.0.0.1}</li>
     *   <li>dotted shorthand with fewer than 4 numeric parts — {@code 127.1}</li>
     * </ul>
     *
     * <p>Ordinary hostnames (which contain at least one non-numeric label, e.g. the TLD) and
     * canonical dotted-decimal IPv4 literals pass through untouched. IPv6 literals arrive here
     * already stripped of brackets by {@code URI.getHost()} and contain {@code ':'}, so they are
     * out of scope for this IPv4-encoding check.
     *
     * <p>Time: O(len(host)). Pure function of the input string.
     *
     * @throws ValidationException if {@code host} uses an ambiguous IPv4 encoding
     */
    void rejectAmbiguousIpEncoding(String host) {
        if (host == null || host.isEmpty() || host.indexOf(':') >= 0) {
            return; // null/empty handled elsewhere; ':' → IPv6 literal, not an IPv4 encoding
        }
        String lower = host.toLowerCase(java.util.Locale.ROOT);

        // Hex marker anywhere (0x...) — always an encoded literal.
        if (lower.contains("0x")) {
            throw ambiguousEncoding(host, "hex IP encoding");
        }

        String[] parts = lower.split("\\.", -1);

        // Pure integer with no dots, e.g. "2130706433".
        if (parts.length == 1) {
            if (isAllDigits(parts[0])) {
                throw ambiguousEncoding(host, "integer IP encoding");
            }
            return; // single non-numeric label (e.g. "localhost") — a normal hostname
        }

        // A dotted host is treated as an IPv4-literal *attempt* only if every part is numeric.
        // If any part has a non-digit char it is a DNS hostname (has a real label) — leave it.
        boolean allNumeric = true;
        for (String part : parts) {
            if (!isAllDigits(part)) {
                allNumeric = false;
                break;
            }
        }
        if (!allNumeric) {
            return; // ordinary hostname such as "example.com" or "1.2.example.com"
        }

        // All-numeric dotted form: must be canonical 4-octet dotted-decimal, no leading zeros.
        if (parts.length != 4) {
            throw ambiguousEncoding(host, "shorthand IPv4 encoding");
        }
        for (String octet : parts) {
            if (octet.length() > 1 && octet.charAt(0) == '0') {
                throw ambiguousEncoding(host, "octal IPv4 encoding");
            }
            int value = Integer.parseInt(octet); // safe: isAllDigits guaranteed, but bound-check
            if (value > 255) {
                throw ambiguousEncoding(host, "out-of-range IPv4 octet");
            }
        }
        // Reaching here: canonical dotted-decimal IPv4 (e.g. "203.0.113.9") — allowed.
    }

    private static boolean isAllDigits(String s) {
        if (s.isEmpty()) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            if (!Character.isDigit(s.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    private static ValidationException ambiguousEncoding(String host, String kind) {
        log.warn("SSRF guard: blocked ambiguous IP encoding host='{}' ({})", host, kind);
        return new ValidationException(
                "The target URL uses an ambiguous IP encoding (" + kind + ") and cannot be scanned.");
    }

    /**
     * Returns {@code true} if {@code addr} falls inside any of the §B3 deny-set ranges.
     *
     * <p>Supports both IPv4 and IPv6. IPv4-mapped IPv6 addresses ({@code ::ffff:0:0/96})
     * are caught by the 4-byte raw check after extraction by the JVM's normalisation —
     * {@link InetAddress#getAddress()} on an IPv4-in-IPv6 address returns the 4-byte
     * IPv4 form in Java.
     */
    public boolean isPrivate(InetAddress addr) {
        byte[] raw = addr.getAddress();

        if (raw.length == 4) {
            return isPrivateV4(raw);
        } else if (raw.length == 16) {
            return isPrivateV6(raw);
        }
        // Unknown family — deny to be safe.
        return true;
    }

    // -----------------------------------------------------------------------
    // IPv4 deny-set check
    // Invariant: raw.length == 4
    // -----------------------------------------------------------------------
    private static boolean isPrivateV4(byte[] raw) {
        for (int i = 0; i < DENY_NETS_V4.length; i++) {
            if (matchesCidrV4(raw, DENY_NETS_V4[i], DENY_PREFIX_V4[i])) {
                return true;
            }
        }
        return false;
    }

    /**
     * Prefix match for IPv4 CIDRs.
     * Loop invariant: after k iterations, the first k bits of {@code addr} match {@code net}.
     * Termination: at most 4 iterations (the fixed array length).
     * Time: O(1) — bounded by 4 bytes.
     */
    private static boolean matchesCidrV4(byte[] addr, byte[] net, int prefixBits) {
        int fullBytes = prefixBits / 8;
        int remainBits = prefixBits % 8;

        // Loop invariant: after byte i the first i*8 bits matched.
        for (int i = 0; i < fullBytes; i++) {
            if (addr[i] != net[i]) {
                return false;
            }
        }
        if (remainBits > 0 && fullBytes < 4) {
            int mask = 0xFF & (0xFF << (8 - remainBits));
            return (addr[fullBytes] & mask) == (net[fullBytes] & mask);
        }
        return true;
    }

    // -----------------------------------------------------------------------
    // IPv6 deny-set check
    // §B3: ::1, ::, fc00::/7, fe80::/10, ::ffff:0:0/96
    // Invariant: raw.length == 16
    // -----------------------------------------------------------------------
    private static boolean isPrivateV6(byte[] raw) {
        // ::1 — loopback
        if (isLoopbackV6(raw)) {
            return true;
        }
        // :: — unspecified
        if (isUnspecifiedV6(raw)) {
            return true;
        }
        // fc00::/7 — ULA: first byte bits 11111110 → (raw[0] & 0xFE) == 0xFC
        if ((raw[0] & 0xFE) == 0xFC) {
            return true;
        }
        // fe80::/10 — link-local: first 10 bits = 1111111010
        // raw[0] == 0xFE, raw[1] bits 7..6 == 10 → (raw[1] & 0xC0) == 0x80
        if (raw[0] == (byte) 0xFE && (raw[1] & 0xC0) == 0x80) {
            return true;
        }
        // ::ffff:0:0/96 — IPv4-mapped: bytes 0–9 all zero, bytes 10–11 == 0xFF 0xFF
        // Java's InetAddress.getAddress() returns the 4-byte form for IPv4-in-IPv6
        // (Inet4Address), but we guard here in case a raw 16-byte mapped address arrives.
        if (isIpv4Mapped(raw)) {
            // Extract the embedded IPv4 address and re-check.
            byte[] v4 = new byte[]{raw[12], raw[13], raw[14], raw[15]};
            return isPrivateV4(v4);
        }
        return false;
    }

    private static boolean isLoopbackV6(byte[] raw) {
        // ::1 = 15 zero bytes + 0x01
        for (int i = 0; i < 15; i++) {
            if (raw[i] != 0) {
                return false;
            }
        }
        return raw[15] == 1;
    }

    private static boolean isUnspecifiedV6(byte[] raw) {
        // :: = 16 zero bytes
        for (byte b : raw) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    private static boolean isIpv4Mapped(byte[] raw) {
        // bytes 0–9 == 0, bytes 10–11 == 0xFF
        for (int i = 0; i < 10; i++) {
            if (raw[i] != 0) {
                return false;
            }
        }
        return raw[10] == (byte) 0xFF && raw[11] == (byte) 0xFF;
    }
}
