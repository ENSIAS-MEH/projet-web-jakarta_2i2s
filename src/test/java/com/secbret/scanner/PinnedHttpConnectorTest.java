package com.secbret.scanner;

import com.secbret.exception.ScanFailedException;
import com.secbret.exception.ValidationException;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The four §B3-required SSRF attack tests plus the TLS pin-and-connect tests for
 * {@link PinnedHttpConnector}.
 *
 * <p>Every test is deterministic and self-contained:
 * <ul>
 *   <li>DNS is controlled through the {@link SsrfGuard.HostResolver} seam — no real lookups,
 *       so a rebinding/TOCTOU resolver can flip its answer reproducibly.</li>
 *   <li>TLS tests run against an in-JVM {@link HttpsServer} on loopback, with certificates
 *       minted at test time via {@code keytool} into a temp keystore (no committed binaries,
 *       no network).</li>
 *   <li>The connector's TLS trust anchor is injected as a test CA (only the trust store
 *       changes) — hostname/endpoint verification is <b>never</b> weakened by the test, so the
 *       "no accept-all reachable" invariant is genuinely exercised.</li>
 * </ul>
 *
 * <h2>The four required attack tests (§B3 "Required tests")</h2>
 * <ol>
 *   <li>{@code directPrivateIpUrl_rejected} — a URL to a reserved IP (cloud metadata) is denied.</li>
 *   <li>{@code dnsRebinding_pinsValidatedIp_neverReresolves} — resolver returns public then
 *       private; connector resolves exactly once and pins the validated (public) IP.</li>
 *   <li>{@code redirectToInternal_rejectedOnHop} — a 302 to an internal IP is rejected by
 *       per-hop re-validation.</li>
 *   <li>{@code dnsNameResolvingToDeniedRange_rejected} — a benign hostname whose A record is a
 *       private IP is denied.</li>
 * </ol>
 */
@DisplayName("PinnedHttpConnector — §B3 pin-and-connect + TLS")
class PinnedHttpConnectorTest {

    private HttpServer plainServer;
    private HttpsServer tlsServer;

    @AfterEach
    void tearDown() {
        if (plainServer != null) {
            plainServer.stop(0);
        }
        if (tlsServer != null) {
            tlsServer.stop(0);
        }
    }

    // =========================================================================
    // §B3 required attack test 1 — direct private/reserved IP URL
    // =========================================================================

    @Test
    @DisplayName("[attack 1] direct private/reserved-IP URL (cloud metadata) is rejected")
    void directPrivateIpUrl_rejected() {
        // Cloud metadata endpoint — a literal reserved IP, no DNS needed.
        SsrfGuard guard = new SsrfGuard(); // real deny-set, real resolver (literal resolves to itself)
        PinnedHttpConnector connector = new PinnedHttpConnector(guard);

        assertThatThrownBy(() -> connector.requestOnce(URI.create("http://169.254.169.254/latest/meta-data/")))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("private or reserved");
    }

    // =========================================================================
    // §B3 required attack test 2 — DNS-rebinding / TOCTOU
    // =========================================================================

    @Test
    @DisplayName("[attack 2] DNS-rebinding: connector pins the validated public IP and never re-resolves")
    void dnsRebinding_pinsValidatedIp_neverReresolves() throws Exception {
        // Resolver flips: call #1 (validation) → a PUBLIC IP; call #2 (a would-be re-resolve at
        // connect time) → a PRIVATE IP. The pinned-connect contract must resolve ONCE and use
        // the validated (public) IP. If it re-resolved, the private answer would slip through
        // AND the counter would read 2.
        InetAddress publicIp = InetAddress.getByName("93.184.216.34"); // example.net range, public
        InetAddress privateIp = InetAddress.getByName("127.0.0.1");    // rebind target (denied)
        AtomicInteger calls = new AtomicInteger();
        SsrfGuard.HostResolver flipping = host -> {
            int n = calls.incrementAndGet();
            return new InetAddress[]{n == 1 ? publicIp : privateIp};
        };
        SsrfGuard guard = new SsrfGuard(flipping);
        PinnedHttpConnector connector = new PinnedHttpConnector(guard);

        // The connect to 93.184.216.34:1 will fail fast (no server) — we don't need it to
        // succeed; we assert the *resolution discipline*: exactly one resolve, pinned to the
        // validated public IP, so the rebinding private answer was never consulted.
        assertThatThrownBy(() ->
                connector.requestOnce(URI.create("http://rebind.evil.test:1/")))
                .isInstanceOf(ScanFailedException.class); // connect refused/timeout, NOT a deny

        assertThat(calls.get())
                .as("host must be resolved exactly once — re-resolution reopens the TOCTOU window")
                .isEqualTo(1);
    }

    @Test
    @DisplayName("[attack 2b] if validation IP is public but the SAME resolve returns a private sibling, deny")
    void rebinding_privateSiblingInResultSet_rejected() {
        // A single private address anywhere in the resolved set rejects the whole URL — this is
        // the multi-A-record rebinding variant (public + private returned together).
        SsrfGuard.HostResolver mixed = host -> new InetAddress[]{
                InetAddress.getByName("93.184.216.34"),
                InetAddress.getByName("10.0.0.5") // private sibling
        };
        PinnedHttpConnector connector = new PinnedHttpConnector(new SsrfGuard(mixed));
        assertThatThrownBy(() -> connector.requestOnce(URI.create("http://mixed.evil.test/")))
                .isInstanceOf(ValidationException.class);
    }

    // =========================================================================
    // §B3 required attack test 3 — redirect to internal
    // =========================================================================

    @Test
    @DisplayName("[attack 3] a 302 redirect to an internal IP is rejected on the redirect hop")
    void redirectToInternal_rejectedOnHop() throws Exception {
        // Real loopback HTTP server that 302-redirects to the cloud-metadata IP. The initial
        // hop reaches the server (resolver pins it to loopback, which we allow via a test guard
        // that isolates redirect behaviour from the deny-set); the SECOND hop's Location is
        // 169.254.169.254, which the real deny-set must reject.
        InetAddress loopback = InetAddress.getLoopbackAddress();
        plainServer = HttpServer.create(new InetSocketAddress(loopback, 0), 0);
        plainServer.createContext("/", exchange -> {
            exchange.getResponseHeaders().add("Location", "http://169.254.169.254/latest/meta-data/");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        plainServer.start();
        int port = plainServer.getAddress().getPort();

        // Guard that pins the entry host to loopback (reachable) but applies the REAL deny-set to
        // every other host — so the redirect target 169.254.169.254 is still denied on hop 2.
        SsrfGuard guard = new SsrfGuard(host -> {
            if ("entry.test".equals(host)) {
                return new InetAddress[]{loopback};
            }
            return InetAddress.getAllByName(host); // real resolution for the redirect target
        }) {
            @Override
            public boolean isPrivate(InetAddress addr) {
                // Allow the loopback server itself (entry point) but keep the real deny-set for
                // the metadata IP — so the redirect hop is the thing under test.
                if (addr.equals(loopback)) {
                    return false;
                }
                return super.isPrivate(addr);
            }
        };
        PinnedHttpConnector connector = new PinnedHttpConnector(guard);

        assertThatThrownBy(() ->
                connector.fetch(URI.create("http://entry.test:" + port + "/")))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("private or reserved");
    }

    // =========================================================================
    // §B3 required attack test 4 — DNS name resolving to a denied range
    // =========================================================================

    @Test
    @DisplayName("[attack 4] a benign hostname whose A record is a private IP is rejected")
    void dnsNameResolvingToDeniedRange_rejected() {
        // "internal.corp.test" looks innocuous but resolves to an RFC-1918 address.
        SsrfGuard.HostResolver toPrivate =
                host -> new InetAddress[]{InetAddress.getByName("192.168.1.50")};
        PinnedHttpConnector connector = new PinnedHttpConnector(new SsrfGuard(toPrivate));

        assertThatThrownBy(() ->
                connector.requestOnce(URI.create("http://internal.corp.test/admin")))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("private or reserved");
    }

    // =========================================================================
    // §B3 item 4 — integer/octal/hex/shorthand-encoded localhost
    // =========================================================================

    @Test
    @DisplayName("[attack 3-enc] integer/octal/hex/shorthand-encoded localhost is rejected before resolution")
    void encodedLocalhost_rejected() {
        PinnedHttpConnector connector = new PinnedHttpConnector(new SsrfGuard()); // real deny-set
        // Each of these is a well-known SSRF encoding of 127.0.0.1. Every one MUST be rejected —
        // either by the guard's canonical-form check (ValidationException) or, for forms the URI
        // parser itself refuses (host == null), by the connector's no-host guard. Both are
        // subclasses of SecBretException, so we assert "rejected".
        for (String enc : new String[]{
                "http://2130706433/",     // integer
                "http://0177.0.0.1/",     // octal (JVM would resolve to public 177.0.0.1!)
                "http://0x7f000001/",     // hex
                "http://0x7f.0.0.1/",     // hex dotted (URI parser returns null host)
                "http://127.1/"           // shorthand (URI parser returns null host)
        }) {
            assertThatThrownBy(() -> connector.requestOnce(URI.create(enc)))
                    .as("encoded localhost %s must be rejected", enc)
                    .isInstanceOf(com.secbret.exception.SecBretException.class);
        }

        // The octal case is the dangerous one — the JVM misreads 0177.0.0.1 as PUBLIC
        // 177.0.0.1, so the deny-set alone would MISS it. Assert it is specifically caught by
        // the guard's canonical-form validation (§B3 item 4), not by luck.
        assertThatThrownBy(() -> new SsrfGuard().resolveAndValidate("0177.0.0.1"))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("ambiguous IP encoding");
    }

    @Test
    @DisplayName("[allow] canonical dotted-decimal public IP literal is NOT flagged as an encoding")
    void canonicalPublicIpLiteral_allowed() {
        // Guard's encoding check must not false-positive on a legitimate public dotted-decimal
        // literal. We stop before an actual connect by asserting no ValidationException on the
        // resolve/encoding step (a public literal resolves to itself and passes the deny-set).
        SsrfGuard guard = new SsrfGuard();
        assertThat(guard.resolveAndValidate("203.0.113.9")).isNotEmpty(); // TEST-NET-3, public form
    }

    // =========================================================================
    // Scheme allowlist on redirect (file:// bypass)
    // =========================================================================

    @Test
    @DisplayName("[scheme] a redirect to a file:// URL is rejected (scheme allowlist on every hop)")
    void redirectToFileScheme_rejected() throws Exception {
        InetAddress loopback = InetAddress.getLoopbackAddress();
        plainServer = HttpServer.create(new InetSocketAddress(loopback, 0), 0);
        plainServer.createContext("/", exchange -> {
            exchange.getResponseHeaders().add("Location", "file:///etc/passwd");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        plainServer.start();
        int port = plainServer.getAddress().getPort();

        SsrfGuard guard = allowLoopbackGuard(loopback);
        PinnedHttpConnector connector = new PinnedHttpConnector(guard);

        assertThatThrownBy(() ->
                connector.fetch(URI.create("http://entry.test:" + port + "/")))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("not permitted");
    }

    // =========================================================================
    // TLS pin-and-connect tests
    // =========================================================================

    @Nested
    @DisplayName("TLS pin-and-connect (verify hostname, never bypass)")
    class TlsPinning {

        @Test
        @DisplayName("[tls-ok] pinned to loopback IP with a cert valid for the hostname → handshake succeeds")
        void certMatchingHostname_pinnedToIp_succeeds() throws Exception {
            Path dir = Files.createTempDirectory("secbret-tls-ok");
            KeyStore serverKs = generateKeyStore(dir, "localhost");
            startTlsServer(serverKs, "OK");

            // Trust the test CA (only the trust anchor changes); hostname verification stays ON.
            SSLSocketFactory factory = trustingFactory(serverKs);
            // Pin the connector to loopback for hostname "localhost"; TLS SNI + cert identity
            // still use "localhost", which the cert is issued for.
            SsrfGuard guard = allowLoopbackGuard(InetAddress.getLoopbackAddress());
            PinnedHttpConnector connector = new PinnedHttpConnector(guard, factory);

            int port = tlsServer.getAddress().getPort();
            PinnedResponse resp = connector.requestOnce(URI.create("https://localhost:" + port + "/"));

            assertThat(resp.statusCode()).isEqualTo(200);
            assertThat(resp.body()).contains("OK");
            assertThat(resp.peerCerts()).as("peer cert chain captured on the pinned handshake").isNotNull();
        }

        @Test
        @DisplayName("[tls-mismatch] cert whose identity does NOT match the hostname → rejected (no bypass)")
        void certNotMatchingHostname_rejected() throws Exception {
            Path dir = Files.createTempDirectory("secbret-tls-bad");
            // Cert is for "wrong.example", but we connect (SNI/verify) as "localhost".
            KeyStore serverKs = generateKeyStore(dir, "wrong.example");
            startTlsServer(serverKs, "SHOULD-NOT-REACH");

            SSLSocketFactory factory = trustingFactory(serverKs); // CA trusted…
            SsrfGuard guard = allowLoopbackGuard(InetAddress.getLoopbackAddress());
            PinnedHttpConnector connector = new PinnedHttpConnector(guard, factory);

            int port = tlsServer.getAddress().getPort();
            // …but the certificate's identity ("wrong.example") does not match the connect
            // hostname ("localhost"), so endpoint identification MUST fail. It is never bypassed.
            assertThatThrownBy(() ->
                    connector.requestOnce(URI.create("https://localhost:" + port + "/")))
                    .isInstanceOf(ScanFailedException.class)
                    .hasMessageContaining("TLS verification failed");
        }

        @Test
        @DisplayName("[tls-untrusted] a cert from an untrusted CA (system default trust) → rejected")
        void untrustedCert_rejected() throws Exception {
            Path dir = Files.createTempDirectory("secbret-tls-untrusted");
            KeyStore serverKs = generateKeyStore(dir, "localhost");
            startTlsServer(serverKs, "SHOULD-NOT-REACH");

            // Use the PRODUCTION connector (system default trust store) — it does NOT trust our
            // self-signed test cert, so chain validation must fail. Proves no accept-all trust
            // manager is reachable on the pinned https path.
            SsrfGuard guard = allowLoopbackGuard(InetAddress.getLoopbackAddress());
            PinnedHttpConnector connector = new PinnedHttpConnector(guard);

            int port = tlsServer.getAddress().getPort();
            assertThatThrownBy(() ->
                    connector.requestOnce(URI.create("https://localhost:" + port + "/")))
                    .isInstanceOf(ScanFailedException.class)
                    .hasMessageContaining("TLS verification failed");
        }
    }

    // =========================================================================
    // Test helpers
    // =========================================================================

    /**
     * A guard that treats the loopback server address as reachable (so an in-JVM server can be
     * hit) while keeping the REAL deny-set for every other address and real DNS for other hosts.
     * Isolates the behaviour under test (pinning / TLS / redirect) from the deny-set, which is
     * covered exhaustively by {@link SsrfGuardTest}.
     */
    private static SsrfGuard allowLoopbackGuard(InetAddress loopback) {
        return new SsrfGuard(host -> {
            if ("entry.test".equals(host) || "localhost".equals(host)) {
                return new InetAddress[]{loopback};
            }
            return InetAddress.getAllByName(host);
        }) {
            @Override
            public boolean isPrivate(InetAddress addr) {
                if (addr.equals(loopback)) {
                    return false;
                }
                return super.isPrivate(addr);
            }
        };
    }

    private void startTlsServer(KeyStore serverKs, String body) throws Exception {
        InetAddress loopback = InetAddress.getLoopbackAddress();
        SSLContext ctx = SSLContext.getInstance("TLS");
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(serverKs, "changeit".toCharArray());
        ctx.init(kmf.getKeyManagers(), null, null);

        tlsServer = HttpsServer.create(new InetSocketAddress(loopback, 0), 0);
        tlsServer.setHttpsConfigurator(new HttpsConfigurator(ctx));
        tlsServer.createContext("/", exchange -> {
            byte[] out = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, out.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(out);
            }
            exchange.close();
        });
        tlsServer.start();
    }

    /** Build an SSLSocketFactory whose trust store trusts the given keystore's certificate. */
    private static SSLSocketFactory trustingFactory(KeyStore certSource) throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(certSource); // trust the test cert as a CA anchor — trust store only, no verifier change
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tmf.getTrustManagers(), null);
        return ctx.getSocketFactory();
    }

    /**
     * Mint a self-signed cert for {@code cn} into a PKCS12 keystore using {@code keytool}.
     * Deterministic, in-process subprocess — no committed key material, no network.
     */
    private static KeyStore generateKeyStore(Path dir, String cn) throws Exception {
        Path ks = dir.resolve("server.p12");
        String keytool = System.getProperty("java.home") + "/bin/keytool";
        Process p = new ProcessBuilder(
                keytool, "-genkeypair",
                "-alias", "server",
                "-keyalg", "RSA", "-keysize", "2048",
                "-dname", "CN=" + cn,
                "-ext", "SAN=dns:" + cn,
                "-validity", "1",
                "-keystore", ks.toString(),
                "-storetype", "PKCS12",
                "-storepass", "changeit",
                "-keypass", "changeit"
        ).redirectErrorStream(true).start();
        int code = p.waitFor();
        if (code != 0) {
            throw new IllegalStateException("keytool failed (" + code + ") generating cert for " + cn);
        }
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (var in = Files.newInputStream(ks)) {
            keyStore.load(in, "changeit".toCharArray());
        }
        return keyStore;
    }
}
