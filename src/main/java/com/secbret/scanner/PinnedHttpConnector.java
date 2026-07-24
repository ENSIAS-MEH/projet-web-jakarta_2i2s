package com.secbret.scanner;

import com.secbret.exception.ScanFailedException;
import com.secbret.exception.ValidationException;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Full pin-and-connect SSRF-safe HTTP(S) fetcher (Part II §B3 item 2).
 *
 * <p>This is the single outbound-fetch path for all three scanner tiers. It closes the
 * TOCTOU / DNS-rebinding window that a validate-then-reopen-by-hostname flow leaves open:
 * the JDK's {@code HttpURLConnection}/{@code HttpClient} and jsoup all re-resolve the
 * hostname internally between our deny-set check and the actual socket connect, so a
 * rebinding attacker can answer with a public IP during validation and a private IP at
 * connect time. Here we instead:
 *
 * <ol>
 *   <li><b>Validate</b> the scheme and resolve+deny-set-check <em>every</em> A/AAAA record
 *       via {@link SsrfGuard} (§B3 item 1 + item 5).</li>
 *   <li><b>Pin</b> the connection to the exact validated {@link InetAddress} — the TCP
 *       socket connects to that IP literal, never re-resolving the hostname (§B3 item 2).</li>
 *   <li><b>TLS: pin the transport, verify the hostname.</b> For {@code https}, the socket
 *       connects to the pinned IP but the TLS layer sets the SNI {@code server_name} to the
 *       <em>original hostname</em> and enables HTTPS endpoint identification against the
 *       hostname (RFC 6125/9110). Certificate + hostname verification is never disabled or
 *       relaxed — no accept-all trust manager or hostname verifier is reachable here.</li>
 *   <li><b>Re-validate every redirect hop.</b> Each 3xx {@code Location} is treated as a new
 *       URL: scheme allowlist + resolve + deny-set + pin-and-connect reapply, up to the
 *       3-redirect cap (§B3 item 3).</li>
 * </ol>
 *
 * <p>Timeouts (5s connect / 5s read), the 3-redirect cap, and the 5MB body limit from the
 * scanner-safety table are enforced here. No retry (Decision #17).
 *
 * <h2>Complexity</h2>
 * O(h) socket round-trips where h ≤ 4 (initial + up to 3 redirect hops). Each hop is a
 * single connect + validate; validation itself is O(1) per the {@link SsrfGuard} bounds.
 */
@ApplicationScoped
public class PinnedHttpConnector {

    private static final Logger log = LoggerFactory.getLogger(PinnedHttpConnector.class);

    /** Connect timeout per hop, milliseconds (§B scanner-safety table). */
    static final int CONNECT_TIMEOUT_MS = 5_000;
    /** Read timeout per hop, milliseconds. */
    static final int READ_TIMEOUT_MS = 5_000;
    /** Maximum redirect hops (§B3 item 3). A 4th 3xx exceeds the cap. */
    static final int MAX_REDIRECTS = 3;
    /** Maximum response body size, bytes (5 MB, §B scanner-safety table). */
    static final int MAX_BODY_BYTES = 5 * 1024 * 1024;
    /** HTTPS endpoint-identification algorithm — enables RFC 6125 hostname verification. */
    private static final String HTTPS_ENDPOINT_ID = "HTTPS";

    private static final String USER_AGENT = "SecBret-Scanner/1.0";

    private final SsrfGuard ssrfGuard;

    /**
     * TLS socket factory. Production uses the system default (system trust store). Tests may
     * inject a factory whose <em>trust anchor</em> is a test CA — this changes only which CAs
     * are trusted, NEVER whether hostname/endpoint verification runs. Hostname verification is
     * set unconditionally on every socket in {@link #openPinnedTlsSocket}, independent of this
     * factory, so no injected factory can weaken it.
     */
    private final SSLSocketFactory sslSocketFactory;

    /** CDI proxy constructor — required for @ApplicationScoped normal-scoped bean proxying (Weld). */
    protected PinnedHttpConnector() {
        this.ssrfGuard = null;
        this.sslSocketFactory = null;
    }

    @Inject
    public PinnedHttpConnector(SsrfGuard ssrfGuard) {
        this(ssrfGuard, (SSLSocketFactory) SSLSocketFactory.getDefault());
    }

    /** Test/seam constructor: inject an SSLSocketFactory backed by a custom trust store. */
    public PinnedHttpConnector(SsrfGuard ssrfGuard, SSLSocketFactory sslSocketFactory) {
        this.ssrfGuard = ssrfGuard;
        this.sslSocketFactory = sslSocketFactory;
    }

    /**
     * Fetch {@code startUrl} following up to {@value #MAX_REDIRECTS} redirects, re-running the
     * full validate-then-pin contract on every hop.
     *
     * @param startUri the absolute http/https URI to fetch
     * @return the final response (after redirects), including body, headers, peer certs, and
     *         the observed redirect chain and hop count
     * @throws ValidationException if any hop's scheme is disallowed or resolves into the deny-set
     * @throws ScanFailedException on I/O error, timeout, or a malformed redirect target
     */
    public PinnedResponse fetch(URI startUri) {
        URI current = startUri;
        List<String> redirectChain = new ArrayList<>();
        redirectChain.add(current.toString());
        int hops = 0;

        while (true) {
            PinnedResponse resp = requestOnce(current);
            if (!isRedirect(resp.statusCode()) || resp.location() == null) {
                return resp.withChain(redirectChain, hops);
            }

            // --- Redirect hop: a 3xx with a Location. This counts against the cap. ---
            hops++;
            if (hops > MAX_REDIRECTS) {
                // Exceeded the cap — return the last redirect response as-is; the caller
                // flags the anomaly. We do NOT follow the (n+1)th hop.
                return resp.withChain(redirectChain, hops);
            }

            URI next;
            try {
                next = current.resolve(resp.location());
            } catch (IllegalArgumentException e) {
                throw new ScanFailedException("Invalid redirect Location: " + resp.location(), e);
            }
            // §B3 item 5: scheme allowlist re-applies on every hop. A redirect to file:/gopher:/
            // ftp:/dict: is rejected here as a scheme violation before any connect is attempted.
            ssrfGuard.requireAllowedScheme(
                    next.getScheme() == null ? null : next.getScheme().toLowerCase(Locale.ROOT));
            if (next.getHost() == null) {
                throw new ScanFailedException("Redirect Location has no host: " + resp.location());
            }
            redirectChain.add(next.toString());
            current = next;
        }
    }

    /**
     * Perform a single request (no redirect following) with the full validate-then-pin
     * contract. Package-private so scanner tiers that manage their own hop loop (e.g. Tier1's
     * chain collection) can reuse the exact pinned-connect primitive.
     */
    PinnedResponse requestOnce(URI uri) {
        String scheme = uri.getScheme() == null ? null : uri.getScheme().toLowerCase(Locale.ROOT);
        ssrfGuard.requireAllowedScheme(scheme);

        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new ScanFailedException("URL has no host: " + uri);
        }

        // §B3 item 1 + 2: validate ALL resolved IPs, then PIN to a validated one.
        InetAddress[] validated = ssrfGuard.resolveAndValidate(host);
        InetAddress pinnedIp = validated[0];

        boolean https = "https".equals(scheme);
        int port = uri.getPort() != -1 ? uri.getPort() : (https ? 443 : 80);

        Socket socket = null;
        try {
            socket = https
                    ? openPinnedTlsSocket(pinnedIp, port, host)
                    : PinnedHttpConnector.openPinnedPlainSocket(pinnedIp, port);
            socket.setSoTimeout(READ_TIMEOUT_MS);

            Certificate[] peerCerts = null;
            if (socket instanceof SSLSocket tls) {
                // Force the handshake now so hostname/cert verification runs before we send.
                tls.startHandshake();
                peerCerts = tls.getSession().getPeerCertificates();
            }

            writeRequest(socket.getOutputStream(), host, uri, port, https);
            return readResponse(socket.getInputStream(), peerCerts);
        } catch (javax.net.ssl.SSLException e) {
            // Certificate/hostname verification failure or handshake problem. Surface it —
            // we NEVER retry with verification disabled (that is the forbidden anti-pattern).
            throw new ScanFailedException("TLS verification failed for " + host + ": "
                    + e.getMessage(), e);
        } catch (java.net.SocketTimeoutException e) {
            throw new ScanFailedException("Connection or read timed out fetching " + uri, e);
        } catch (IOException e) {
            throw new ScanFailedException("I/O error fetching " + uri + ": " + e.getMessage(), e);
        } finally {
            closeQuietly(socket);
        }
    }

    // -------------------------------------------------------------------------
    // Socket construction — pin to the validated IP
    // -------------------------------------------------------------------------

    private static Socket openPinnedPlainSocket(InetAddress pinnedIp, int port) throws IOException {
        Socket socket = new Socket();
        // Connect to the PINNED IP literal — no hostname, so the OS never re-resolves.
        socket.connect(new InetSocketAddress(pinnedIp, port), CONNECT_TIMEOUT_MS);
        return socket;
    }

    /**
     * Open a TLS socket whose TCP endpoint is the pinned IP, but whose SNI and certificate
     * identity check use the original hostname. This is the §B3 "pin the transport, verify
     * the hostname" contract.
     */
    private SSLSocket openPinnedTlsSocket(InetAddress pinnedIp, int port, String host)
            throws IOException {
        // Underlying TCP socket connects to the validated IP literal (no re-resolution).
        Socket underlying = new Socket();
        underlying.connect(new InetSocketAddress(pinnedIp, port), CONNECT_TIMEOUT_MS);

        // Layer TLS over the already-connected pinned socket. autoClose=true so closing the
        // SSLSocket closes the underlying socket.
        SSLSocket tls = (SSLSocket) sslSocketFactory.createSocket(underlying, host, port, true);

        SSLParameters params = tls.getSSLParameters();
        // SNI = original hostname → name-based virtual hosts serve the right cert.
        params.setServerNames(List.of(new SNIHostName(host)));
        // Endpoint identification against the HOSTNAME (not the pinned IP). This is the
        // switch that makes the JDK verify the certificate's identity matches `host` during
        // the handshake. It is NEVER cleared — doing so is the forbidden anti-pattern.
        params.setEndpointIdentificationAlgorithm(HTTPS_ENDPOINT_ID);
        tls.setSSLParameters(params);
        return tls;
    }

    // -------------------------------------------------------------------------
    // Minimal HTTP/1.1 request/response over the pinned socket
    // -------------------------------------------------------------------------

    private static void writeRequest(OutputStream out, String host, URI uri, int port,
                                     boolean https) throws IOException {
        String pathAndQuery = requestTarget(uri);
        String hostHeader = isDefaultPort(port, https) ? host : host + ":" + port;
        String request = "GET " + pathAndQuery + " HTTP/1.1\r\n"
                + "Host: " + hostHeader + "\r\n"
                + "User-Agent: " + USER_AGENT + "\r\n"
                + "Accept: */*\r\n"
                + "Connection: close\r\n"
                + "\r\n";
        out.write(request.getBytes(StandardCharsets.US_ASCII));
        out.flush();
    }

    private static PinnedResponse readResponse(InputStream in, Certificate[] peerCerts)
            throws IOException {
        // Read the full stream (capped) then split header/body on the blank line. HTTP/1.1
        // headers are ASCII; the body is decoded as UTF-8 for jsoup.
        byte[] raw = readCapped(in, MAX_BODY_BYTES);
        int sep = indexOfCrlfCrlf(raw);
        String headerBlock = new String(raw, 0, sep < 0 ? raw.length : sep,
                StandardCharsets.US_ASCII);
        String body = sep < 0 ? "" : new String(raw, sep + 4, raw.length - sep - 4,
                StandardCharsets.UTF_8);

        String[] lines = headerBlock.split("\r\n");
        int statusCode = parseStatusLine(lines.length > 0 ? lines[0] : "");
        Map<String, String> headers = new LinkedHashMap<>();
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon > 0) {
                String name = lines[i].substring(0, colon).trim().toLowerCase(Locale.ROOT);
                String value = lines[i].substring(colon + 1).trim();
                // First-wins for repeated headers (matches Location semantics we need).
                headers.putIfAbsent(name, value);
            }
        }
        return new PinnedResponse(statusCode, headers, body, peerCerts, List.of(), 0);
    }

    private static byte[] readCapped(InputStream in, int cap) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int total = 0;
        int n;
        while ((n = in.read(chunk)) != -1) {
            int allowed = Math.min(n, cap - total);
            if (allowed > 0) {
                buf.write(chunk, 0, allowed);
                total += allowed;
            }
            if (total >= cap) {
                break; // 5MB limit reached; stop reading.
            }
        }
        return buf.toByteArray();
    }

    // -------------------------------------------------------------------------
    // Small pure helpers
    // -------------------------------------------------------------------------

    private static int parseStatusLine(String statusLine) {
        // "HTTP/1.1 302 Found" → 302
        String[] parts = statusLine.split(" ");
        if (parts.length < 2) {
            throw new IllegalArgumentException("Malformed status line: " + statusLine);
        }
        try {
            return Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Malformed status code: " + statusLine, e);
        }
    }

    private static String requestTarget(URI uri) {
        String path = uri.getRawPath();
        if (path == null || path.isEmpty()) {
            path = "/";
        }
        String query = uri.getRawQuery();
        return query == null ? path : path + "?" + query;
    }

    private static boolean isDefaultPort(int port, boolean https) {
        return (https && port == 443) || (!https && port == 80);
    }

    static boolean isRedirect(int code) {
        return code == 301 || code == 302 || code == 303 || code == 307 || code == 308;
    }

    private static int indexOfCrlfCrlf(byte[] data) {
        for (int i = 0; i + 3 < data.length; i++) {
            if (data[i] == '\r' && data[i + 1] == '\n'
                    && data[i + 2] == '\r' && data[i + 3] == '\n') {
                return i;
            }
        }
        return -1;
    }

    private static void closeQuietly(Socket socket) {
        if (socket != null) {
            try {
                socket.close();
            } catch (IOException ignored) {
                // best-effort close
            }
        }
    }
}
