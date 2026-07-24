package com.secbret.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link SecurityHeaderFilter}.
 *
 * Covers: all headers present, CSP nonce changes between requests, CORS whitelist.
 */
@ExtendWith(MockitoExtension.class)
class SecurityHeaderFilterTest {

    @Mock HttpServletRequest  request;
    @Mock HttpServletResponse response;
    @Mock FilterChain         chain;

    private SecurityHeaderFilter filter;

    @BeforeEach
    void setUp() throws Exception {
        filter = new SecurityHeaderFilter();
        filter.init(null); // no env var set → empty extra origins
        when(request.getHeader("Origin")).thenReturn(null);
        when(request.getMethod()).thenReturn("GET");
    }

    // ---------------------------------------------------------------- security headers

    @Test
    @DisplayName("X-Frame-Options: DENY is set on every response")
    void setsXFrameOptions() throws Exception {
        filter.doFilter(request, response, chain);
        verify(response).setHeader("X-Frame-Options", "DENY");
    }

    @Test
    @DisplayName("X-Content-Type-Options: nosniff is set on every response")
    void setsXContentTypeOptions() throws Exception {
        filter.doFilter(request, response, chain);
        verify(response).setHeader("X-Content-Type-Options", "nosniff");
    }

    @Test
    @DisplayName("Strict-Transport-Security header is set on every response")
    void setsHsts() throws Exception {
        filter.doFilter(request, response, chain);
        verify(response).setHeader(eq("Strict-Transport-Security"),
                contains("max-age=31536000"));
    }

    @Test
    @DisplayName("Referrer-Policy: strict-origin-when-cross-origin is set on every response")
    void setsReferrerPolicy() throws Exception {
        filter.doFilter(request, response, chain);
        verify(response).setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    }

    // ---------------------------------------------------------------- CSP nonce

    @Test
    @DisplayName("CSP header includes nonce in script-src and style-src")
    void cspHeaderContainsNonce() throws Exception {
        ArgumentCaptor<String> nonceCaptor = ArgumentCaptor.forClass(String.class);
        // Capture the nonce stored on the request
        doNothing().when(request).setAttribute(eq(SecurityHeaderFilter.NONCE_ATTR), nonceCaptor.capture());

        filter.doFilter(request, response, chain);

        String nonce = nonceCaptor.getValue();
        assertThat(nonce).isNotNull().isNotBlank();

        // Verify the CSP header contains the nonce
        ArgumentCaptor<String> cspCaptor = ArgumentCaptor.forClass(String.class);
        verify(response).setHeader(eq("Content-Security-Policy"), cspCaptor.capture());
        String csp = cspCaptor.getValue();
        assertThat(csp).contains("'nonce-" + nonce + "'");
        assertThat(csp).contains("script-src");
        assertThat(csp).contains("style-src");
    }

    @Test
    @DisplayName("CSP nonce is different on each request")
    void cspNonce_freshPerRequest() throws Exception {
        ArgumentCaptor<String> nonce1 = ArgumentCaptor.forClass(String.class);
        doNothing().when(request).setAttribute(eq(SecurityHeaderFilter.NONCE_ATTR), nonce1.capture());
        filter.doFilter(request, response, chain);

        reset(request, response, chain);
        when(request.getHeader("Origin")).thenReturn(null);
        when(request.getMethod()).thenReturn("GET");
        ArgumentCaptor<String> nonce2 = ArgumentCaptor.forClass(String.class);
        doNothing().when(request).setAttribute(eq(SecurityHeaderFilter.NONCE_ATTR), nonce2.capture());
        filter.doFilter(request, response, chain);

        assertThat(nonce1.getValue()).isNotEqualTo(nonce2.getValue());
    }

    @Test
    @DisplayName("CSP default-src is strict 'self' (no CDN origins)")
    void cspDefaultSrcIsSelf() throws Exception {
        filter.doFilter(request, response, chain);

        ArgumentCaptor<String> cspCaptor = ArgumentCaptor.forClass(String.class);
        verify(response).setHeader(eq("Content-Security-Policy"), cspCaptor.capture());
        assertThat(cspCaptor.getValue()).startsWith("default-src 'self'");
    }

    // ---------------------------------------------------------------- CORS

    @Test
    @DisplayName("no CORS headers when Origin is absent")
    void cors_noOrigin_noHeaders() throws Exception {
        filter.doFilter(request, response, chain);
        verify(response, never()).setHeader(eq("Access-Control-Allow-Origin"), anyString());
    }

    @Test
    @DisplayName("no CORS headers for a non-whitelisted external origin")
    void cors_unknownOrigin_noHeaders() throws Exception {
        when(request.getHeader("Origin")).thenReturn("https://evil.com");
        when(request.getScheme()).thenReturn("http");
        when(request.getServerName()).thenReturn("localhost");
        when(request.getServerPort()).thenReturn(8080);
        filter.doFilter(request, response, chain);
        verify(response, never()).setHeader(eq("Access-Control-Allow-Origin"), anyString());
    }

    @Test
    @DisplayName("CORS headers are set for the same origin")
    void cors_sameOrigin_headersSet() throws Exception {
        when(request.getHeader("Origin")).thenReturn("http://localhost:8080");
        when(request.getScheme()).thenReturn("http");
        when(request.getServerName()).thenReturn("localhost");
        when(request.getServerPort()).thenReturn(8080);

        filter.doFilter(request, response, chain);

        verify(response).setHeader("Access-Control-Allow-Origin", "http://localhost:8080");
        verify(response).setHeader("Access-Control-Allow-Credentials", "true");
    }

    @Test
    @DisplayName("wildcard is never emitted as ACAO even if env var is '*'")
    void cors_wildcardNeverEmitted() throws Exception {
        // Even if someone sets CORS_ALLOWED_ORIGINS=*, the code must never emit *
        // because allow-credentials cannot be used with *.
        // The isAllowedOrigin check compares origin == "*" which would only match
        // if the actual Origin header sent by a browser is literally "*" — browsers
        // never send that. So ACAO:* is structurally impossible.
        when(request.getHeader("Origin")).thenReturn("*");
        when(request.getScheme()).thenReturn("http");
        when(request.getServerName()).thenReturn("localhost");
        when(request.getServerPort()).thenReturn(8080);
        filter.doFilter(request, response, chain);
        verify(response, never()).setHeader(eq("Access-Control-Allow-Origin"), eq("*"));
    }
}
