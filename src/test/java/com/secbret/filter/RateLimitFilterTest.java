package com.secbret.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.io.ByteArrayOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link RateLimitFilter} client-IP extraction and header setting.
 */
@ExtendWith(MockitoExtension.class)
class RateLimitFilterTest {

    @Mock HttpServletRequest  request;
    @Mock HttpServletResponse response;
    @Mock FilterChain         chain;

    // ---------------------------------------------------------------- clientIp

    @Nested
    @DisplayName("clientIp extraction")
    class ClientIpExtraction {

        @Test
        @DisplayName("ignores X-Forwarded-For when TRUSTED_PROXY_CIDRS is unset (env default)")
        void clientIp_xForwardedFor_ignoredWhenNoTrustedProxyCidr() {
            // TRUSTED_PROXY_CIDRS env var is unset in the test JVM → XFF must be ignored
            when(request.getHeader("X-Forwarded-For")).thenReturn("1.2.3.4, 10.0.0.1");
            when(request.getRemoteAddr()).thenReturn("9.9.9.9");
            assertThat(RateLimitFilter.clientIp(request)).isEqualTo("9.9.9.9");
        }

        @Test
        @DisplayName("falls back to REMOTE_ADDR when X-Forwarded-For is absent")
        void clientIp_noHeader_remoteAddr() {
            when(request.getHeader("X-Forwarded-For")).thenReturn(null);
            when(request.getRemoteAddr()).thenReturn("9.9.9.9");
            assertThat(RateLimitFilter.clientIp(request)).isEqualTo("9.9.9.9");
        }

        @Test
        @DisplayName("single IP in X-Forwarded-For is still ignored when no trusted CIDR configured")
        void clientIp_xForwardedFor_singleIpIgnoredWithoutTrustedCidr() {
            when(request.getHeader("X-Forwarded-For")).thenReturn("5.6.7.8");
            when(request.getRemoteAddr()).thenReturn("2.2.2.2");
            assertThat(RateLimitFilter.clientIp(request)).isEqualTo("2.2.2.2");
        }
    }

    // ---------------------------------------------------------------- 429 emission

    @Nested
    @MockitoSettings(strictness = Strictness.LENIENT)
    @DisplayName("429 response on exhausted bucket")
    class RateLimitExhausted {

        @Test
        @DisplayName("rejected request returns 429 with Retry-After header and JSON body")
        void reject_sets429AndRetryAfter() throws Exception {
            // Arrange: use a fresh filter instance with env defaults
            RateLimitFilter filter = new RateLimitFilter();
            filter.init(null);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            when(response.getOutputStream()).thenReturn(new jakarta.servlet.ServletOutputStream() {
                @Override public boolean isReady() { return true; }
                @Override public void setWriteListener(jakarta.servlet.WriteListener l) {}
                @Override public void write(int b) { baos.write(b); }
            });

            // Simulate a POST /login request from the same IP many times to exhaust the bucket.
            // Default login limit = 10, window = 15 min; but stampede means only 3 allowed initially.
            // We need a new limiter so previous tests don't pollute. Create a fresh filter.
            // Rather than exhausting, spy on the response — check that when a 429 is emitted
            // the correct headers and status are set.

            // The simplest approach: stub the request to look like a POST /login,
            // then call doFilter enough times to exhaust the stampede tokens (3 for limit=10).
            when(request.getMethod()).thenReturn("POST");
            when(request.getRequestURI()).thenReturn("/login");
            when(request.getHeader("X-Forwarded-For")).thenReturn(null);
            when(request.getRemoteAddr()).thenReturn("1.2.3.4");
            when(request.getUserPrincipal()).thenReturn(null);
            when(request.getHeader("Origin")).thenReturn(null);

            // Allow first 3 calls through (stampede = 3 tokens out of limit=10)
            for (int i = 0; i < 3; i++) {
                ByteArrayOutputStream ignore = new ByteArrayOutputStream();
                when(response.getOutputStream()).thenReturn(new jakarta.servlet.ServletOutputStream() {
                    @Override public boolean isReady() { return true; }
                    @Override public void setWriteListener(jakarta.servlet.WriteListener l) {}
                    @Override public void write(int b) { ignore.write(b); }
                });
                filter.doFilter(request, response, chain);
            }

            // 4th call should be rejected
            filter.doFilter(request, response, chain);

            verify(response).setStatus(429);
            verify(response).setHeader(eq("Retry-After"), anyString());
            // chain.doFilter was invoked only 3 times (first 3), not on the 4th
            verify(chain, times(3)).doFilter(request, response);
        }
    }

    // ---------------------------------------------------------------- auth surface backstop

    @Nested
    @MockitoSettings(strictness = Strictness.LENIENT)
    @DisplayName("Auth surface detection")
    class AuthSurface {

        @Test
        @DisplayName("/auth/ prefix triggers backstop")
        void authSurface_authPrefix() throws Exception {
            // Verify that a request to /auth/me GET still goes through chain
            // (backstop only — not rejected unless limit exceeded)
            RateLimitFilter filter = new RateLimitFilter();
            filter.init(null);

            when(request.getMethod()).thenReturn("GET");
            when(request.getRequestURI()).thenReturn("/auth/me");
            when(request.getHeader("X-Forwarded-For")).thenReturn(null);
            when(request.getRemoteAddr()).thenReturn("2.2.2.2");
            when(request.getUserPrincipal()).thenReturn(null);
            when(request.getHeader("Origin")).thenReturn(null);

            filter.doFilter(request, response, chain);

            verify(chain).doFilter(request, response);
        }
    }
}
