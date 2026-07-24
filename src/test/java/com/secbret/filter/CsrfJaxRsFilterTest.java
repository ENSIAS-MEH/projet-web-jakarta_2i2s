package com.secbret.filter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Response;
import org.eclipse.krazo.security.CsrfToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.security.Principal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link CsrfJaxRsFilter}.
 *
 * Covers: safe methods exempt, unauthenticated exempt, missing token → 403,
 * wrong token → 403, valid token → allowed.
 */
@ExtendWith(MockitoExtension.class)
class CsrfJaxRsFilterTest {

    @Mock ContainerRequestContext ctx;
    @Mock HttpServletRequest      httpRequest;
    @Mock HttpSession             session;
    @Mock Principal               principal;

    private CsrfJaxRsFilter filter;

    private static final String VALID_TOKEN = "test-csrf-token-abc123";

    /** Krazo stores a CsrfToken OBJECT under this key — never a plain String. */
    private static final String KRAZO_SESSION_KEY =
            "org.eclipse.krazo.security.SessionCsrfTokenStrategy.TOKEN";
    private static final CsrfToken SESSION_TOKEN =
            new CsrfToken("X-CSRF-TOKEN", "_csrf", VALID_TOKEN);

    @BeforeEach
    void setUp() {
        filter = new CsrfJaxRsFilter();
        filter.httpRequest = httpRequest; // package-private field injection
    }

    // ---------------------------------------------------------------- safe methods

    @Nested
    @DisplayName("Safe methods (GET/HEAD/OPTIONS) are exempt")
    class SafeMethods {

        @Test
        @DisplayName("GET request passes without CSRF check")
        void get_exempt() throws Exception {
            when(ctx.getMethod()).thenReturn("GET");
            filter.filter(ctx);
            verify(ctx, never()).abortWith(any());
        }

        @Test
        @DisplayName("HEAD request passes without CSRF check")
        void head_exempt() throws Exception {
            when(ctx.getMethod()).thenReturn("HEAD");
            filter.filter(ctx);
            verify(ctx, never()).abortWith(any());
        }

        @Test
        @DisplayName("OPTIONS request passes without CSRF check")
        void options_exempt() throws Exception {
            when(ctx.getMethod()).thenReturn("OPTIONS");
            filter.filter(ctx);
            verify(ctx, never()).abortWith(any());
        }
    }

    // ---------------------------------------------------------------- unauthenticated

    @Test
    @DisplayName("unauthenticated POST passes CSRF filter (rejected at @RolesAllowed instead)")
    void unauthenticated_exempt() throws Exception {
        when(ctx.getMethod()).thenReturn("POST");
        when(httpRequest.getUserPrincipal()).thenReturn(null);
        filter.filter(ctx);
        verify(ctx, never()).abortWith(any());
    }

    // ---------------------------------------------------------------- missing token

    @Nested
    @DisplayName("Missing or invalid CSRF token → 403")
    class InvalidToken {

        @BeforeEach
        void authenticatedSetup() {
            when(ctx.getMethod()).thenReturn("POST");
            when(httpRequest.getUserPrincipal()).thenReturn(principal);
            when(httpRequest.getSession(false)).thenReturn(session);
            // Krazo-shaped session state: CsrfToken object under the strategy key
            when(session.getAttribute(KRAZO_SESSION_KEY)).thenReturn(SESSION_TOKEN);
        }

        @Test
        @DisplayName("missing X-CSRF-Token header → 403")
        void missingHeader_403() throws Exception {
            when(ctx.getHeaderString(CsrfJaxRsFilter.CSRF_HEADER)).thenReturn(null);
            filter.filter(ctx);

            ArgumentCaptor<Response> captor = ArgumentCaptor.forClass(Response.class);
            verify(ctx).abortWith(captor.capture());
            assertThat(captor.getValue().getStatus()).isEqualTo(403);
        }

        @Test
        @DisplayName("blank X-CSRF-Token header → 403")
        void blankHeader_403() throws Exception {
            when(ctx.getHeaderString(CsrfJaxRsFilter.CSRF_HEADER)).thenReturn("   ");
            filter.filter(ctx);
            verify(ctx).abortWith(argThat(r -> r.getStatus() == 403));
        }

        @Test
        @DisplayName("wrong X-CSRF-Token value → 403")
        void wrongToken_403() throws Exception {
            when(ctx.getHeaderString(CsrfJaxRsFilter.CSRF_HEADER)).thenReturn("wrong-token");
            filter.filter(ctx);
            verify(ctx).abortWith(argThat(r -> r.getStatus() == 403));
        }
    }

    // ---------------------------------------------------------------- valid token

    @Test
    @DisplayName("valid X-CSRF-Token matching session token → request proceeds")
    void validToken_allowed() throws Exception {
        when(ctx.getMethod()).thenReturn("POST");
        when(httpRequest.getUserPrincipal()).thenReturn(principal);
        when(httpRequest.getSession(false)).thenReturn(session);
        when(session.getAttribute(KRAZO_SESSION_KEY)).thenReturn(SESSION_TOKEN);
        when(ctx.getHeaderString(CsrfJaxRsFilter.CSRF_HEADER)).thenReturn(VALID_TOKEN);

        filter.filter(ctx);

        verify(ctx, never()).abortWith(any());
    }

    // ---------------------------------------------------------------- no session

    @Test
    @DisplayName("authenticated request with no session → 403")
    void noSession_403() throws Exception {
        when(ctx.getMethod()).thenReturn("DELETE");
        when(httpRequest.getUserPrincipal()).thenReturn(principal);
        when(httpRequest.getSession(false)).thenReturn(null);

        filter.filter(ctx);

        verify(ctx).abortWith(argThat(r -> r.getStatus() == 403));
    }

    // ---------------------------------------------------------------- PUT/DELETE also enforced

    @Test
    @DisplayName("DELETE with valid token → allowed")
    void delete_validToken_allowed() throws Exception {
        when(ctx.getMethod()).thenReturn("DELETE");
        when(httpRequest.getUserPrincipal()).thenReturn(principal);
        when(httpRequest.getSession(false)).thenReturn(session);
        when(session.getAttribute(KRAZO_SESSION_KEY)).thenReturn(SESSION_TOKEN);
        when(ctx.getHeaderString(CsrfJaxRsFilter.CSRF_HEADER)).thenReturn(VALID_TOKEN);

        filter.filter(ctx);

        verify(ctx, never()).abortWith(any());
    }
}
