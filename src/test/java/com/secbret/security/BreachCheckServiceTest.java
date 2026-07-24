package com.secbret.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for HIBP k-anonymity breach check (Part III §HIBP Password Check).
 * Verifies fail-open behaviour on timeout, network error, and non-200 response.
 */
@SuppressWarnings("unchecked")
class BreachCheckServiceTest {

    private BreachCheckService serviceWith(HttpClient client) {
        return new BreachCheckService("https://hibp.test", 3000, client);
    }

    @Test
    @DisplayName("matching suffix in HIBP response → isBreached = true")
    void matchingSuffix_returnsTrue() throws Exception {
        // SHA-1 of "password" = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        // prefix = 5BAA6, suffix = 1E4C9B93F3F0682250B6CF8331B7EE68FD8
        String password = "password";
        String suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";
        String body = "0000000000000000000000000000000000000:1\r\n" + suffix + ":3861493\r\n";

        HttpClient client = mock(HttpClient.class);
        HttpResponse<String> resp = mock(HttpResponse.class);
        when(resp.statusCode()).thenReturn(200);
        when(resp.body()).thenReturn(body);
        when(client.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(resp);

        assertThat(serviceWith(client).isBreached(password)).isTrue();
    }

    @Test
    @DisplayName("suffix not in HIBP response → isBreached = false")
    void notMatchingSuffix_returnsFalse() throws Exception {
        HttpClient client = mock(HttpClient.class);
        HttpResponse<String> resp = mock(HttpResponse.class);
        when(resp.statusCode()).thenReturn(200);
        when(resp.body()).thenReturn("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\r\n");
        when(client.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(resp);

        assertThat(serviceWith(client).isBreached("this-is-a-unique-not-breached-pw-xyz")).isFalse();
    }

    @Test
    @DisplayName("timeout → fail-open (returns false, no exception)")
    void timeout_failOpen() throws Exception {
        HttpClient client = mock(HttpClient.class);
        when(client.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new HttpTimeoutException("timed out"));

        assertThat(serviceWith(client).isBreached("anypassword123")).isFalse();
    }

    @Test
    @DisplayName("IOException (unreachable) → fail-open (returns false)")
    void ioException_failOpen() throws Exception {
        HttpClient client = mock(HttpClient.class);
        when(client.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new IOException("connection refused"));

        assertThat(serviceWith(client).isBreached("anypassword123")).isFalse();
    }

    @Test
    @DisplayName("non-200 response → fail-open (returns false)")
    void non200Response_failOpen() throws Exception {
        HttpClient client = mock(HttpClient.class);
        HttpResponse<String> resp = mock(HttpResponse.class);
        when(resp.statusCode()).thenReturn(503);
        when(client.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(resp);

        assertThat(serviceWith(client).isBreached("anypassword123")).isFalse();
    }

    @Test
    @DisplayName("null password → false without calling HIBP")
    void nullPassword_returnsFalse() {
        HttpClient client = mock(HttpClient.class);
        assertThat(serviceWith(client).isBreached(null)).isFalse();
    }

    @Test
    @DisplayName("case-insensitive suffix match")
    void caseInsensitiveSuffixMatch() throws Exception {
        // SHA-1 of "password" suffix in lowercase
        String suffix = "1e4c9b93f3f0682250b6cf8331b7ee68fd8";
        String body = suffix.toUpperCase() + ":100\r\n";

        HttpClient client = mock(HttpClient.class);
        HttpResponse<String> resp = mock(HttpResponse.class);
        when(resp.statusCode()).thenReturn(200);
        when(resp.body()).thenReturn(body);
        when(client.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(resp);

        assertThat(serviceWith(client).isBreached("password")).isTrue();
    }
}
