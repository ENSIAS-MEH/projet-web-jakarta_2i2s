package com.secbret.ai.ml;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import java.time.Clock;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import secbret.ml.MLScorerGrpc;
import secbret.ml.Secbret.ClassificationRequest;
import secbret.ml.Secbret.ClassificationResponse;

/**
 * Unit tests for {@link GrpcMlScoringClient} — the gRPC blocking stub is mocked
 * so the mapping and error paths are exercised without a live channel. The real
 * end-to-end round-trip against the sidecar image is covered by
 * {@code MlSidecarGrpcIT} (Testcontainers).
 *
 * <p>Verifies: (a) success maps {@code ClassificationResponse} → {@link MlScore}
 * incl. {@code model_version}; (b) {@code DEADLINE_EXCEEDED} degrades to empty and
 * is recorded as a circuit-breaker failure; (c) {@code UNAVAILABLE} degrades to
 * empty (rules-only fallback).
 */
@DisplayName("GrpcMlScoringClient")
class GrpcMlScoringClientTest {

    private MLScorerGrpc.MLScorerBlockingStub stub;
    private MlCircuitBreaker breaker;
    private GrpcMlScoringClient client;

    private static final MlScoreRequest REQUEST =
            MlScoreRequest.ofRulesOnly("https://example.test/login", 0.42);

    @BeforeEach
    void setUp() {
        stub = mock(MLScorerGrpc.MLScorerBlockingStub.class);
        // Mockito mocks of the stub must also return a mock from withDeadline(...)
        // so the chained call resolves; wire it back to the same mock.
        when(stub.withDeadline(any())).thenReturn(stub);
        // Real breaker with a low threshold + fixed clock so we can assert
        // failure accounting deterministically.
        breaker = new MlCircuitBreaker(Clock.systemUTC(), 5, 60_000L, 30_000L);
        client = new GrpcMlScoringClient(stub, breaker, 2_000L);
    }

    @Nested
    @DisplayName("success mapping")
    class Success {

        @Test
        @DisplayName("maps ml_score, confidence and model_version onto MlScore")
        void mapsResponse() {
            when(stub.classify(any(ClassificationRequest.class))).thenReturn(
                    ClassificationResponse.newBuilder()
                            .setMlScore(0.73)
                            .setConfidence(0.88)
                            .setModelVersion("baseline-2026.07.1")
                            .build());

            Optional<MlScore> result = client.classify(REQUEST);

            assertThat(result).isPresent();
            assertThat(result.get().mlScore()).isEqualTo(0.73);
            assertThat(result.get().confidence()).isEqualTo(0.88);
            assertThat(result.get().modelVersion()).isEqualTo("baseline-2026.07.1");
            // A success must not open the breaker.
            assertThat(breaker.currentState()).isEqualTo(MlCircuitBreaker.State.CLOSED);
        }
    }

    @Nested
    @DisplayName("failure handling")
    class Failures {

        @Test
        @DisplayName("DEADLINE_EXCEEDED → empty and records a breaker failure")
        void deadlineExceeded_recordsFailure() {
            when(stub.classify(any(ClassificationRequest.class)))
                    .thenThrow(new StatusRuntimeException(Status.DEADLINE_EXCEEDED));

            Optional<MlScore> result = client.classify(REQUEST);

            assertThat(result).isEmpty();
            // Exactly one failure recorded in the window (not yet enough to OPEN).
            assertThat(breaker.windowFailureCount(System.currentTimeMillis())).isEqualTo(1);
            assertThat(breaker.currentState()).isEqualTo(MlCircuitBreaker.State.CLOSED);
        }

        @Test
        @DisplayName("UNAVAILABLE → empty (rules-only fallback)")
        void unavailable_fallsBack() {
            when(stub.classify(any(ClassificationRequest.class)))
                    .thenThrow(new StatusRuntimeException(Status.UNAVAILABLE));

            assertThat(client.classify(REQUEST)).isEmpty();
        }

        @Test
        @DisplayName("five consecutive failures OPEN the breaker; further calls short-circuit")
        void fiveFailures_openBreaker() {
            when(stub.classify(any(ClassificationRequest.class)))
                    .thenThrow(new StatusRuntimeException(Status.UNAVAILABLE));

            for (int i = 0; i < 5; i++) {
                assertThat(client.classify(REQUEST)).isEmpty();
            }
            assertThat(breaker.currentState()).isEqualTo(MlCircuitBreaker.State.OPEN);
        }
    }

    @Test
    @DisplayName("rejects null request")
    void nullRequest_throws() {
        org.assertj.core.api.Assertions
                .assertThatThrownBy(() -> client.classify(null))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
