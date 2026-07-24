package com.secbret.ai.ml;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link StubMlScoringClient}: always returns empty,
 * routes through the circuit breaker, and rejects null input.
 */
@DisplayName("StubMlScoringClient")
class StubMlScoringClientTest {

    MutableClock clock;
    MlCircuitBreaker breaker;
    StubMlScoringClient stub;

    @BeforeEach
    void setUp() {
        clock   = new MutableClock(1_000_000L);
        breaker = new MlCircuitBreaker(clock, 3, 10_000L, 5_000L);
        stub    = new StubMlScoringClient(breaker);
    }

    @Test
    @DisplayName("classify always returns empty (UNAVAILABLE)")
    void alwaysReturnsEmpty() {
        MlScoreRequest req = MlScoreRequest.ofRulesOnly("https://example.com", 0.5);
        Optional<MlScore> result = stub.classify(req);
        assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("multiple calls all return empty")
    void multipleCallsAllReturnEmpty() {
        MlScoreRequest req = MlScoreRequest.ofRulesOnly("https://phish.example.com", 0.3);
        for (int i = 0; i < 10; i++) {
            assertThat(stub.classify(req)).isEmpty();
        }
    }

    @Test
    @DisplayName("stub never opens the circuit breaker (absence ≠ failure)")
    void stubNeverOpensBreaker() {
        MlScoreRequest req = MlScoreRequest.ofRulesOnly("https://example.com", 0.5);
        // Fire many calls — the stub returns empty without throwing,
        // so the breaker must remain CLOSED.
        for (int i = 0; i < 20; i++) {
            stub.classify(req);
        }
        assertThat(breaker.currentState()).isEqualTo(MlCircuitBreaker.State.CLOSED);
    }

    @Test
    @DisplayName("rejects null request")
    void rejectsNullRequest() {
        assertThatThrownBy(() -> stub.classify(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("breaker OPEN still short-circuits (returns empty) even for stub")
    void breakerOpenShortCircuits() {
        // Manually open the breaker by driving failures through a raw delegate.
        for (int i = 0; i < 3; i++) {
            breaker.execute(() -> { throw new RuntimeException("force open"); });
        }
        assertThat(breaker.currentState()).isEqualTo(MlCircuitBreaker.State.OPEN);

        // Stub classify must still return empty (breaker's short-circuit path).
        MlScoreRequest req = MlScoreRequest.ofRulesOnly("https://example.com", 0.5);
        assertThat(stub.classify(req)).isEmpty();
    }
}
