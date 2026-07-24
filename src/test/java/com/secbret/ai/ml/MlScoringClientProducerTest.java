package com.secbret.ai.ml;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link MlScoringClientProducer} selection (§6): stub when
 * {@code ML_SIDECAR_HOST} is absent, gRPC client when configured. The env is
 * stubbed via an overridden {@code getenv} so no real channel needs a reachable
 * host — the produced gRPC client is built lazily with an unconnected channel.
 */
@DisplayName("MlScoringClientProducer selection")
class MlScoringClientProducerTest {

    private MlCircuitBreaker breaker;
    private TestProducer producer;

    static final class TestProducer extends MlScoringClientProducer {
        final Map<String, String> env = new HashMap<>();
        TestProducer(MlCircuitBreaker breaker) { super(breaker); }
        @Override protected String getenv(String name) { return env.get(name); }
    }

    private TestProducer newProducer() {
        breaker = new MlCircuitBreaker(Clock.systemUTC(), 5, 60_000L, 30_000L);
        return new TestProducer(breaker);
    }

    @AfterEach
    void tearDown() {
        if (producer != null) {
            producer.env.clear();
            // release any channel the gRPC branch created
            invokeShutdown(producer);
        }
    }

    @Test
    @DisplayName("ML_SIDECAR_HOST unset → StubMlScoringClient")
    void unset_producesStub() {
        producer = newProducer();
        MlScoringClient client = producer.mlScoringClient();
        assertThat(client).isInstanceOf(StubMlScoringClient.class);
    }

    @Test
    @DisplayName("ML_SIDECAR_HOST blank → StubMlScoringClient")
    void blank_producesStub() {
        producer = newProducer();
        producer.env.put("ML_SIDECAR_HOST", "   ");
        assertThat(producer.mlScoringClient()).isInstanceOf(StubMlScoringClient.class);
    }

    @Test
    @DisplayName("ML_SIDECAR_HOST set → GrpcMlScoringClient")
    void set_producesGrpcClient() {
        producer = newProducer();
        producer.env.put("ML_SIDECAR_HOST", "secbret-ml:50051");
        MlScoringClient client = producer.mlScoringClient();
        assertThat(client).isInstanceOf(GrpcMlScoringClient.class);
    }

    private static void invokeShutdown(MlScoringClientProducer p) {
        try {
            var m = MlScoringClientProducer.class.getDeclaredMethod("shutdown");
            m.setAccessible(true);
            m.invoke(p);
        } catch (ReflectiveOperationException ignored) {
            // best-effort cleanup in tests
        }
    }
}
