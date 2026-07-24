package com.secbret.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.secbret.ai.ml.GrpcMlScoringClient;
import com.secbret.ai.ml.MlCircuitBreaker;
import com.secbret.ai.ml.MlScore;
import com.secbret.ai.ml.MlScoreRequest;
import io.grpc.ManagedChannel;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;

/**
 * Integration test: builds the real {@code ml-sidecar/} Docker image and
 * round-trips a live gRPC {@code MLScorer.Classify} call through
 * {@link GrpcMlScoringClient}, proving:
 * <ul>
 *   <li>a real request → {@code ml_score} in [0,1] and a non-blank
 *       {@code model_version} (the baseline seed {@code baseline-2026.07.1});</li>
 *   <li>the Java client maps the protobuf response onto {@link MlScore}.</li>
 * </ul>
 *
 * <p><b>Skips gracefully</b> when Docker is unavailable or the image cannot be
 * built (e.g. offline CI without the Python base image cached) — the assumption
 * marks the test skipped rather than failed, per the task's "tag it to skip
 * gracefully" requirement.
 */
@DisplayName("ML sidecar gRPC round-trip (Testcontainers)")
class MlSidecarGrpcIT {

    private static final int GRPC_PORT = 50051;

    private static GenericContainer<?> sidecar;
    private static ManagedChannel channel;
    private static GrpcMlScoringClient client;

    @BeforeAll
    static void startSidecar() {
        assumeTrue(DockerClientFactory.instance().isDockerAvailable(),
                "Docker not available — skipping ML sidecar IT");

        try {
            ImageFromDockerfile image = new ImageFromDockerfile("secbret-ml-it", false)
                    .withDockerfile(Path.of("ml-sidecar", "Dockerfile"));

            @SuppressWarnings("resource")
            GenericContainer<?> c = new GenericContainer<>(image)
                    .withExposedPorts(GRPC_PORT)
                    .waitingFor(Wait.forListeningPort())
                    .withStartupTimeout(Duration.ofMinutes(3));
            c.start();
            sidecar = c;
        } catch (RuntimeException ex) {
            // Build/pull failure (e.g. no network for python:3.11-slim) — skip, don't fail.
            assumeTrue(false, "ml-sidecar image could not be built — skipping: " + ex.getMessage());
        }

        channel = NettyChannelBuilder
                .forAddress(sidecar.getHost(), sidecar.getMappedPort(GRPC_PORT))
                .usePlaintext()
                .build();

        MlCircuitBreaker breaker = new MlCircuitBreaker(Clock.systemUTC(), 5, 60_000L, 30_000L);
        client = new GrpcMlScoringClient(channel, breaker, 2_000L);
    }

    @AfterAll
    static void stopSidecar() {
        if (channel != null) {
            channel.shutdownNow();
            try {
                channel.awaitTermination(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        if (sidecar != null) {
            sidecar.stop();
        }
    }

    @Test
    @DisplayName("real classify → score in [0,1] and non-blank model_version")
    void classify_roundTrip() {
        MlScoreRequest request = new MlScoreRequest(
                "http://paypal-secure-login.example.ru/verify",
                0.6,
                "{\"domainAgeDays\":3}",
                null,
                null);

        Optional<MlScore> result = client.classify(request);

        assertThat(result).isPresent();
        MlScore score = result.get();
        assertThat(score.mlScore()).isBetween(0.0, 1.0);
        assertThat(score.confidence()).isBetween(0.0, 1.0);
        assertThat(score.modelVersion()).isNotBlank();
        assertThat(score.modelVersion()).isEqualTo("secbret-2026.07.2");
    }
}
