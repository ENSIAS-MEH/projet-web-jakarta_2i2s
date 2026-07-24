package com.secbret.ai.ml;

/**
 * Response from the ML scoring client, modelling the {@code ClassificationResponse}
 * fields from the gRPC contract (Part II §7 "gRPC Contract"):
 *
 * <pre>
 * message ClassificationResponse {
 *     double ml_score      = 1;   // [0.0, 1.0]
 *     double confidence    = 2;   // [0.0, 1.0]
 *     string model_version = 3;   // e.g. "baseline-2026.07.1"
 * }
 * </pre>
 *
 * <p>When the ML sidecar is consulted successfully, {@code model_version} is logged
 * at INFO and stored in {@code secbret_analysis.model_version} (V18 migration). When
 * the model version changes between calls the real gRPC client logs WARN so operators
 * can correlate score shifts with model rollouts. The stub always returns an empty
 * Optional — this record is never produced by it — but the type is part of the stable
 * interface contract.
 *
 * @param mlScore      phishing probability in [0.0, 1.0]
 * @param confidence   model confidence in [0.0, 1.0]
 * @param modelVersion non-blank version string from the sidecar
 */
public record MlScore(double mlScore, double confidence, String modelVersion) {

    public MlScore {
        if (mlScore < 0.0 || mlScore > 1.0) {
            throw new IllegalArgumentException(
                    "mlScore must be in [0.0, 1.0], got " + mlScore);
        }
        if (confidence < 0.0 || confidence > 1.0) {
            throw new IllegalArgumentException(
                    "confidence must be in [0.0, 1.0], got " + confidence);
        }
        if (modelVersion == null || modelVersion.isBlank()) {
            throw new IllegalArgumentException("modelVersion must not be null or blank");
        }
    }
}
