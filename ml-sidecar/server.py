"""
server.py — SecBret ML sidecar: Python 3.11 gRPC server.

Listens on 0.0.0.0:50051 and implements the MLScorer.Classify RPC defined in
proto/secbret.proto.

Design decisions:
  - Model is loaded once at startup from model/classifier.pkl via joblib.
    Loading failure exits non-zero immediately (fail fast — never serve garbage).
  - Feature extraction is delegated to model.feature_extractor; inputs are
    restricted to the fields carried by ClassificationRequest.
  - Structured JSON-line logging to stdout (no external log library required;
    json.dumps keeps the format stable for log aggregators).
  - Graceful SIGTERM shutdown: the gRPC server's stop(grace=5) drains in-flight
    calls for up to 5 seconds before the process exits.
  - No per-request model loading.  The sklearn Pipeline object is thread-safe
    for concurrent predict_proba calls (it holds no mutable state after fit).
"""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
import time
from concurrent import futures
from pathlib import Path

import grpc
import joblib
import numpy as np

# Generated stubs live alongside this file (generated at Docker build time or
# by running: python -m grpc_tools.protoc -I proto --python_out=. --grpc_python_out=. proto/secbret.proto)
import secbret_pb2
import secbret_pb2_grpc
from model.feature_extractor import extract

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PORT = int(os.environ.get("GRPC_PORT", "50051"))
MAX_WORKERS = int(os.environ.get("GRPC_MAX_WORKERS", "4"))
MODEL_PATH = Path(os.environ.get("MODEL_PATH", "model/classifier.pkl"))

# ---------------------------------------------------------------------------
# Structured logging helpers
# ---------------------------------------------------------------------------

def _log(level: str, msg: str, **extra: object) -> None:
    """Emit a single JSON log line to stdout."""
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "level": level,
        "service": "secbret-ml",
        "msg": msg,
    }
    record.update(extra)
    print(json.dumps(record), flush=True)


def log_info(msg: str, **extra: object) -> None:
    _log("INFO", msg, **extra)


def log_warn(msg: str, **extra: object) -> None:
    _log("WARN", msg, **extra)


def log_error(msg: str, **extra: object) -> None:
    _log("ERROR", msg, **extra)


# ---------------------------------------------------------------------------
# Model loader
# ---------------------------------------------------------------------------

def _load_model(path: Path):
    """Load classifier.pkl.  Exits with code 1 on any failure (fail fast)."""
    log_info("Loading model", path=str(path))
    if not path.exists():
        log_error("Model file not found — cannot start", path=str(path))
        sys.exit(1)
    try:
        model = joblib.load(path)
    except Exception as exc:
        log_error("Failed to deserialise model", path=str(path), error=str(exc))
        sys.exit(1)

    # Verify the model has predict_proba (needed for confidence output)
    if not hasattr(model, "predict_proba"):
        log_error(
            "Model does not support predict_proba — cannot produce confidence scores",
            path=str(path),
        )
        sys.exit(1)

    version = getattr(model, "model_version_", "unknown")
    log_info("Model loaded", model_version=version)
    return model, version


# ---------------------------------------------------------------------------
# gRPC service implementation
# ---------------------------------------------------------------------------

class MLScorerServicer(secbret_pb2_grpc.MLScorerServicer):
    """Implements MLScorer.Classify.

    Per the spec §7:
      - Input: url, rule_score, tier1/2/3_findings_json
      - Output: ml_score (0.0–1.0), confidence, model_version
      - Latency budget: caller timeout is 2 seconds; handler must be fast (<100ms typical).
    """

    def __init__(self, model, model_version: str) -> None:
        self._model = model
        self._model_version = model_version

    def Classify(
        self,
        request: secbret_pb2.ClassificationRequest,
        context: grpc.ServicerContext,
    ) -> secbret_pb2.ClassificationResponse:
        t_start = time.perf_counter()

        try:
            features = extract(
                url=request.url,
                rule_score=request.rule_score,
                tier1_findings_json=request.tier1_findings_json,
                tier2_findings_json=request.tier2_findings_json,
                tier3_findings_json=request.tier3_findings_json,
            )
        except Exception as exc:
            log_error(
                "Feature extraction failed",
                url=request.url[:100],  # L-6: log a truncated URL, not the full value
                error=str(exc),
            )
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Feature extraction error: {exc}")
            return secbret_pb2.ClassificationResponse()

        X = np.array([features], dtype=float)

        try:
            proba = self._model.predict_proba(X)[0]  # shape: (2,) [P(benign), P(phishing)]
        except Exception as exc:
            log_error(
                "Model prediction failed",
                url=request.url[:100],  # L-6: log a truncated URL, not the full value
                error=str(exc),
            )
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Prediction error: {exc}")
            return secbret_pb2.ClassificationResponse()

        # proba[1] = P(phishing) → ml_score; confidence = max(proba)
        ml_score = float(proba[1])
        confidence = float(np.max(proba))

        elapsed_ms = (time.perf_counter() - t_start) * 1000.0

        # Log at INFO on every call; include model_version so operators can
        # correlate score shifts with model rollouts (spec §7 ML Model Version Tracking).
        log_info(
            "Classify",
            url=request.url[:100],  # L-6: log a truncated URL, not the full value
            ml_score=round(ml_score, 4),
            confidence=round(confidence, 4),
            model_version=self._model_version,
            elapsed_ms=round(elapsed_ms, 2),
        )

        return secbret_pb2.ClassificationResponse(
            ml_score=ml_score,
            confidence=confidence,
            model_version=self._model_version,
        )


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------

def serve() -> None:
    model, model_version = _load_model(MODEL_PATH)

    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=MAX_WORKERS),
        options=[
            ("grpc.max_receive_message_length", 4 * 1024 * 1024),  # 4 MB
        ],
    )
    secbret_pb2_grpc.add_MLScorerServicer_to_server(
        MLScorerServicer(model, model_version), server
    )

    bind_addr = f"0.0.0.0:{PORT}"
    server.add_insecure_port(bind_addr)
    server.start()
    log_info("gRPC server started", addr=bind_addr, model_version=model_version)

    # Graceful SIGTERM: drain in-flight calls for up to 5 seconds.
    def _handle_sigterm(signum, frame):  # noqa: ANN001
        log_info("SIGTERM received — draining server (grace=5s)")
        server.stop(grace=5)
        log_info("Server stopped")
        sys.exit(0)

    signal.signal(signal.SIGTERM, _handle_sigterm)

    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        log_info("Keyboard interrupt — stopping server")
        server.stop(grace=2)


if __name__ == "__main__":
    serve()
