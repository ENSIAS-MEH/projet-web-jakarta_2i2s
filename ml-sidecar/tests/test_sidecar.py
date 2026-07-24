"""
test_sidecar.py — pytest suite for the SecBret ML sidecar.

Tests:
  1. Feature extractor unit tests (no gRPC or model required)
  2. End-to-end gRPC test: spins the server in a subprocess, makes a real
     Classify call, asserts response schema, score ∈ [0, 1],
     model_version non-empty, and latency < 500 ms.

Run from ml-sidecar/ with:
    pytest tests/test_sidecar.py -v
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import grpc
import pytest

# Ensure the repo root (ml-sidecar/) is on the path so both stub modules and
# the model package are importable.
_SIDECAR_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_SIDECAR_ROOT))

import secbret_pb2          # noqa: E402  (generated stubs must exist)
import secbret_pb2_grpc     # noqa: E402
from model.feature_extractor import (  # noqa: E402
    FEATURE_NAMES,
    NUM_FEATURES,
    extract,
)


# ===========================================================================
# Feature extractor unit tests
# ===========================================================================

class TestFeatureExtractor:
    """Unit tests for model/feature_extractor.py.

    These tests verify determinism, output shape, and boundary behaviour;
    they do not require the model file or a running server.
    """

    def _call(
        self,
        url: str = "http://example.com/page",
        rule_score: float = 0.3,
        t1: str = "",
        t2: str = "",
        t3: str = "",
    ) -> list[float]:
        return extract(url, rule_score, t1, t2, t3)

    def test_output_length(self):
        """extract() returns exactly NUM_FEATURES values."""
        features = self._call()
        assert len(features) == NUM_FEATURES

    def test_feature_names_length(self):
        assert len(FEATURE_NAMES) == NUM_FEATURES

    def test_determinism(self):
        """Same inputs always produce identical feature vectors."""
        url = "https://phish.bad-actor.example.com/login?redirect=http://real-bank.com"
        t1 = json.dumps({"sslValid": False, "domainAgeDays": 3})
        t2 = json.dumps({"formCount": 2, "externalDomainCount": 5})
        t3 = json.dumps({"kitMatched": True})
        f1 = extract(url, 0.8, t1, t2, t3)
        f2 = extract(url, 0.8, t1, t2, t3)
        assert f1 == f2

    def test_url_length_feature(self):
        """url_length feature equals len(url)."""
        url = "http://x.com/a"
        features = self._call(url=url)
        assert features[0] == float(len(url))

    def test_rule_score_passthrough(self):
        """rule_score is passed through as feature index 4."""
        features = self._call(rule_score=0.75)
        assert abs(features[4] - 0.75) < 1e-9

    def test_ssl_valid_true(self):
        """t1_ssl_valid=1 when tier1 sslValid is True."""
        t1 = json.dumps({"sslValid": True})
        features = self._call(t1=t1)
        assert features[5] == 1.0

    def test_ssl_valid_missing(self):
        """t1_ssl_valid=0 when tier1 JSON is empty."""
        features = self._call(t1="")
        assert features[5] == 0.0

    def test_domain_age_zero_when_missing(self):
        """t1_domain_age_days=0 when tier1 JSON has no domainAgeDays."""
        features = self._call(t1=json.dumps({"sslValid": True}))
        assert features[6] == 0.0

    def test_domain_age_present(self):
        t1 = json.dumps({"sslValid": True, "domainAgeDays": 1825})
        features = self._call(t1=t1)
        assert features[6] == 1825.0

    def test_form_count(self):
        t2 = json.dumps({"formCount": 3, "externalDomainCount": 2})
        features = self._call(t2=t2)
        assert features[7] == 3.0
        assert features[8] == 2.0

    def test_kit_matched_true(self):
        t3 = json.dumps({"kitMatched": True})
        features = self._call(t3=t3)
        assert features[9] == 1.0

    def test_kit_matched_false(self):
        t3 = json.dumps({"kitMatched": False})
        features = self._call(t3=t3)
        assert features[9] == 0.0

    def test_ip_host_detection(self):
        """has_ip_host=1 for IPv4 literal host."""
        features = self._call(url="http://192.168.1.1/phishing")
        assert features[3] == 1.0

    def test_non_ip_host(self):
        features = self._call(url="http://legit-bank.com/")
        assert features[3] == 0.0

    def test_malformed_json_tolerated(self):
        """Malformed tier JSON is treated as absent (0s), no exception."""
        features = extract(
            "http://example.com", 0.5,
            "{bad json", "also bad", "}}}"
        )
        assert len(features) == NUM_FEATURES

    def test_empty_url(self):
        """Empty URL does not raise; url_length=0."""
        features = self._call(url="")
        assert features[0] == 0.0

    def test_all_features_are_floats(self):
        """All features are Python floats."""
        features = self._call()
        assert all(isinstance(f, float) for f in features)


# ===========================================================================
# End-to-end gRPC test (subprocess server)
# ===========================================================================

SERVER_PORT = 50099  # use a non-default port to avoid colliding with any live sidecar


@pytest.fixture(scope="module")
def grpc_server():
    """Spin up server.py as a subprocess; yield a connected gRPC stub; tear down."""
    import os

    env = os.environ.copy()
    env["GRPC_PORT"] = str(SERVER_PORT)
    env["MODEL_PATH"] = str(_SIDECAR_ROOT / "model" / "classifier.pkl")
    env["PYTHONPATH"] = str(_SIDECAR_ROOT)

    proc = subprocess.Popen(
        [sys.executable, str(_SIDECAR_ROOT / "server.py")],
        cwd=str(_SIDECAR_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    # Wait up to 10s for the server to be ready
    channel = grpc.insecure_channel(f"localhost:{SERVER_PORT}")
    deadline = time.monotonic() + 10.0
    ready = False
    while time.monotonic() < deadline:
        try:
            grpc.channel_ready_future(channel).result(timeout=1)
            ready = True
            break
        except grpc.FutureTimeoutError:
            if proc.poll() is not None:
                out, _ = proc.communicate()
                pytest.fail(
                    f"Server exited prematurely with code {proc.returncode}.\n"
                    f"Output:\n{out.decode(errors='replace') if out else ''}"
                )

    if not ready:
        proc.terminate()
        proc.wait(timeout=5)
        pytest.fail("gRPC server did not become ready within 10 seconds")

    stub = secbret_pb2_grpc.MLScorerStub(channel)
    yield stub

    proc.terminate()
    proc.wait(timeout=10)
    channel.close()


class TestGrpcEndToEnd:
    """Integration tests against a live in-process server subprocess."""

    def _sample_request(self, **overrides) -> secbret_pb2.ClassificationRequest:
        defaults = dict(
            url="http://login.verify-paypal.bad-actor.com/update?token=abc123",
            rule_score=0.72,
            tier1_findings_json=json.dumps({
                "sslValid": False,
                "domainAgeDays": 14,
            }),
            tier2_findings_json=json.dumps({
                "formCount": 3,
                "externalDomainCount": 7,
            }),
            tier3_findings_json=json.dumps({
                "kitMatched": True,
            }),
        )
        defaults.update(overrides)
        return secbret_pb2.ClassificationRequest(**defaults)

    def test_response_schema(self, grpc_server):
        """Response has ml_score, confidence, model_version fields."""
        req = self._sample_request()
        resp = grpc_server.Classify(req, timeout=5.0)
        assert hasattr(resp, "ml_score")
        assert hasattr(resp, "confidence")
        assert hasattr(resp, "model_version")

    def test_score_in_range(self, grpc_server):
        """ml_score is in [0.0, 1.0]."""
        req = self._sample_request()
        resp = grpc_server.Classify(req, timeout=5.0)
        assert 0.0 <= resp.ml_score <= 1.0

    def test_confidence_in_range(self, grpc_server):
        """confidence is in [0.0, 1.0]."""
        req = self._sample_request()
        resp = grpc_server.Classify(req, timeout=5.0)
        assert 0.0 <= resp.confidence <= 1.0

    def test_model_version_non_empty(self, grpc_server):
        """model_version is a non-empty string."""
        req = self._sample_request()
        resp = grpc_server.Classify(req, timeout=5.0)
        assert resp.model_version and len(resp.model_version) > 0

    def test_latency_under_500ms(self, grpc_server):
        """Round-trip latency is below 500 ms."""
        req = self._sample_request()
        t_start = time.perf_counter()
        grpc_server.Classify(req, timeout=5.0)
        elapsed_ms = (time.perf_counter() - t_start) * 1000.0
        assert elapsed_ms < 500.0, f"Latency {elapsed_ms:.1f}ms exceeded 500ms budget"

    def test_benign_url_lower_score(self, grpc_server):
        """A benign-looking URL with low rule_score should produce lower ml_score
        than the high-risk phishing request (probabilistic, not a hard threshold)."""
        benign_req = self._sample_request(
            url="https://www.google.com/",
            rule_score=0.02,
            tier1_findings_json=json.dumps({"sslValid": True, "domainAgeDays": 9000}),
            tier2_findings_json=json.dumps({"formCount": 0, "externalDomainCount": 1}),
            tier3_findings_json=json.dumps({"kitMatched": False}),
        )
        phish_req = self._sample_request()  # high rule_score, kitMatched=True

        benign_resp = grpc_server.Classify(benign_req, timeout=5.0)
        phish_resp = grpc_server.Classify(phish_req, timeout=5.0)

        assert benign_resp.ml_score < phish_resp.ml_score, (
            f"Expected benign score ({benign_resp.ml_score:.4f}) < "
            f"phishing score ({phish_resp.ml_score:.4f})"
        )

    def test_empty_findings_tolerated(self, grpc_server):
        """Empty tier findings strings do not crash the server."""
        req = self._sample_request(
            tier1_findings_json="",
            tier2_findings_json="",
            tier3_findings_json="",
        )
        resp = grpc_server.Classify(req, timeout=5.0)
        assert 0.0 <= resp.ml_score <= 1.0

    def test_multiple_calls_consistent(self, grpc_server):
        """Same request returns the same score (model is deterministic)."""
        req = self._sample_request()
        r1 = grpc_server.Classify(req, timeout=5.0)
        r2 = grpc_server.Classify(req, timeout=5.0)
        assert abs(r1.ml_score - r2.ml_score) < 1e-9
        assert r1.model_version == r2.model_version
