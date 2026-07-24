"""
train.py — SecBret ML sidecar: train the phishing classifier on REAL data.

Phase 7 / task 26: replaces the synthetic baseline (train_baseline.py) with a
model trained on the public PhiUSIIL Phishing URL Dataset (UCI #967, CC BY 4.0).

Feature parity is guaranteed by reusing the SAME feature_extractor.extract()
that server.py uses at inference time: for every dataset row we synthesise the
exact request fields (url + rule_score + tier1/2/3 findings JSON) the gRPC
service receives, then extract the identical 10-feature vector. This eliminates
train/serve skew — no feature is computed one way here and another way in prod.

Dataset provenance:
  PhiUSIIL Phishing URL Dataset, UCI ML Repository #967 (CC BY 4.0).
  235,795 rows: 134,850 legitimate + 100,945 phishing.
  IMPORTANT: dataset label==1 is LEGITIMATE, label==0 is phishing.
  We invert to SecBret's convention (y==1 == phishing) below.

Reproducibility:
  - Fixed seed (SEED below).
  - Held-out stratified split (test_size=0.2).
  - One command:  python model/train.py   (add --sample to use the tiny
    committed sample.csv instead of the full download).

Usage:
    bash data/download_dataset.sh        # once; fetches the raw CSV (~55 MB)
    python model/train.py                # trains on the full dataset
    python model/train.py --sample       # trains on data/sample.csv (200 rows)

Outputs:
    model/classifier.pkl   — joblib-serialised Pipeline with .model_version_
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

# Import the exact extractor the server uses (train/serve feature parity).
_MODEL_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_MODEL_DIR.parent))
from model.feature_extractor import NUM_FEATURES, extract  # noqa: E402

SEED = 42
MODEL_VERSION = "secbret-2026.07.2"

_FULL_CSV = _MODEL_DIR.parent / "data" / "PhiUSIIL_Phishing_URL_Dataset.csv"
_SAMPLE_CSV = _MODEL_DIR.parent / "data" / "sample.csv"


def _to_tier_json(row: dict[str, str]) -> tuple[float, str, str, str]:
    """Map one dataset row to the (rule_score, tier1, tier2, tier3) request fields.

    The dataset carries page-scan signals that line up with SecBret's tier
    findings, so we reconstruct the request the way the pipeline would deliver it:
      - tier1.sslValid           <- IsHTTPS
      - tier2.formCount          <- HasSubmitButton + HasExternalFormSubmit (0/1/2)
      - tier2.externalDomainCount<- NoOfExternalRef (proxy for external domains)
      - tier3.kitMatched         <- HasPasswordField (phishing kits harvest creds)
    domainAgeDays is not in the dataset, so it stays absent (extractor -> 0),
    exactly as it would be when the whois enrichment is missing in prod.
    rule_score is unknown offline -> 0.0 (neutral), so the model must earn its
    signal from URL structure + page findings, not from the rule engine's score.
    """
    def _i(key: str) -> int:
        try:
            return int(float(row.get(key, "0") or 0))
        except ValueError:
            return 0

    ssl_valid = _i("IsHTTPS") == 1
    form_count = _i("HasSubmitButton") + _i("HasExternalFormSubmit")
    external_cnt = _i("NoOfExternalRef")
    kit_matched = _i("HasPasswordField") == 1

    t1 = json.dumps({"sslValid": ssl_valid})
    t2 = json.dumps({"formCount": form_count, "externalDomainCount": external_cnt})
    t3 = json.dumps({"kitMatched": kit_matched})
    return 0.0, t1, t2, t3


def _load_features(csv_path: Path) -> tuple[np.ndarray, np.ndarray]:
    """Read the dataset and produce (X, y) via the production feature_extractor.

    y == 1 means phishing (SecBret convention); dataset label==0 is phishing,
    so y = 1 - dataset_label.
    """
    X_rows: list[list[float]] = []
    y_rows: list[int] = []
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row.get("URL", "")
            if not url:
                continue
            rule_score, t1, t2, t3 = _to_tier_json(row)
            feats = extract(url, rule_score, t1, t2, t3)
            X_rows.append(feats)
            # dataset: 1==legit, 0==phishing  ->  y: 1==phishing
            y_rows.append(1 - int(row["label"]))

    if not X_rows:
        raise SystemExit(f"No usable rows in {csv_path}")
    X = np.asarray(X_rows, dtype=float)
    y = np.asarray(y_rows, dtype=int)
    assert X.shape[1] == NUM_FEATURES, f"feature width {X.shape[1]} != {NUM_FEATURES}"
    return X, y


def main() -> None:
    ap = argparse.ArgumentParser(description="Train the SecBret phishing classifier.")
    ap.add_argument(
        "--sample",
        action="store_true",
        help="Train on the committed 200-row sample.csv instead of the full CSV.",
    )
    args = ap.parse_args()

    if args.sample:
        csv_path = _SAMPLE_CSV
    elif _FULL_CSV.exists():
        csv_path = _FULL_CSV
    else:
        print(
            f"[train] Full dataset not found at {_FULL_CSV}.\n"
            f"[train] Run: bash data/download_dataset.sh   (or pass --sample)",
            file=sys.stderr,
        )
        sys.exit(2)

    print(f"[train] Seed: {SEED}")
    print(f"[train] Model version: {MODEL_VERSION}")
    print(f"[train] Dataset: {csv_path.name}")

    X, y = _load_features(csv_path)
    n_phish = int((y == 1).sum())
    n_benign = int((y == 0).sum())
    print(f"[train] Rows: {len(y)}  (phishing={n_phish}, benign={n_benign})")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=SEED, stratify=y
    )

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(
            C=1.0,
            max_iter=1000,
            random_state=SEED,
            solver="lbfgs",
            class_weight="balanced",  # dataset is 57/43; keep recall honest
        )),
    ])
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]

    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_proba)

    print(f"\n[train] Held-out metrics ({len(y_test)} samples):")
    print(f"[train]   precision : {precision:.4f}")
    print(f"[train]   recall    : {recall:.4f}")
    print(f"[train]   f1        : {f1:.4f}")
    print(f"[train]   roc_auc   : {roc_auc:.4f}")
    print("\n[train] Classification report:")
    print(classification_report(y_test, y_pred, target_names=["benign", "phishing"]))

    pipeline.model_version_ = MODEL_VERSION
    out_path = _MODEL_DIR / "classifier.pkl"
    joblib.dump(pipeline, out_path)
    print(f"[train] Saved: {out_path} ({out_path.stat().st_size} bytes)")
    print(f"[train] model_version = {MODEL_VERSION}")


if __name__ == "__main__":
    main()
