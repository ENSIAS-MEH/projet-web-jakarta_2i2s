# SecBret ML Sidecar

Python gRPC service that scores URLs for phishing likelihood. Consulted by the
Java rules engine only in the uncertain band (`0.05 < ruleScore < 0.95`);
at the extremes, and whenever the sidecar is down, the rules decide alone
(`combined = ruleScore` — degraded, never an error). When consulted, the blend
is `combined = 0.4·ruleScore + 0.6·mlScore`.

```
Tier 1–3 findings → RulesEngine → (uncertain band?) → gRPC Classify → blend → verdict band
```

Failure handling on the Java side (`GrpcMlScoringClient` + `MlCircuitBreaker`):
per-call deadline `ML_TIMEOUT_MS` (default 2000 ms), no retry; 5 errors/60 s
opens the breaker for 30 s, then a single half-open probe.

## classifier.pkl

`model/classifier.pkl` is the trained model, loaded by `server.py` at startup.

| Property | Value |
|---|---|
| Pipeline | `StandardScaler` → `LogisticRegression(class_weight=balanced)`, seed 42 |
| Version | `secbret-2026.07.2`, embedded in the pickle as `clf.model_version_` |
| Dataset | PhiUSIIL Phishing URL (UCI #967, CC BY 4.0, 235,795 URLs) |
| Held-out metrics (stratified 20 %, n=47,159) | precision 0.9634 · recall 0.9796 · F1 0.9715 · ROC-AUC 0.9975 |
| Input | positional vector of **10 features** from `model/feature_extractor.py` |
| Pickle compat | pinned `scikit-learn==1.5.0` (`requirements.txt`) — train in a venv built from that file or the container may unpickle garbage silently |

The `model_version` travels on every gRPC response and is persisted per
analysis (`secbret_analysis.model_version`); the Java client WARNs when it
changes, so any verdict is traceable to the exact model that produced it.

### The 10 features (index is the contract)

| # | Feature | Source |
|---|---|---|
| 0 | `url_length` | URL string |
| 1 | `url_entropy` (Shannon) | URL string |
| 2 | `subdomain_depth` | URL string |
| 3 | `has_ip_host` | URL string |
| 4 | `rule_score` | rules engine (0.0 at train time) |
| 5 | `t1_ssl_valid` | tier1 JSON `sslValid` |
| 6 | `t1_domain_age_days` | tier1 JSON |
| 7 | `t2_form_count` | tier2 JSON `formCount` |
| 8 | `t2_external_domain_cnt` | tier2 JSON `externalDomainCount` |
| 9 | `t3_kit_matched` | tier3 JSON `kitMatched` |

`extract()` is used **identically at train and serve time** (`train.py`
reconstructs the gRPC request fields per dataset row — zero train/serve skew).
Any change to `extract()` silently invalidates the current pkl: a feature
change always forces a retrain and a version bump.

## Layout

| File | Role |
|---|---|
| `proto/secbret.proto` | gRPC contract — `MLScorer.Classify(ClassificationRequest) → ClassificationResponse`. Single source of truth; Java stubs generated at Maven build, Python stubs in the Docker build. |
| `server.py` | gRPC server on `:50051`; loads `/app/model/classifier.pkl`, logs `model_version`. |
| `model/feature_extractor.py` | `extract(url, rule_score, t1_json, t2_json, t3_json) → list[float]` (total: missing/malformed JSON → defaults, never raises). |
| `model/train.py` | Dataset → features → scaler+LR → `classifier.pkl` (prints held-out P/R/F1/AUC). |
| `data/download_dataset.sh` | Fetches PhiUSIIL. Raw CSV is gitignored; a 200-row `sample.csv` is committed for offline smoke-retrains. |
| `tests/` | 25 pytest (17 extractor + 8 gRPC e2e). |

## Retrain

```bash
bash ml-sidecar/data/download_dataset.sh        # raw data stays out of git
# edit model/train.py: bump MODEL_VERSION = 'secbret-YYYY.MM.rev'
cd ml-sidecar && python model/train.py          # writes classifier.pkl, prints metrics
python -m pytest tests/ -q                      # 25 green
# update the version assert in src/test/java/com/secbret/integration/MlSidecarGrpcIT.java
mvn verify                                      # IT rebuilds the sidecar image via Testcontainers
docker compose build secbret-ml && docker compose up -d secbret-ml
```

Rules: monotonic version string; seed 42 + stratified 80/20 split; keep the
classifier boring (scaler + LogisticRegression) unless a PR argues otherwise.
Label trap: PhiUSIIL `label==1` means **legitimate** — `train.py` inverts to
`y==1 == phishing`; check the convention of any new dataset first.

## Configuration (Java side, read at Payara startup)

| Var | Default | Effect |
|---|---|---|
| `ML_SIDECAR_HOST` | unset | set (`secbret-ml:50051`) ⇒ real gRPC client; unset ⇒ stub client, rules-only |
| `ML_TIMEOUT_MS` | 2000 | absolute deadline per Classify call, no retry |

## Note

Missing `tier1.sslValid` reads as "no HTTPS", which alone saturates P(phish) → 1.0 in PhiUSIIL space for any URL.

