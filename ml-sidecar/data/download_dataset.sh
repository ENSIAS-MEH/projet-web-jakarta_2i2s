#!/usr/bin/env bash
# download_dataset.sh — fetch the PhiUSIIL Phishing URL Dataset (UCI ML Repository).
#
# Provenance:
#   Name    : PhiUSIIL Phishing URL Dataset
#   Source  : UCI Machine Learning Repository, dataset #967
#   URL     : https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
#   Paper   : Prasad & Chandra (2024), "PhiUSIIL: A diverse security profile
#             empowered phishing URL detection framework...", Computers & Security.
#   License : Creative Commons Attribution 4.0 International (CC BY 4.0)
#   Size    : ~55 MB CSV, 235,795 rows (134,850 legitimate + 100,945 phishing)
#   NOTE    : dataset label==1 means LEGITIMATE, label==0 means phishing.
#             train.py inverts this to SecBret's convention (1==phishing).
#
# The raw CSV is intentionally NOT committed (see ml-sidecar/data/.gitignore).
# Run this once before training:  bash data/download_dataset.sh
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
URL="https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"
CSV="$DIR/PhiUSIIL_Phishing_URL_Dataset.csv"

if [[ -f "$CSV" ]]; then
  echo "[download] Dataset already present: $CSV"
  exit 0
fi

echo "[download] Fetching PhiUSIIL dataset from UCI..."
curl -fSL --max-time 300 -o "$DIR/phiusiil.zip" "$URL"
unzip -o -q "$DIR/phiusiil.zip" -d "$DIR"
rm -f "$DIR/phiusiil.zip"
echo "[download] Ready: $CSV"
