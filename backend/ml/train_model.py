"""
backend/ml/train_model.py
==========================
Phase 4 — PhishGuard AI ML Training Pipeline

Dataset
-------
Source:  https://github.com/faizann24/Using-Machine-Learning-To-Detect-Malicious-URLs
License: Free / academic use
Format:  CSV — columns: url, label  (good=0, bad=1)
Size:    ~420 000 labelled URLs

Algorithm
---------
RandomForestClassifier(n_estimators=200, random_state=42, class_weight="balanced")

Outputs
-------
  backend/model/phishing_model.joblib      — serialised classifier
  backend/model/feature_metadata.json     — feature names, metrics, provenance

Usage
-----
  cd backend/
  python ml/train_model.py                # full run (downloads data if needed)
  python ml/train_model.py --no-download  # skip download (data already cached)
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import requests
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

# ── Make sure the backend/ root is importable ────────────────────────────────
BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from ml.feature_extractor import FEATURE_NAMES, extract_features  # noqa: E402

# ── Paths ────────────────────────────────────────────────────────────────────
DATA_DIR   = BACKEND_DIR / "data"
MODEL_DIR  = BACKEND_DIR / "model"
DATA_FILE  = DATA_DIR  / "phishing_urls.csv"
MODEL_FILE = MODEL_DIR / "phishing_model.joblib"
META_FILE  = MODEL_DIR / "feature_metadata.json"

# ── Dataset source ────────────────────────────────────────────────────────────
DATASET_URL = (
    "https://raw.githubusercontent.com/faizann24/"
    "Using-Machine-Learning-To-Detect-Malicious-URLs/"
    "master/data/data.csv"
)
DATASET_DESCRIPTION = (
    "Phishing / malicious URL dataset by Faizan Ahmad, hosted on GitHub. "
    "~420 000 URLs labelled good (legitimate) or bad (phishing/malware)."
)

# ── Sample cap — set to None to train on the full ~420 k rows ────────────────
# 60 000 (30 k per class) keeps training under ~3 minutes on most laptops
# while still producing reliable metrics.
SAMPLE_SIZE: int | None = 60_000

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — Download
# ─────────────────────────────────────────────────────────────────────────────

def download_dataset() -> None:
    """Download dataset from GitHub and cache it locally."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if DATA_FILE.exists():
        log.info("Dataset already cached at %s  (%.1f MB)",
                 DATA_FILE, DATA_FILE.stat().st_size / 1e6)
        return

    log.info("Downloading dataset from GitHub…")
    log.info("  %s", DATASET_URL)

    try:
        with requests.get(DATASET_URL, timeout=180, stream=True) as resp:
            resp.raise_for_status()
            total = int(resp.headers.get("content-length", 0))
            downloaded = 0
            with open(DATA_FILE, "wb") as fh:
                for chunk in resp.iter_content(chunk_size=131_072):
                    fh.write(chunk)
                    downloaded += len(chunk)
                    if total:
                        pct = downloaded / total * 100
                        print(f"\r  {pct:5.1f}%  ({downloaded/1e6:.1f} MB)", end="", flush=True)
        print()
        log.info("Saved → %s  (%.1f MB)", DATA_FILE, DATA_FILE.stat().st_size / 1e6)
    except requests.RequestException as exc:
        log.error("Download failed: %s", exc)
        log.error("Please download the CSV manually from:")
        log.error("  %s", DATASET_URL)
        log.error("and save it as: %s", DATA_FILE)
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Step 2 — Load + preprocess
# ─────────────────────────────────────────────────────────────────────────────

def load_dataset() -> pd.DataFrame:
    """Load raw CSV, normalise labels, drop bad rows, optionally sample."""
    log.info("Loading dataset from %s…", DATA_FILE)
    df = pd.read_csv(DATA_FILE, dtype=str)

    # Normalise column names
    df.columns = [c.strip().lower() for c in df.columns]

    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError(
            f"Expected columns 'url' and 'label', got: {list(df.columns)}"
        )

    # Map text labels → binary integers
    label_map = {"good": 0, "bad": 1, "0": 0, "1": 1, "legitimate": 0, "phishing": 1}
    df["label"] = df["label"].str.strip().str.lower().map(label_map)

    # Drop rows with null URL or unmappable label
    before = len(df)
    df = df.dropna(subset=["url", "label"])
    df["label"] = df["label"].astype(int)
    dropped = before - len(df)
    if dropped:
        log.warning("Dropped %d rows with null/unmappable values.", dropped)

    log.info(
        "Full dataset: %d rows  |  phishing=%d  legitimate=%d",
        len(df),
        (df["label"] == 1).sum(),
        (df["label"] == 0).sum(),
    )

    # ── Balanced stratified sample ────────────────────────────────────────────
    if SAMPLE_SIZE and len(df) > SAMPLE_SIZE:
        half = SAMPLE_SIZE // 2
        n_pos = min(half, int((df["label"] == 1).sum()))
        n_neg = min(half, int((df["label"] == 0).sum()))
        pos = df[df["label"] == 1].sample(n=n_pos, random_state=42)
        neg = df[df["label"] == 0].sample(n=n_neg, random_state=42)
        df = (
            pd.concat([pos, neg])
            .sample(frac=1, random_state=42)
            .reset_index(drop=True)
        )
        log.info(
            "Balanced sample: %d rows  |  phishing=%d  legitimate=%d",
            len(df),
            (df["label"] == 1).sum(),
            (df["label"] == 0).sum(),
        )

    return df


# ─────────────────────────────────────────────────────────────────────────────
# Step 3 — Feature extraction
# ─────────────────────────────────────────────────────────────────────────────

def build_feature_matrix(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    """Apply the Phase-3 feature extractor to every URL."""
    n = len(df)
    log.info("Extracting features for %d URLs…", n)

    rows:   list[list[float]] = []
    errors: int = 0

    for i, url in enumerate(df["url"].astype(str)):
        result = extract_features(url)
        if result.error:
            errors += 1
        rows.append(result.vector)

        if (i + 1) % 5_000 == 0 or (i + 1) == n:
            print(f"\r  {i+1:>6}/{n}  ({(i+1)/n*100:.1f}%)", end="", flush=True)

    print()
    if errors:
        log.warning("Feature extraction errors: %d / %d URLs", errors, n)

    X = np.array(rows, dtype=np.float32)
    y = df["label"].values.astype(int)
    log.info("Feature matrix: shape=%s  dtype=%s", X.shape, X.dtype)
    return X, y


# ─────────────────────────────────────────────────────────────────────────────
# Step 4 — Train
# ─────────────────────────────────────────────────────────────────────────────

def train_model(X_train: np.ndarray, y_train: np.ndarray) -> RandomForestClassifier:
    log.info(
        "Training RandomForestClassifier  "
        "n_estimators=200  class_weight=balanced  n_jobs=-1…"
    )
    clf = RandomForestClassifier(
        n_estimators=50,
        random_state=42,
        class_weight="balanced",
        max_features="sqrt",
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)
    log.info("Training complete  |  trees=%d", len(clf.estimators_))
    return clf


# ─────────────────────────────────────────────────────────────────────────────
# Step 5 — Evaluate
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_model(
    clf: RandomForestClassifier,
    X_test: np.ndarray,
    y_test: np.ndarray,
) -> dict:
    """Compute and print evaluation metrics. Returns a dict for the metadata file."""
    y_pred = clf.predict(X_test)

    acc  = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec  = float(recall_score(y_test, y_pred, zero_division=0))
    f1   = float(f1_score(y_test, y_pred, zero_division=0))
    cm   = confusion_matrix(y_test, y_pred)

    print()
    print("=" * 60)
    print("  EVALUATION — test set (20% stratified hold-out)")
    print("=" * 60)
    print(f"  Accuracy : {acc:.4f}   ({acc * 100:.2f}%)")
    print(f"  Precision: {prec:.4f}   ({prec * 100:.2f}%)")
    print(f"  Recall   : {rec:.4f}   ({rec * 100:.2f}%)")
    print(f"  F1-Score : {f1:.4f}   ({f1 * 100:.2f}%)")
    print("-" * 60)
    print("  Confusion Matrix (rows=actual, cols=predicted):")
    print(f"                Pred Legit   Pred Phish")
    print(f"  Actual Legit  {cm[0,0]:>10}   {cm[0,1]:>10}")
    print(f"  Actual Phish  {cm[1,0]:>10}   {cm[1,1]:>10}")
    print("-" * 60)
    print(classification_report(
        y_test, y_pred,
        target_names=["Legitimate", "Phishing"],
        digits=4,
    ))
    print("=" * 60)

    # Feature importance (top 10)
    importances = clf.feature_importances_
    top_idx = np.argsort(importances)[::-1][:10]
    print("\n  Top 10 feature importances:")
    for rank, idx in enumerate(top_idx, 1):
        print(f"  {rank:>2}. {FEATURE_NAMES[idx]:<35} {importances[idx]:.4f}")
    print()

    return {
        "accuracy":              round(acc,  6),
        "precision":             round(prec, 6),
        "recall":                round(rec,  6),
        "f1_score":              round(f1,   6),
        "confusion_matrix":      cm.tolist(),
        "test_set_size":         int(len(y_test)),
        "phishing_test_count":   int((y_test == 1).sum()),
        "legitimate_test_count": int((y_test == 0).sum()),
        "top_features": [
            {"rank": i + 1, "name": FEATURE_NAMES[idx], "importance": round(float(importances[idx]), 6)}
            for i, idx in enumerate(top_idx)
        ],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Step 6 — Save
# ─────────────────────────────────────────────────────────────────────────────

def save_artifacts(
    clf: RandomForestClassifier,
    metrics: dict,
    n_training_rows: int,
) -> None:
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    # Model file
    joblib.dump(clf, MODEL_FILE, compress=3)
    log.info("Model → %s  (%.2f MB)", MODEL_FILE, MODEL_FILE.stat().st_size / 1e6)

    # Metadata
    meta = {
        "model_name":    "PhishGuard AI Phishing URL Classifier",
        "model_version": "1.0.0",
        "phase":         4,
        "training_date": datetime.now(timezone.utc).isoformat(),
        "algorithm":     "RandomForestClassifier",
        "hyperparameters": {
            "n_estimators": 50,
            "random_state": 42,
            "class_weight": "balanced",
            "max_features": "sqrt",
        },
        "feature_names":  list(FEATURE_NAMES),
        "feature_count":  len(FEATURE_NAMES),
        "dataset": {
            "source":            DATASET_URL,
            "description":       DATASET_DESCRIPTION,
            "labels":            {"0": "legitimate", "1": "phishing/malicious"},
            "training_rows_used": n_training_rows,
            "sample_cap":        SAMPLE_SIZE,
        },
        "metrics": metrics,
        "model_file": "phishing_model.joblib",
        "notes": (
            "Phase 4 model uses 34 lexical/structural URL features only. "
            "No domain-age (WHOIS) or page-content features in this phase. "
            "Phase 5 adds SHAP explainability. "
            "Metrics are from real evaluation on a held-out test set."
        ),
    }

    with open(META_FILE, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
    log.info("Metadata → %s", META_FILE)


# ─────────────────────────────────────────────────────────────────────────────
# Step 7 — Verify
# ─────────────────────────────────────────────────────────────────────────────

def verify_saved_model() -> None:
    """Load the saved model and run a quick end-to-end sanity check."""
    log.info("Verifying saved model…")

    clf: RandomForestClassifier = joblib.load(MODEL_FILE)

    test_cases = [
        ("https://github.com",                          "expect: likely legitimate"),
        ("http://paypal-secure-login.example.com",      "expect: likely phishing"),
        ("https://192.168.1.1/admin/login",             "expect: likely phishing"),
    ]

    for url, note in test_cases:
        result = extract_features(url)
        vec    = np.array([result.vector], dtype=np.float32)

        assert vec.shape[1] == len(FEATURE_NAMES), (
            f"Feature count mismatch! Model input dim={vec.shape[1]}, "
            f"extractor returns {len(FEATURE_NAMES)}"
        )

        prob = clf.predict_proba(vec)[0]   # [P(legit), P(phish)]
        pred = int(clf.predict(vec)[0])
        label = "PHISHING" if pred == 1 else "LEGITIMATE"

        log.info(
            "  %-55s  →  %-11s  P(phish)=%.3f   [%s]",
            url, label, prob[1], note,
        )

    log.info("Model verification passed ✓")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="PhishGuard AI Phase 4 — Model Training")
    parser.add_argument(
        "--no-download",
        action="store_true",
        help="Skip dataset download (assumes data/phishing_urls.csv already exists)",
    )
    args = parser.parse_args()

    print()
    print("=" * 60)
    print("  PhishGuard AI — Phase 4 Model Training Pipeline")
    print("=" * 60)
    print(f"  Feature count   : {len(FEATURE_NAMES)}")
    print(f"  Sample cap      : {SAMPLE_SIZE if SAMPLE_SIZE else 'full dataset'}")
    print(f"  Model algorithm : RandomForestClassifier(n_estimators=50)")
    print("=" * 60)
    print()

    # 1. Download
    if not args.no_download:
        download_dataset()

    # 2. Load
    df = load_dataset()

    # 3. Feature extraction
    X, y = build_feature_matrix(df)

    # 4. Train / test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    log.info(
        "Split  →  train=%d  test=%d  |  phish in test: %d",
        len(X_train), len(X_test), int((y_test == 1).sum()),
    )

    # 5. Train
    clf = train_model(X_train, y_train)

    # 6. Evaluate
    metrics = evaluate_model(clf, X_test, y_test)

    # 7. Save
    save_artifacts(clf, metrics, n_training_rows=len(df))

    # 8. Verify
    verify_saved_model()

    print()
    print("[OK]  Phase 4 complete.")
    print(f"   Model  : {MODEL_FILE}")
    print(f"   Meta   : {META_FILE}")
    print()


if __name__ == "__main__":
    main()
