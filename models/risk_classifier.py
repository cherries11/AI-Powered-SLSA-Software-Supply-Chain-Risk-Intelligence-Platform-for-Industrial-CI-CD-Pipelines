"""
Risk Classifier
───────────────
RandomForest-based risk classifier for SLSA supply chain analysis.

Labels:
    0 → Low risk
    1 → Medium risk
    2 → High risk

Usage:
    # Train and save
    python -m models.risk_classifier

    # Predict from a full_slsa_check() result
    from models.risk_classifier import predict_risk
    label, confidence = predict_risk(slsa_result)
"""

import json
import logging
import os
from pathlib import Path
from typing import Tuple

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

from models.features import FEATURE_NAMES, RISK_LABELS, RiskFeatures

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# ── Paths ───────────────────────────────────────────────────────────────
MODELS_DIR  = Path(__file__).parent
MODEL_PATH  = MODELS_DIR / "risk_classifier.joblib"
SCHEMA_PATH = MODELS_DIR / "feature_schema.json"


# ─────────────────────────────────────────────
# Synthetic Training Data
# ─────────────────────────────────────────────

def _generate_synthetic_data() -> Tuple[np.ndarray, np.ndarray]:
    """
    Generate synthetic training samples for the stub model.
    Format: [slsa_level, unpinned_actions, unpinned_runners,
             missing_attestation, critical, high, medium, total, has_verify]

    Replace with real scan data in Phase 3 (Teammate A's scanner outputs).
    """
    # ── Low risk (label 0): clean workflows ────────────────────────────
    low_risk = [
        [3, 0, 0, 0, 0, 0, 0, 0, 1],
        [3, 0, 0, 0, 0, 0, 1, 1, 1],
        [3, 0, 1, 0, 0, 0, 0, 1, 1],
        [2, 0, 0, 0, 0, 1, 0, 1, 0],
        [3, 0, 0, 0, 0, 0, 2, 2, 1],
        [3, 0, 0, 0, 0, 0, 0, 0, 0],
        [2, 0, 1, 0, 0, 0, 1, 2, 1],
        [3, 0, 0, 1, 0, 0, 0, 1, 1],
    ]

    # ── Medium risk (label 1): some issues ─────────────────────────────
    medium_risk = [
        [2, 1, 1, 1, 0, 1, 1, 4, 0],
        [1, 2, 1, 0, 0, 2, 1, 5, 0],
        [2, 1, 0, 2, 0, 2, 0, 4, 0],
        [2, 0, 2, 1, 0, 1, 2, 5, 0],
        [1, 1, 1, 2, 0, 1, 1, 5, 0],
        [2, 2, 0, 1, 0, 2, 0, 4, 0],
        [1, 1, 2, 1, 0, 1, 2, 6, 0],
        [2, 0, 1, 2, 0, 2, 1, 5, 0],
    ]

    # ── High risk (label 2): critical/many issues ───────────────────────
    high_risk = [
        [1, 3, 2, 3, 1, 3, 2, 9,  0],
        [1, 4, 3, 4, 2, 4, 1, 11, 0],
        [1, 2, 3, 5, 1, 5, 2, 10, 0],
        [1, 5, 2, 3, 2, 3, 3, 11, 0],
        [0, 3, 4, 4, 1, 4, 2, 10, 0],
        [1, 4, 2, 5, 2, 5, 1, 12, 0],
        [0, 3, 3, 4, 3, 4, 2, 11, 0],
        [1, 5, 3, 3, 1, 5, 3, 12, 0],
    ]

    X = np.array(low_risk + medium_risk + high_risk, dtype=float)
    y = np.array(
        [0] * len(low_risk) +
        [1] * len(medium_risk) +
        [2] * len(high_risk),
        dtype=int,
    )
    return X, y


# ─────────────────────────────────────────────
# Train & Save
# ─────────────────────────────────────────────

def train_and_save() -> RandomForestClassifier:
    """
    Train the RandomForest classifier on synthetic data and save to disk.

    Returns:
        Trained RandomForestClassifier instance.
    """
    logger.info("Generating synthetic training data...")
    X, y = _generate_synthetic_data()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    logger.info("Training RandomForest classifier...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=6,
        random_state=42,
        class_weight="balanced",  # handles class imbalance
    )
    clf.fit(X_train, y_train)

    # ── Evaluate ────────────────────────────────────────────────────────
    y_pred = clf.predict(X_test)
    report = classification_report(
        y_test, y_pred,
        target_names=[RISK_LABELS[i] for i in range(3)],
        zero_division=0,
    )
    logger.info("Classification report:\n%s", report)

    # ── Save model ──────────────────────────────────────────────────────
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    logger.info("Model saved → %s", MODEL_PATH)

    # ── Save feature schema (for dashboard reference) ───────────────────
    schema = {"feature_names": FEATURE_NAMES, "risk_labels": RISK_LABELS}
    with open(SCHEMA_PATH, "w") as f:
        json.dump(schema, f, indent=2)
    logger.info("Schema saved → %s", SCHEMA_PATH)

    return clf


# ─────────────────────────────────────────────
# Load
# ─────────────────────────────────────────────

def load_model() -> RandomForestClassifier:
    """
    Load the trained model from disk. Trains it first if not found.

    Returns:
        Trained RandomForestClassifier instance.
    """
    if not MODEL_PATH.exists():
        logger.warning("Model not found at '%s'. Training now...", MODEL_PATH)
        return train_and_save()

    logger.info("Loading model from '%s'.", MODEL_PATH)
    return joblib.load(MODEL_PATH)


# ─────────────────────────────────────────────
# Predict
# ─────────────────────────────────────────────

def predict_risk(slsa_result: dict) -> Tuple[str, float]:
    """
    Predict risk level from a full_slsa_check() output dict.

    Args:
        slsa_result: Output of full_slsa_check()

    Returns:
        Tuple of (risk_label: str, confidence: float)
        e.g. ("High", 0.87)
    """
    features = RiskFeatures.from_slsa_result(slsa_result)
    vector   = np.array([features.to_vector()], dtype=float)

    clf   = load_model()
    label = int(clf.predict(vector)[0])
    proba = float(clf.predict_proba(vector)[0][label])

    risk_label = RISK_LABELS[label]
    logger.info("Risk prediction: %s (confidence: %.2f)", risk_label, proba)

    return risk_label, round(proba, 4)


# ─────────────────────────────────────────────
# Entry point — train and quick smoke test
# ─────────────────────────────────────────────

if __name__ == "__main__":
    # 1. Train and save
    train_and_save()

    # 2. Smoke test with a mock slsa_result
    mock_result = {
        "level": 1,
        "issues": [
            {"type": "unpinned_action",       "severity": "high"},
            {"type": "unpinned_action",       "severity": "high"},
            {"type": "unpinned_runner",       "severity": "medium"},
            {"type": "missing_attestation",   "severity": "high"},
        ],
        "verification": None,
    }

    label, confidence = predict_risk(mock_result)
    print(f"\nSmoke test → Risk: {label}  |  Confidence: {confidence:.0%}")