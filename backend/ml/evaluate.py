"""Standalone evaluation on a held-out synthetic split (run after training).

Usage: .venv/Scripts/python -m backend.ml.evaluate
Prints metrics + confusion matrix. Deliberately simple: the numbers must match
metadata.json produced by train.py (same seed, same split).
"""

from __future__ import annotations

import json

from sklearn.metrics import balanced_accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from backend.ml.dataset import DATASET_SEED, generate_dataset
from backend.ml.train import ARTIFACT_DIR, RANDOM_SEED


def evaluate() -> dict:
    from joblib import load

    pipeline = load(ARTIFACT_DIR / "model.joblib")
    X, y, _ = generate_dataset(seed=DATASET_SEED)
    _, X_test, _, y_test = train_test_split(X, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y)
    y_pred = pipeline.predict(X_test)
    report = {
        "precision": round(float(precision_score(y_test, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_test, y_pred, zero_division=0)), 4),
        "balanced_accuracy": round(float(balanced_accuracy_score(y_test, y_pred)), 4),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "note": "metrics describe the synthetic distribution only",
    }
    print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    evaluate()
