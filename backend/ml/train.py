"""LEGACY: train the 22-feature baseline on the synthetic corpus (kept for comparison only).

The runtime model is trained by backend.ml.train_real on real public data; this module writes to
ml/artifacts_synthetic/ and is NOT loaded by the scanner.

Usage:  .venv/Scripts/python -m backend.ml.train

Outputs (ml/artifacts/):
- model.joblib                  fitted sklearn pipeline
- metadata.json                 versions, class balance, metrics, MODEL STATUS

MODEL STATUS rules (honest by construction):
- "PRODUCTION CANDIDATE (synthetic)" only if test F1 >= 0.8 AND both classes
  are represented; otherwise "NOT PRODUCTION READY - experimental".
- Metrics describe the synthetic distribution only; this is stated everywhere
  the model is surfaced. The runtime treats the model as advisory regardless.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from backend.core.version import APP_VERSION
from backend.ml.dataset import DATASET_SEED, SYNTHETIC_LABEL, generate_dataset
from backend.ml.features import FEATURE_NAMES

ARTIFACT_DIR = Path(__file__).resolve().parents[2] / "ml" / "artifacts_synthetic"
RANDOM_SEED = 42
MIN_F1_PRODUCTION = 0.8


def train() -> dict:
    from joblib import dump

    X, y, samples = generate_dataset(seed=DATASET_SEED)
    n_total = len(y)
    n_pos = sum(y)
    n_neg = n_total - n_pos

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y
    )

    pipeline = Pipeline(
        [("scaler", StandardScaler()), ("clf", LogisticRegression(max_iter=2000, random_state=RANDOM_SEED))]
    )

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_SEED)
    cv_scores = cross_val_score(pipeline, X_train, y_train, cv=cv, scoring="f1")

    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)

    metrics = {
        "dataset": {
            "synthetic": True,
            "label": SYNTHETIC_LABEL,
            "seed": DATASET_SEED,
            "total": n_total,
            "positive": n_pos,
            "negative": n_neg,
            "train_size": len(y_train),
            "test_size": len(y_test),
        },
        "cv_f1_train": {
            "mean": round(float(cv_scores.mean()), 4),
            "std": round(float(cv_scores.std()), 4),
            "folds": [round(float(s), 4) for s in cv_scores],
        },
        "test": {
            "precision": round(float(precision_score(y_test, y_pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_test, y_pred, zero_division=0)), 4),
            "f1": round(float(f1_score(y_test, y_pred, zero_division=0)), 4),
            "balanced_accuracy": round(float(balanced_accuracy_score(y_test, y_pred)), 4),
        },
        "confusion_matrix_test": {
            "labels": ["benign(0)", "poisoned(1)"],
            "matrix": confusion_matrix(y_test, y_pred).tolist(),
        },
    }

    f1 = metrics["test"]["f1"]
    both_classes = n_pos > 0 and n_neg > 0
    # Honesty rule: PERFECT separation on synthetic templates is itself a red
    # flag — it means the corpus is trivially separable and validates nothing
    # about real-world MCP tools. Such a model must NOT be labeled production
    # ready. Only a strong-but-imperfect score would justify a candidate label,
    # and even that is capped at "synthetic candidate".
    if not both_classes:
        status = "NOT PRODUCTION READY - degenerate dataset"
    elif f1 >= 0.995:
        status = "NOT PRODUCTION READY - synthetic separation too easy to demonstrate real-world value"
    elif f1 >= MIN_F1_PRODUCTION:
        status = "EXPERIMENTAL CANDIDATE (synthetic distribution only)"
    else:
        status = "NOT PRODUCTION READY - experimental"

    metadata = {
        "model_version": "0.1.0-synthetic",
        "feature_schema_version": "1-synthetic",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "trainer_app_version": APP_VERSION,
        "model_type": "sklearn Pipeline(StandardScaler, LogisticRegression)",
        "features": list(FEATURE_NAMES),
        "model_status": status,
        "usage": "advisory only - assists prioritization; never creates, upgrades or removes findings",
        "metrics": metrics,
    }

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    dump(pipeline, ARTIFACT_DIR / "model.joblib")
    (ARTIFACT_DIR / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


if __name__ == "__main__":
    meta = train()
    print(json.dumps(meta, indent=2))
