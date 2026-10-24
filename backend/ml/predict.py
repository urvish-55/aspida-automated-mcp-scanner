"""Runtime ML prediction (advisory only).

The model scores each tool DESCRIPTION. It is trained on real public data (see ML.md); it is a prioritization
hint next to the deterministic rules and never creates, upgrades or removes findings.

Guarantees:
- Missing artifacts  -> {"status": "unavailable"} with a reason; never an error.
- Version mismatch   -> refused (feature schema or model version drift).
- Any failure        -> status="error" with a short note; the scan continues.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from backend.core.config import get_settings
from backend.core.version import ML_FEATURE_SCHEMA_VERSION, ML_MODEL_VERSION

_CACHE: dict[str, Any] = {}
MAX_TOOLS = 500
MAX_TEXT = 4000


def _artifact_dir() -> Path:
    return Path(get_settings().ml_model_dir)


def model_available() -> bool:
    """Cheap check used by /api/health."""
    d = _artifact_dir()
    return (d / "model.joblib").is_file() and (d / "metadata.json").is_file()


def load_metadata() -> dict[str, Any]:
    path = _artifact_dir() / "metadata.json"
    key = f"meta:{path}:{path.stat().st_mtime_ns}"
    if key not in _CACHE:
        _CACHE.clear()
        _CACHE[key] = json.loads(path.read_text(encoding="utf-8"))
    return _CACHE[key]  # type: ignore[no-any-return]


def _load_pipeline() -> tuple[Any, dict[str, Any]]:
    from joblib import load

    meta = load_metadata()
    feat_v = str(meta.get("feature_schema_version"))
    if feat_v != str(ML_FEATURE_SCHEMA_VERSION):
        raise ValueError(f"feature schema mismatch: model {feat_v} != runtime {ML_FEATURE_SCHEMA_VERSION}")
    model_v = str(meta.get("model_version"))
    if model_v != str(ML_MODEL_VERSION):
        raise ValueError(f"model version mismatch: artifact {model_v} != runtime {ML_MODEL_VERSION}")
    key = f"model:{_artifact_dir()}:{meta.get('trained_at')}"
    if key not in _CACHE:
        _CACHE[key] = load(_artifact_dir() / "model.joblib")
    return _CACHE[key], meta


async def predict_for_findings(findings: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Scan-level ML advisory block (status + honest note). ``findings`` is accepted for API stability only."""
    if not model_available():
        return {"status": "unavailable", "note": "model not trained yet; run: python -m backend.ml.train_real (see ML.md)"}
    try:
        pipeline, meta = _load_pipeline()
        base = {"model_version": meta.get("model_version"), "model_status": meta.get("model_status")}
        scored = [
            (str(t.get("name") or ""), str(t.get("description") or "").strip()[:MAX_TEXT])
            for t in (tools or [])[:MAX_TOOLS]
        ]
        scored = [(n, d) for n, d in scored if d]
        if not scored:
            return {
                **base,
                "status": "not_applicable",
                "note": "no tool descriptions available to score (live URL scans do not capture descriptions); ML advisory not applicable",
            }
        probs = pipeline.predict_proba([d for _, d in scored])[:, 1]
        review = float(meta["thresholds"]["review"])
        high = float(meta["thresholds"]["high"])
        ranked = sorted(zip((n for n, _ in scored), (float(p) for p in probs)), key=lambda x: -x[1])
        flagged = [{"tool": n, "score": round(p, 4), "level": "high" if p >= high else "review"} for n, p in ranked if p >= review]
        top = ranked[0][1]
        return {
            **base,
            "status": "completed",
            "note": (
                f"Advisory ML assessment of {len(scored)} tool description(s): {len(flagged)} above the review threshold "
                f"(about 1% of benign registry tools score this high). Highest score {top:.2f}. Advisory only."
            ),
            "max_poisoned_probability": round(top, 4),
            "flagged_tools": flagged[:20],
            "tools_scored": len(scored),
            "thresholds": meta["thresholds"],
            "disclaimer": "ML output is advisory and uncalibrated; it never creates, upgrades or removes findings.",
        }
    except FileNotFoundError:
        return {"status": "unavailable", "note": "model artifacts missing"}
    except ValueError as exc:
        return {"status": "error", "note": f"model refused: {exc}"}
    except Exception as exc:  # noqa: BLE001 - ML must never break a scan
        return {"status": "error", "note": f"{type(exc).__name__}"}
