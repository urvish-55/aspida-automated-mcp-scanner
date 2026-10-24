"""Train the advisory ML model on REAL public data (description text only).

Usage (paths are wherever you unpacked the datasets):

    python -m backend.ml.train_real \
        --mcptox  "D:/datasets/MCPTox-Benchmark-main" \
        --tools   "D:/datasets/tools.jsonl" \
        --servers "D:/datasets/servers.jsonl" \
        --invariant "D:/datasets/mcp-injection-experiments-main"

Method (every choice below exists to avoid flattering numbers):
- Input is the tool DESCRIPTION only. MCPTox tools have no parameters and invented names, so name and schema
  features would let the model separate the two datasets by their provenance instead of by maliciousness.
- Cross-validation is grouped by server: all tools of one server are in the same fold, so a server's
  boilerplate cannot leak between train and test.
- Operating thresholds are chosen on out-of-fold scores at a fixed false-positive rate (1% and 0.1% of benign
  tools), not at 0.5 - the benign class is ~98% of the data.
- Independent evaluation: hand-written attacks (published excerpts + Invariant PoCs) and benign tools from other
  repositories are scored by a model that never saw them. Only after that are they added to the final fit.
- Leave-one-template-out: train on two MCPTox attack templates, test on the third.
- A description-length-only baseline is reported so length leakage is visible.
"""

from __future__ import annotations

import argparse
import json
import warnings
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve
from sklearn.model_selection import GroupKFold
from sklearn.pipeline import Pipeline

from backend.core.version import APP_VERSION, ML_FEATURE_SCHEMA_VERSION, ML_MODEL_VERSION
from backend.ml import real_data
from backend.ml.real_data import Sample

ARTIFACT_DIR = Path(__file__).resolve().parents[2] / "ml" / "artifacts"
RANDOM_SEED = 42
REPO_ROOT = Path(__file__).resolve().parents[2]


def make_pipeline() -> Pipeline:
    return Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=3, max_features=60000, sublinear_tf=True)),
        ("clf", LogisticRegression(class_weight="balanced", C=3.0, max_iter=3000, random_state=RANDOM_SEED)),
    ])


def _texts(rows: list[Sample]) -> list[str]:
    return [r.text for r in rows]


def _y(rows: list[Sample]) -> np.ndarray:
    return np.array([r.label for r in rows])


def recall_at_fpr(scores: np.ndarray, y: np.ndarray, fpr: float) -> tuple[float, float]:
    f, t, th = roc_curve(y, scores)
    i = max(int(np.searchsorted(f, fpr, side="right")) - 1, 0)
    return float(t[i]), float(th[i])


def grouped_cv(rows: list[Sample], folds: int = 5) -> np.ndarray:
    y = _y(rows)
    groups = np.array([r.group for r in rows])
    oof = np.zeros(len(rows))
    texts = _texts(rows)
    for tr, te in GroupKFold(n_splits=folds).split(texts, y, groups):
        m = make_pipeline().fit([texts[i] for i in tr], y[tr])
        oof[te] = m.predict_proba([texts[i] for i in te])[:, 1]
    return oof


def length_baseline(rows: list[Sample], folds: int = 5) -> np.ndarray:
    y = _y(rows)
    groups = np.array([r.group for r in rows])
    x = np.log1p(np.array([[len(r.text)] for r in rows], float))
    oof = np.zeros(len(rows))
    for tr, te in GroupKFold(n_splits=folds).split(x, y, groups):
        m = LogisticRegression(class_weight="balanced", max_iter=1000).fit(x[tr], y[tr])
        oof[te] = m.predict_proba(x[te])[:, 1]
    return oof


def leave_template_out(rows: list[Sample], threshold: float) -> dict[str, float]:
    out: dict[str, float] = {}
    neg_groups = sorted({r.group for r in rows if r.label == 0})
    hold = set(np.random.RandomState(1).choice(neg_groups, len(neg_groups) // 5, replace=False))
    for tpl in sorted({r.template for r in rows if r.label == 1}):
        train = [r for r in rows if not (r.label == 1 and r.template == tpl) and not (r.label == 0 and r.group in hold)]
        test_pos = [r for r in rows if r.label == 1 and r.template == tpl]
        m = make_pipeline().fit(_texts(train), _y(train))
        out[tpl] = round(float((m.predict_proba(_texts(test_pos))[:, 1] >= threshold).mean()), 4)
    return out


def train(mcptox: Path, tools: Path, servers: Path | None, invariant: Path | None, bench: Path, out_dir: Path) -> dict:
    warnings.filterwarnings("ignore")
    pos = real_data.load_mcptox(mcptox)
    neg, reg_stats = real_data.load_registry(tools, servers)
    ind_pos, ind_neg = real_data.load_benchmark(bench)
    if invariant:
        ind_pos += real_data.load_invariant(invariant)
    known = {r.text for r in neg}
    ind_neg = [r for r in ind_neg if r.text not in known]  # never score on text the model trained on
    rows = pos + neg
    y = _y(rows)

    oof = grouped_cv(rows)
    r1, th1 = recall_at_fpr(oof, y, 0.01)
    r01, th01 = recall_at_fpr(oof, y, 0.001)
    base = length_baseline(rows)
    b1, _ = recall_at_fpr(base, y, 0.01)

    # independent evaluation: model fitted on the main corpus only
    held = make_pipeline().fit(_texts(rows), y)
    ip = held.predict_proba(_texts(ind_pos))[:, 1] if ind_pos else np.array([])
    ineg = held.predict_proba(_texts(ind_neg))[:, 1] if ind_neg else np.array([])
    independent = {
        "positives": int(len(ip)),
        "negatives": int(len(ineg)),
        "recall_at_review_threshold": round(float((ip >= th1).mean()), 4) if len(ip) else None,
        "hits": int((ip >= th1).sum()),
        "false_positive_rate": round(float((ineg >= th1).mean()), 4) if len(ineg) else None,
        "false_positives": int((ineg >= th1).sum()),
        "note": "scored by a model that had not seen these samples; hand-written attacks differ in style from MCPTox",
        "missed": [{"name": r.name, "source": r.source, "score": round(float(s), 4)} for r, s in zip(ind_pos, ip) if s < th1],
    }
    lto = leave_template_out(rows, th1)

    # final fit on everything, including the independent samples
    final_rows = rows + ind_pos + ind_neg
    final = make_pipeline().fit(_texts(final_rows), _y(final_rows))

    metrics = {
        "dataset": {
            "synthetic": False,
            "total": len(final_rows),
            "positive": int(sum(r.label for r in final_rows)),
            "negative": int(sum(1 - r.label for r in final_rows)),
            "positive_sources": {"mcptox": len(pos), "independent_attacks": len(ind_pos)},
            "negative_sources": {"registry": len(neg), "independent_benign": len(ind_neg)},
            "registry_filtering": reg_stats,
            "positive_prevalence": round(len(pos) / len(rows), 4),
            "label_quality": "positives: published benchmark labels; negatives: UNLABELLED real registry tools "
                             "(benign candidates - a few may be genuinely malicious, so reported false-positive rates are upper-bound-ish)",
        },
        "cross_validation_grouped_by_server": {
            "folds": 5,
            "roc_auc": round(float(roc_auc_score(y, oof)), 4),
            "pr_auc": round(float(average_precision_score(y, oof)), 4),
            "recall_at_fpr_1pct": round(r1, 4),
            "recall_at_fpr_0_1pct": round(r01, 4),
            "length_only_baseline_recall_at_fpr_1pct": round(b1, 4),
        },
        "leave_one_template_out_recall": lto,
        "independent_evaluation": independent,
        "test": {  # keys the dashboard already renders
            "precision": None,
            "recall": round(r1, 4),
            "f1": None,
            "balanced_accuracy": None,
            "note": "recall at the 1% false-positive operating point on grouped cross-validation (positives are only 1.6% of the data, so precision/F1 at 0.5 would be misleading)",
        },
    }
    ind_recall = independent["recall_at_review_threshold"]
    if ind_recall is None or ind_recall < 0.8:
        status = "EXPERIMENTAL - trained on real data; weak recall on independent hand-written attacks"
    else:
        status = "EXPERIMENTAL CANDIDATE - real data; independent set is small, re-validate before relying on it"

    metadata = {
        "model_version": ML_MODEL_VERSION,
        "feature_schema_version": ML_FEATURE_SCHEMA_VERSION,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "trainer_app_version": APP_VERSION,
        "model_type": "sklearn Pipeline(TfidfVectorizer word 1-2gram, LogisticRegression balanced) on tool description text",
        "input": "tool description text only (no name, no schema)",
        "features": ["tfidf word 1-2gram (<=60000 terms)"],
        "model_status": status,
        "usage": "advisory only - assists prioritization; never creates, upgrades or removes findings",
        "thresholds": {"review": round(th1, 6), "high": round(th01, 6),
                       "meaning": "review = score at 1% false-positive rate on out-of-fold benign tools; high = 0.1%"},
        "caveats": [
            "In-distribution numbers (grouped CV, leave-template-out) are optimistic: MCPTox payloads are machine-generated from three templates and share vocabulary.",
            "The independent set has only 10 attacks, so its recall has a very wide confidence interval.",
            "Attacks that carry no malicious text in the description (a benign-looking sleeper that changes later, a look-alike name) cannot be found from the description.",
            "Negatives are unlabelled registry tools; label noise is possible.",
        ],
        "score_note": "uncalibrated score in [0,1] (class-balanced training); compare against thresholds, do not read as a probability",
        "metrics": metrics,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    from joblib import dump

    dump(final, out_dir / "model.joblib")
    (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mcptox", type=Path, required=True)
    ap.add_argument("--tools", type=Path, required=True)
    ap.add_argument("--servers", type=Path)
    ap.add_argument("--invariant", type=Path)
    ap.add_argument("--benchmark-data", type=Path, default=REPO_ROOT / "benchmark" / "data")
    ap.add_argument("--out", type=Path, default=ARTIFACT_DIR)
    a = ap.parse_args()
    meta = train(a.mcptox, a.tools, a.servers, a.invariant, a.benchmark_data, a.out)
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()
