"""Benchmark regression guard (skips if the corpora are absent).

Bounds are deliberately loose: they catch a detector regression, they do not certify accuracy.
The attack corpora are tiny and were used while tuning (in-sample) — see benchmark/RESULTS.md.
"""

import pytest

from benchmark.evaluate import DATA, evaluate

pytestmark = pytest.mark.skipif(not (DATA / "real_benign_tools.jsonl").exists(), reason="benchmark corpora not built")


@pytest.fixture(scope="module")
def result():
    return evaluate(reveal_holdout=False)


def test_real_benign_false_positives_stay_low(result):
    for name in ("real_benign_dev", "real_benign_holdout"):
        c = result["corpora"][name]
        assert c["n"] > 100
        assert c["medium_plus"]["rate"] <= 0.02, name
        assert c["confirmed"]["k"] == 0, f"{name}: real benign tool classified as CONFIRMED poisoning"


def test_attack_recall_does_not_regress(result):
    assert result["corpora"]["published_attacks"]["medium_plus"]["rate"] >= 0.85
    assert result["corpora"]["external_synthetic"]["medium_plus"]["rate"] >= 0.90
