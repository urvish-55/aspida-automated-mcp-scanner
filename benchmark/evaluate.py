"""Evaluate the static poisoning detectors on the benchmark corpora.

Alert definitions (reported separately, never merged):
  flagged   : at least one prompt-injection finding with status confirmed OR suspected
  confirmed : at least one prompt-injection finding with status confirmed

Only metadata that a corpus actually provides is analysed (name + description) with a
neutral, tightly constrained schema, so schema/capability rules cannot inflate or mask
the result. Results are reported per corpus with 95% Wilson intervals; synthetic and
real-world data are NEVER pooled into one headline number.

    python -m benchmark.evaluate [--json benchmark/results/latest.json] [--label NAME]
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from backend.core.version import RULESET_VERSION
from backend.scanners.mcp_ingest import normalize_target
from backend.scanners.static.engine import run_static_analysis

DATA = Path(__file__).parent / "data"
NEUTRAL_SCHEMA = {
    "type": "object",
    "properties": {"input": {"type": "string", "maxLength": 200}},
    "required": ["input"],
    "additionalProperties": False,
}
CORPORA = {
    "real_benign_dev": ("real_benign_tools.jsonl", "benign"),
    "real_benign_holdout": ("real_benign_tools.jsonl", "benign"),
    "published_attacks": ("published_attacks.jsonl", "poisoned"),
    "external_synthetic": ("external_poisoning_synthetic.jsonl", "poisoned"),
}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def load(name: str) -> list[dict]:
    path = DATA / CORPORA[name][0]
    recs = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if name.startswith("real_benign_"):
        want = name.rsplit("_", 1)[1]
        recs = [r for r in recs if r.get("split") == want]
    return recs


MEDIUM_PLUS = ("medium", "high", "critical")


def _summ(findings: list, tool: str) -> dict:
    pi = [f for f in findings if f.category == "prompt_injection" and tool in f.affected_tools]
    return {
        "flagged": any(f.status in ("confirmed", "suspected") for f in pi),
        "medium_plus": any(f.status in ("confirmed", "suspected") and f.severity in MEDIUM_PLUS for f in pi),
        "confirmed": any(f.status == "confirmed" for f in pi),
        "rules": sorted({f"{f.rule_id}:{f.status}" for f in pi}),
    }


def analyse_group(records: list[dict]) -> list[dict]:
    """Analyse records as ONE server (so cross-tool references can be resolved), attribute per tool."""
    seen: dict[str, int] = {}
    tools = []
    keyed = []
    for r in records:
        n = seen.get(r["tool_name"], 0)
        seen[r["tool_name"]] = n + 1
        name = r["tool_name"] if n == 0 else f"{r['tool_name']}__{n}"
        keyed.append(name)
        tools.append({"name": name, "description": r["tool_description"], "inputSchema": NEUTRAL_SCHEMA})
    findings, _ = run_static_analysis(normalize_target({"tools": tools}), "benchmark")
    return [_summ(findings, name) for name in keyed]


def analyse_corpus(name: str, recs: list[dict]) -> list[tuple[dict, dict]]:
    if CORPORA[name][1] == "benign":
        groups: dict[str, list[dict]] = defaultdict(list)
        for r in recs:
            groups[r["source"]["repository"]].append(r)
        out = []
        for g in groups.values():
            out += list(zip(g, analyse_group(g)))
        return out
    # attack samples are independent single-tool servers (no cross-tool context available)
    return [(r, analyse_group([r])[0]) for r in recs]


def rate(k: int, n: int) -> dict:
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": round(k / n, 4) if n else None, "ci95": [round(lo, 4), round(hi, 4)]}


def evaluate(reveal_holdout: bool = False) -> dict:
    out: dict = {"ruleset_version": RULESET_VERSION, "evaluated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "corpora": {}}
    for name, (_, expected) in CORPORA.items():
        recs = load(name)
        results = analyse_corpus(name, recs)
        flagged = sum(a["flagged"] for _, a in results)
        confirmed = sum(a["confirmed"] for _, a in results)
        medium = sum(a["medium_plus"] for _, a in results)
        entry: dict = {"expected_label": expected, "n": len(recs), "flagged": rate(flagged, len(recs)),
                       "medium_plus": rate(medium, len(recs)), "confirmed": rate(confirmed, len(recs))}
        if expected == "benign":
            entry["false_positives"] = [
                {"sample_id": r["sample_id"], "rules": a["rules"], "description": r["tool_description"][:200]} for r, a in results if a["flagged"]
            ]
            by_repo: dict[str, list[int]] = defaultdict(lambda: [0, 0])
            for r, a in results:
                by_repo[r["source"]["repository"]][1] += 1
                by_repo[r["source"]["repository"]][0] += a["flagged"]
            entry["by_repository"] = {k: {"flagged": v[0], "n": v[1]} for k, v in sorted(by_repo.items())}
        else:
            entry["misses"] = [
                {"sample_id": r["sample_id"], "technique": r.get("technique"), "rules": a["rules"], "description": r["tool_description"][:200]}
                for r, a in results if not a["flagged"]
            ]
            by_tech: dict[str, list[int]] = defaultdict(lambda: [0, 0])
            for r, a in results:
                by_tech[r.get("technique", "?")][1] += 1
                by_tech[r.get("technique", "?")][0] += a["flagged"]
            entry["by_technique"] = {k: {"flagged": v[0], "n": v[1]} for k, v in sorted(by_tech.items())}
        out["corpora"][name] = entry
    return out


def render(res: dict) -> str:
    lines = [f"Ruleset {res['ruleset_version']}  evaluated {res['evaluated_at']}", ""]
    for name, e in res["corpora"].items():
        kind = "FALSE-POSITIVE rate" if e["expected_label"] == "benign" else "RECALL"
        f, c, m = e["flagged"], e["confirmed"], e["medium_plus"]
        lines.append(f"[{name}] n={e['n']}  {kind}: any-flag {f['k']}/{f['n']} = {f['rate']:.1%} (95% CI {f['ci95'][0]:.1%}-{f['ci95'][1]:.1%});"
                     f" medium+ {m['k']}/{m['n']} = {m['rate']:.1%} (CI {m['ci95'][0]:.1%}-{m['ci95'][1]:.1%});"
                     f" confirmed {c['k']}/{c['n']} = {c['rate']:.1%} (CI {c['ci95'][0]:.1%}-{c['ci95'][1]:.1%})")
        for fp in e.get("false_positives", [])[:20]:
            lines.append(f"    FP  {fp['sample_id']}  {fp['rules']}  | {fp['description'][:90]!r}")
        for ms in e.get("misses", [])[:20]:
            lines.append(f"    MISS {ms['sample_id']} ({ms['technique']}) | {ms['description'][:90]!r}")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", type=Path)
    ap.add_argument("--label", default="")
    ap.add_argument("--reveal-holdout", action="store_true", help="print per-sample holdout false positives (use ONLY after tuning is finished)")
    a = ap.parse_args()
    res = evaluate(a.reveal_holdout)
    if not a.reveal_holdout:  # keep holdout sample-level content out of the output while tuning
        res["corpora"]["real_benign_holdout"].pop("false_positives", None)
        res["corpora"]["real_benign_holdout"]["note"] = "sample-level holdout results withheld until tuning is finished"
    res["label"] = a.label
    print(render(res))
    if a.json:
        a.json.parent.mkdir(parents=True, exist_ok=True)
        a.json.write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
