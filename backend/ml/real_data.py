"""Loaders that turn public MCP datasets into labelled description samples.

Nothing here downloads data or is committed to the repository: raw datasets stay
wherever the user keeps them (their licences differ and some are unstated), and
paths are passed on the command line. Every sample keeps its provenance.

Sources (see ML.md for details and caveats):
- MCPTox (AAAI'26)            positives  485 poisoned tool descriptions, 45 servers, 3 attack templates
- tools.jsonl / servers.jsonl negatives  real registry crawl (Smithery / crawler / AWS / seed) - UNLABELLED
                                          for poisoning; treated as benign *candidates*
- mcp-injection-experiments   positives  3 researcher proofs of concept (independent evaluation)
- benchmark/data/*            positives  published attack excerpts; negatives: real benign tools (independent)
"""

from __future__ import annotations

import ast
import json
from dataclasses import dataclass
from pathlib import Path

MAX_TEXT = 4000


@dataclass(frozen=True)
class Sample:
    text: str          # tool description (the only input the model sees)
    name: str          # kept for provenance/debugging, never used as a feature
    label: int         # 1 = poisoned/malicious, 0 = benign candidate
    group: str         # leakage group: samples sharing a group never straddle a train/test split
    source: str        # dataset the sample came from
    template: str = ""  # MCPTox attack template (positives only)


def _clean(text: str) -> str:
    return (text or "").strip()[:MAX_TEXT]


def load_mcptox(root: Path) -> list[Sample]:
    data = json.loads((root / "pure_tool.json").read_text(encoding="utf-8"))
    out: list[Sample] = []
    for block in data:
        for entry in block.values():
            text = _clean(entry["tool_content"])
            if text:
                out.append(Sample(text, entry["tool_name"], 1, "mcptox:" + entry["server_name"], "mcptox", entry.get("paradigm", "")))
    return out


def load_registry(tools_path: Path, servers_path: Path | None = None) -> tuple[list[Sample], dict[str, int]]:
    """Real registry tools. Deduplicated on description text (forks/mirrors repeat verbatim)."""
    source_of: dict[str, str] = {}
    if servers_path and servers_path.is_file():
        for line in servers_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                s = json.loads(line)
                source_of[s["slug"]] = s.get("source") or "unknown"
    seen: set[str] = set()
    out: list[Sample] = []
    stats = {"rows": 0, "empty_description": 0, "duplicate_description": 0}
    for line in tools_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        stats["rows"] += 1
        t = json.loads(line)
        text = _clean(t.get("description") or "")
        if not text:
            stats["empty_description"] += 1
            continue
        if text in seen:
            stats["duplicate_description"] += 1
            continue
        seen.add(text)
        slug = t["server_slug"]
        out.append(Sample(text, t["name"], 0, "registry:" + slug, "registry:" + source_of.get(slug, "unknown")))
    return out, stats


def load_invariant(root: Path) -> list[Sample]:
    """Tool docstrings from the three Invariant Labs proof-of-concept servers (read as text, never executed)."""
    out: list[Sample] = []
    for fname in ("direct-poisoning.py", "shadowing.py", "whatsapp-takeover.py"):
        path = root / fname
        if not path.is_file():
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.FunctionDef) and any("tool" in ast.unparse(d) for d in node.decorator_list):
                doc = ast.get_docstring(node)
                if doc:
                    out.append(Sample(_clean(doc), node.name, 1, "independent:" + fname, "invariant-poc"))
    return out


def load_benchmark(bench_dir: Path) -> tuple[list[Sample], list[Sample]]:
    """Independent evaluation material already shipped with the project's benchmark."""
    pos: list[Sample] = []
    neg: list[Sample] = []
    pub = bench_dir / "published_attacks.jsonl"
    if pub.is_file():
        for line in pub.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                pos.append(Sample(_clean(r["tool_description"]), r["tool_name"], 1, "independent:" + r["sample_id"], "published-attacks"))
    ben = bench_dir / "real_benign_tools.jsonl"
    if ben.is_file():
        for line in ben.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                text = _clean(r["tool_description"])
                if text:
                    neg.append(Sample(text, r["tool_name"], 0, "independent:" + r["source"]["repository"], "benchmark-real-benign"))
    return pos, neg
