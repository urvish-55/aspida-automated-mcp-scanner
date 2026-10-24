"""Extract real MCP tool definitions (name + description) from cloned open-source servers.

Code is treated as untrusted DATA: files are read as text and parsed with regex /
`ast`; nothing is imported or executed.

Every record carries provenance (repository, commit, file, license, retrieval time,
content hash, extractor version). Records are labelled ``benign_candidate``: real tools
with no evidence of malicious behaviour — NOT "secure".

Usage:
    python -m benchmark.collect_real_tools --root ~/net --out benchmark/data/real_benign_tools.jsonl
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

EXTRACTOR_VERSION = "1"

# repo dir name -> metadata. Only permissively licensed sources are included.
# "split": "dev" repos were inspected while tuning detectors; "holdout" repos were collected
# and NOT inspected (no per-sample output) until tuning was finished.
REPOS = {
    "servers": {
        "split": "dev",
        "repository": "modelcontextprotocol/servers",
        "url": "https://github.com/modelcontextprotocol/servers",
        "license": "MIT/Apache-2.0 (transition; see LICENSE)",
        "globs": ["src/*/index.ts", "src/everything/tools/*.ts", "src/*/src/**/server.py"],
        "kinds": {"ts", "py"},
    },
    "github-mcp-server": {
        "split": "dev",
        "repository": "github/github-mcp-server",
        "url": "https://github.com/github/github-mcp-server",
        "license": "MIT",
        "globs": ["pkg/github/*.go"],
        "kinds": {"go"},
    },
    "exa-mcp-server": {
        "split": "dev",
        "repository": "exa-labs/exa-mcp-server",
        "url": "https://github.com/exa-labs/exa-mcp-server",
        "license": "MIT",
        "globs": ["src/**/*.ts"],
        "kinds": {"ts"},
    },
    "firecrawl-mcp-server": {
        "split": "dev",
        "repository": "firecrawl/firecrawl-mcp-server",
        "url": "https://github.com/firecrawl/firecrawl-mcp-server",
        "license": "MIT",
        "globs": ["src/**/*.ts"],
        "kinds": {"ts"},
    },
    "mcp-server-kubernetes": {
        "split": "dev",
        "repository": "Flux159/mcp-server-kubernetes",
        "url": "https://github.com/Flux159/mcp-server-kubernetes",
        "license": "MIT",
        "globs": ["src/**/*.ts"],
        "kinds": {"ts"},
    },
    "supabase-mcp": {
        "split": "dev",
        "repository": "supabase-community/supabase-mcp",
        "url": "https://github.com/supabase-community/supabase-mcp",
        "license": "Apache-2.0",
        "globs": ["packages/mcp-server-supabase/src/**/*.ts"],
        "kinds": {"ts"},
    },
    "context7": {
        "split": "dev",
        "repository": "upstash/context7",
        "url": "https://github.com/upstash/context7",
        "license": "MIT",
        "globs": ["packages/mcp/src/*.ts"],
        "kinds": {"ts"},
    },
    "mcp-playwright": {
        "split": "holdout", "repository": "executeautomation/mcp-playwright",
        "url": "https://github.com/executeautomation/mcp-playwright", "license": "MIT",
        "globs": ["src/**/*.ts"], "kinds": {"ts"},
    },
    "Figma-Context-MCP": {
        "split": "holdout", "repository": "GLips/Figma-Context-MCP",
        "url": "https://github.com/GLips/Figma-Context-MCP", "license": "MIT",
        "globs": ["src/**/*.ts"], "kinds": {"ts"},
    },
    "mcp-filesystem-server": {
        "split": "holdout", "repository": "mark3labs/mcp-filesystem-server",
        "url": "https://github.com/mark3labs/mcp-filesystem-server", "license": "MIT",
        "globs": ["filesystemserver/**/*.go"], "kinds": {"go"},
    },
    "mcp-server-cloudflare": {
        "split": "holdout", "repository": "cloudflare/mcp-server-cloudflare",
        "url": "https://github.com/cloudflare/mcp-server-cloudflare", "license": "Apache-2.0",
        "globs": ["apps/**/*.ts", "packages/**/*.ts"], "kinds": {"ts"},
    },
}

STR = r"""(?:"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`)"""
CONCAT = rf"{STR}(?:\s*\+\s*{STR})*"
_ESC = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "'": "'", "`": "`", "\\": "\\"}


def _unquote(lit: str) -> str:
    body = lit[1:-1]
    return re.sub(r"\\(.)", lambda m: _ESC.get(m.group(1), m.group(1)), body)


def _eval_concat(expr: str) -> str:
    return "".join(_unquote(m.group(0)) for m in re.finditer(STR, expr))


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _clean(desc: str) -> str:
    return re.sub(r"[ \t]+\n", "\n", desc).strip()


def extract_ts(text: str) -> list[tuple[str, str, int]]:
    consts = {m.group(1): m.group(2) for m in re.finditer(r"(?:const|let)\s+([A-Za-z_]\w*)\s*=\s*(?:\"([^\"\n]+)\"|'([^'\n]+)')", text) if m.group(2)}
    consts.update({m.group(1): m.group(3) for m in re.finditer(r"(?:const|let)\s+([A-Za-z_]\w*)\s*=\s*(?:\"([^\"\n]+)\"|'([^'\n]+)')", text) if m.group(3)})
    out: list[tuple[str, str, int]] = []
    for dm in re.finditer(rf"\bdescription\s*:\s*({CONCAT})", text):
        before = text[max(0, dm.start() - 1800): dm.start()]
        name = None
        # nearest of: registerTool(NAME, / tool(NAME, / name: "..."
        best = -1
        for pat in (r"(?:registerTool|\.tool)\(\s*(?:\"([^\"\n]+)\"|'([^'\n]+)'|([A-Za-z_]\w*))\s*,",
                    r"\bname\s*:\s*(?:\"([^\"\n]+)\"|'([^'\n]+)')"):
            for m in re.finditer(pat, before):
                if m.start() > best:
                    best = m.start()
                    g = [x for x in m.groups() if x]
                    ident = g[0] if g else None
                    name = consts.get(ident, ident) if ident else None
        if name is None or dm.start() - (max(0, dm.start() - 1800) + best) > 1500:
            continue
        # A tool config has a schema next to its description; a parameter description does not.
        window = text[max(0, dm.start() - 600): dm.end() + 900]
        if not re.search(r"\b(inputSchema|parameters|schema|annotations|outputSchema)\b", window):
            continue
        # Between the tool name and its description there must be no schema opening; if there is,
        # this is a parameter description nested inside the schema.
        if re.search(r"\b(properties|inputSchema|parameters|schema)\s*:", before[best:]):
            continue
        # A parameter's own description sits inside a property map: reject when the closest
        # preceding structural token is a property key such as `foo: {` / `z.string()` chains.
        tail = before[-160:]
        if re.search(r"z\.\w+\([^)]*\)\s*(\.\w+\([^)]*\)\s*)*,?\s*$", tail):
            continue
        desc = _clean(_eval_concat(dm.group(1)))
        if len(desc) >= 8:
            out.append((name, desc, text.count("\n", 0, dm.start()) + 1))
    for m in re.finditer(rf"\.tool\(\s*({STR})\s*,\s*({CONCAT})\s*,", text):
        desc = _clean(_eval_concat(m.group(2)))
        if len(desc) >= 8:
            out.append((_unquote(m.group(1)), desc, text.count("\n", 0, m.start()) + 1))
    return out


def extract_go(text: str) -> list[tuple[str, str, int]]:
    out = []
    pat = re.compile(
        rf"mcp\.Tool\{{\s*Name\s*:\s*\"([a-z0-9_\-]+)\"\s*,(?:(?!\bName\s*:)[\s\S]){{0,600}}?\bDescription\s*:\s*(?:t\(\s*\"[A-Z0-9_]+\"\s*,\s*)?({CONCAT})"
    )
    for m in pat.finditer(text):
        desc = _clean(_eval_concat(m.group(2)))
        if len(desc) >= 8:
            out.append((m.group(1), desc, text.count("\n", 0, m.start()) + 1))
    for m in re.finditer(rf"mcp\.NewTool\(\s*\"([a-z0-9_\-]+)\"\s*,\s*mcp\.WithDescription\(\s*({CONCAT})", text):
        desc = _clean(_eval_concat(m.group(2)))
        if len(desc) >= 8:
            out.append((m.group(1), desc, text.count("\n", 0, m.start()) + 1))
    return out


def extract_py(text: str) -> list[tuple[str, str, int]]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    enum_vals: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for stmt in node.body:
                if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
                    for t in stmt.targets:
                        if isinstance(t, ast.Name):
                            enum_vals[f"{node.name}.{t.id}"] = stmt.value.value
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", "")) == "Tool":
            kw = {k.arg: k.value for k in node.keywords if k.arg}
            nm, ds = kw.get("name"), kw.get("description")
            if ds is None or not (isinstance(ds, ast.Constant) and isinstance(ds.value, str)):
                continue
            name = None
            if isinstance(nm, ast.Constant) and isinstance(nm.value, str):
                name = nm.value
            else:
                node_ = nm.value if isinstance(nm, ast.Attribute) and nm.attr == "value" else nm  # X.Y.value
                if isinstance(node_, ast.Attribute) and isinstance(node_.value, ast.Name):
                    name = enum_vals.get(f"{node_.value.id}.{node_.attr}")
            if name:
                out.append((name, _clean(ds.value), node.lineno))
    return out


EXTRACTORS = {".ts": extract_ts, ".go": extract_go, ".py": extract_py}


def collect(root: Path, retrieved_at: str) -> tuple[list[dict], list[dict]]:
    records: list[dict] = []
    manifest: list[dict] = []
    for dirname, meta in REPOS.items():
        repo = root / dirname
        if not repo.is_dir():
            manifest.append({"repository": meta["repository"], "status": "skipped", "reason": "not cloned"})
            continue
        commit = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        seen: set[tuple[str, str]] = set()
        n = 0
        files: list[Path] = []
        for g in meta["globs"]:
            files += sorted(repo.glob(g))
        for f in files:
            rel = f.relative_to(repo).as_posix()
            if "test" in rel.lower() or "node_modules" in rel or rel.endswith(".d.ts"):
                continue
            ext = f.suffix
            if ext not in EXTRACTORS:
                continue
            try:
                text = f.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for name, desc, line in EXTRACTORS[ext](text):
                key = (name, _sha(desc))
                if key in seen:
                    continue
                seen.add(key)
                n += 1
                records.append(
                    {
                        "sample_id": f"{dirname}:{name}:{_sha(desc)[:8]}",
                        "tool_name": name,
                        "tool_description": desc,
                        "split": meta["split"],
                        "label": "benign_candidate",
                        "real_world": True,
                        "synthetic": False,
                        "label_method": "provenance (reputable open-source MCP server; no evidence of malicious behavior)",
                        "source": {
                            "type": "github",
                            "repository": meta["repository"],
                            "url": f"{meta['url']}/blob/{commit}/{rel}#L{line}",
                            "commit": commit,
                            "file": rel,
                            "license": meta["license"],
                            "retrieved_at": retrieved_at,
                        },
                        "content_hash": _sha(f"{name}\n{desc}"),
                        "extractor_version": EXTRACTOR_VERSION,
                    }
                )
        manifest.append(
            {
                "source_id": dirname,
                "repository": meta["repository"],
                "source_url": meta["url"],
                "commit": commit,
                "license": meta["license"],
                "retrieved_at": retrieved_at,
                "split": meta["split"],
                "tools_extracted": n,
                "extractor_version": EXTRACTOR_VERSION,
                "status": "success" if n else "failed",
            }
        )
    return records, manifest


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, required=True, help="directory containing cloned repos")
    ap.add_argument("--out", type=Path, default=Path("benchmark/data/real_benign_tools.jsonl"))
    ap.add_argument("--manifest", type=Path, default=Path("benchmark/data/real_benign_manifest.json"))
    a = ap.parse_args()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    recs, man = collect(a.root, now)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in recs), encoding="utf-8")
    a.manifest.write_text(json.dumps(man, indent=2), encoding="utf-8")
    print(f"{len(recs)} tools written to {a.out}")
    for m in man:  # counts only: holdout content is intentionally not printed
        print(" ", m.get("repository"), m.get("split"), m.get("tools_extracted"), m.get("status"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
