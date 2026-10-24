"""Evidence-only investigation views: tool risk, heatmap, capability graph, attack paths, scan comparison.

Rules (spec 62.9/62.10): nothing here is invented. Every node/cell/path is built from stored findings and
tool capabilities. When the evidence for an attack chain is incomplete, the path is returned with
``complete = False`` and the missing stages are listed instead of being filled in.

The per-tool exposure score is a DISPLAY aid for ranking tools inside one scan. It is not part of the
RISK-1 scan score (see backend/risk/engine.py) and is labelled as such in the API response.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
RANK_SEVERITY = {v: k for k, v in SEVERITY_RANK.items()}
CONF_RANK = {"high": 3, "medium": 2, "low": 1}

# Findings that are coverage gaps / errors are not risk evidence.
NON_EVIDENCE_STATUS = {"error", "not_tested", "not_applicable"}

FINDING_POINTS = {"critical": 40, "high": 25, "medium": 12, "low": 4, "info": 0}
CAPABILITY_POINTS = {
    "shell_execution": 12,
    "credential_access": 10,
    "filesystem_write": 8,
    "network_access": 6,
    "database_access": 6,
    "email_access": 5,
    "filesystem_read": 3,
}

CAPABILITY_LABELS = {
    "shell_execution": "Shell",
    "filesystem_read": "Filesystem (read)",
    "filesystem_write": "Filesystem (write)",
    "network_access": "Network",
    "credential_access": "Credentials",
    "database_access": "Database",
    "email_access": "Email",
}
CAPABILITY_VERB = {
    "shell_execution": "executes",
    "filesystem_read": "reads",
    "filesystem_write": "writes",
    "network_access": "communicates with",
    "credential_access": "accesses",
    "database_access": "accesses",
    "email_access": "communicates with",
}

# Heatmap columns. 'capabilities' columns light up when the tool has the capability; 'finding_categories'
# columns light up from findings in those categories that name the tool.
HEATMAP_COLUMNS: list[dict[str, Any]] = [
    {"id": "poisoning", "label": "Poisoning", "finding_categories": ["prompt_injection", "unicode", "naming", "collision"]},
    {"id": "input", "label": "Input", "finding_categories": ["schema", "dynamic_path", "dynamic_cmdi", "dynamic_size", "dynamic_malf", "dynamic_viol"]},
    {"id": "network", "label": "Network", "capabilities": ["network_access", "email_access"]},
    {"id": "filesystem", "label": "Filesystem", "capabilities": ["filesystem_read", "filesystem_write"]},
    {"id": "shell", "label": "Shell", "capabilities": ["shell_execution"]},
    {"id": "secrets", "label": "Credentials / Data", "capabilities": ["credential_access", "database_access"]},
]

INJECTION_CATEGORIES = {"prompt_injection", "unicode"}


def _is_evidence(f: dict[str, Any]) -> bool:
    return f.get("status") not in NON_EVIDENCE_STATUS and f.get("category") != "engine"


def _band(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _max_severity(findings: list[dict[str, Any]]) -> str:
    best = 0
    for f in findings:
        best = max(best, SEVERITY_RANK.get(f.get("severity", "info"), 0))
    return RANK_SEVERITY.get(best, "none") if best else "none"


def _findings_by_tool(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        if not _is_evidence(f):
            continue
        for t in f.get("affected_tools") or []:
            out.setdefault(str(t), []).append(f)
    return out


def tool_exposure(tool: dict[str, Any], tool_findings: list[dict[str, Any]]) -> dict[str, Any]:
    points = 0
    reasons: list[dict[str, Any]] = []
    for f in tool_findings:
        p = FINDING_POINTS.get(f.get("severity", "info"), 0)
        if f.get("status") == "informational":
            p = 0
        if p:
            reasons.append({"kind": "finding", "label": f"{f.get('rule_id')}: {f.get('title')}", "points": p})
            points += p
    for cap in tool.get("capabilities") or []:
        p = CAPABILITY_POINTS.get(cap, 0)
        if p:
            reasons.append({"kind": "capability", "label": CAPABILITY_LABELS.get(cap, cap), "points": p})
            points += p
    score = min(100, points)
    return {"score": score, "band": _band(score), "reasons": reasons}


def build_analysis(scan: dict[str, Any], tools: list[dict[str, Any]], findings: list[dict[str, Any]]) -> dict[str, Any]:
    by_tool = _findings_by_tool(findings)
    tool_rows: list[dict[str, Any]] = []
    for t in tools:
        tf = by_tool.get(t["name"], [])
        non_info = [f for f in tf if f.get("status") != "informational"]
        tool_rows.append(
            {
                "name": t["name"],
                "capabilities": t.get("capabilities") or [],
                "finding_count": len(non_info),
                "max_severity": _max_severity(non_info),
                "exposure": tool_exposure(t, tf),
            }
        )
    tool_rows.sort(key=lambda r: (-r["exposure"]["score"], r["name"]))
    return {
        "scan_id": scan["id"],
        "exposure_note": "Per-tool exposure is a display ranking (finding severity + capability weight). It is not part of the RISK-1 scan score.",
        "tools": tool_rows,
        "heatmap": build_heatmap(tools, findings),
        "graph": build_graph(scan, tools, by_tool),
        "attack_paths": build_attack_paths(tools, findings),
    }


# --------------------------------------------------------------------------- heatmap
def build_heatmap(tools: list[dict[str, Any]], findings: list[dict[str, Any]]) -> dict[str, Any]:
    by_tool = _findings_by_tool(findings)
    cap_finding_cats = {"capability", "permission"}
    rows: list[dict[str, Any]] = []
    for t in tools:
        tf = by_tool.get(t["name"], [])
        caps = set(t.get("capabilities") or [])
        cells: list[dict[str, Any]] = []
        for col in HEATMAP_COLUMNS:
            evidence: list[str] = []
            finding_ids: list[str] = []
            sev = "none"
            matched: list[dict[str, Any]] = []
            if "finding_categories" in col:
                cats = set(col["finding_categories"])
                matched = [f for f in tf if f.get("category") in cats and f.get("status") != "informational"]
            if "capabilities" in col:
                present = [c for c in col["capabilities"] if c in caps]
                for c in present:
                    evidence.append(f"capability: {CAPABILITY_LABELS.get(c, c)}")
                if present:
                    matched = [f for f in tf if f.get("category") in cap_finding_cats and f.get("status") != "informational"]
                    sev = "info"
            for f in matched:
                evidence.append(f"{f.get('rule_id')}: {f.get('title')}")
                finding_ids.append(str(f.get("id", "")))
            if matched:
                sev = _max_severity(matched)
            cells.append({"column": col["id"], "level": sev, "evidence": evidence[:8], "finding_ids": finding_ids[:20]})
        rows.append({"tool": t["name"], "cells": cells})
    return {"columns": [{"id": c["id"], "label": c["label"]} for c in HEATMAP_COLUMNS], "rows": rows}


# --------------------------------------------------------------------------- graph
def build_graph(scan: dict[str, Any], tools: list[dict[str, Any]], by_tool: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = [
        {"id": "server", "kind": "server", "label": scan.get("target_label") or "MCP server", "level": "none"}
    ]
    edges: list[dict[str, Any]] = []
    caps_seen: dict[str, int] = {}
    for t in tools:
        tf = [f for f in by_tool.get(t["name"], []) if f.get("status") != "informational"]
        nodes.append({"id": f"tool:{t['name']}", "kind": "tool", "label": t["name"], "level": _max_severity(tf), "finding_count": len(tf)})
        edges.append({"source": "server", "target": f"tool:{t['name']}", "verb": "invokes"})
        for c in t.get("capabilities") or []:
            caps_seen[c] = caps_seen.get(c, 0) + 1
            edges.append({"source": f"tool:{t['name']}", "target": f"cap:{c}", "verb": CAPABILITY_VERB.get(c, "accesses")})
    for c, n in sorted(caps_seen.items()):
        level = "high" if c in ("shell_execution", "credential_access") else "medium" if c in ("filesystem_write", "network_access") else "low"
        nodes.append({"id": f"cap:{c}", "kind": "capability", "label": CAPABILITY_LABELS.get(c, c), "level": level, "tool_count": n})
    return {"nodes": nodes, "edges": edges}


# --------------------------------------------------------------------------- attack paths
def _min_conf(confs: list[str]) -> str:
    if not confs:
        return "low"
    return min(confs, key=lambda c: CONF_RANK.get(c, 1))


def _node(stage: str, label: str, status: str, **kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"stage": stage, "label": label, "status": status, "tools": [], "finding_ids": [], "evidence": [], "confidence": None, "category": None}
    base.update(kw)
    return base


def build_attack_paths(tools: list[dict[str, Any]], findings: list[dict[str, Any]], limit: int = 12) -> list[dict[str, Any]]:
    """Build attack-chain candidates from evidence only.

    Source      : a confirmed/suspected prompt-injection or hidden-text finding on a tool (untrusted metadata).
    Invocation  : the agent can be steered to call another tool (documented tool-poisoning mechanism;
                  always 'potential', never presented as observed).
    Collection  : a tool with filesystem-read or credential capability.
    Egress      : a tool with network capability.
    Outcome     : always labelled 'potential'.
    A path is `complete` only when every non-potential stage has evidence; otherwise the missing stages are listed.
    """
    evid = [f for f in findings if _is_evidence(f) and f.get("status") in ("confirmed", "suspected")]
    sources = [f for f in evid if f.get("category") in INJECTION_CATEGORIES and f.get("severity") != "info"]
    combo = [f for f in evid if f.get("rule_id") == "CAP-010"]

    def with_cap(*caps: str) -> list[dict[str, Any]]:
        return [t for t in tools if any(c in (t.get("capabilities") or []) for c in caps)]

    readers = with_cap("filesystem_read", "credential_access")
    egress = with_cap("network_access")
    shells = with_cap("shell_execution")

    def source_node(f: dict[str, Any] | None) -> dict[str, Any]:
        if f is None:
            return _node("untrusted_input", "Untrusted input vector", "missing", evidence=["No injection or hidden-text finding was recorded in this scan."])
        tool = (f.get("affected_tools") or [""])[0]
        return _node(
            "untrusted_input",
            f"Untrusted tool metadata: {tool}" if tool else "Untrusted tool metadata",
            "evidenced",
            tools=[tool] if tool else [],
            finding_ids=[str(f.get("id", ""))],
            evidence=[f"{f.get('rule_id')}: {f.get('title')}"] + [str(e.get("summary", ""))[:200] for e in (f.get("evidence") or [])[:2] if isinstance(e, dict)],
            confidence=f.get("confidence", "medium"),
            category=f.get("category"),
        )

    def cap_node(stage: str, label: str, tl: list[dict[str, Any]], caps: tuple[str, ...]) -> dict[str, Any]:
        if not tl:
            return _node(stage, label, "missing", evidence=[f"No tool with capability {' / '.join(CAPABILITY_LABELS[c] for c in caps)} was observed."])
        t = tl[0]
        return _node(
            stage,
            f"{label}: {t['name']}",
            "evidenced",
            tools=[t["name"]],
            evidence=[f"capability {CAPABILITY_LABELS.get(c, c)} inferred for {t['name']}" for c in caps if c in (t.get("capabilities") or [])],
            confidence="medium",
            category="capability",
        )

    paths: list[dict[str, Any]] = []
    src_list: list[dict[str, Any] | None] = list(sources[:4]) if sources else ([None] if combo else [])
    for src in src_list:
        s_node = source_node(src)
        inv = _node(
            "tool_invocation",
            "Agent invokes another tool",
            "potential",
            evidence=["Tool-poisoning mechanism: instructions in tool metadata can steer which tools the agent calls. Not observed in this scan."],
            confidence="low",
            category="mechanism",
        )
        reader_opts: list[dict[str, Any] | None] = list(readers[:2]) or [None]
        net_opts: list[dict[str, Any] | None] = list(egress[:2]) or [None]
        for reader in reader_opts:
            for net in net_opts:
                nodes = [
                    s_node,
                    inv,
                    cap_node("collection", "Reads files / credentials", [reader] if reader else [], ("filesystem_read", "credential_access")),
                    cap_node("egress", "Network egress", [net] if net else [], ("network_access",)),
                    _node("outcome", "Potential data exfiltration", "potential", evidence=["Outcome if every preceding stage is exploitable; not demonstrated by static evidence."], confidence="low"),
                ]
                paths.append(_finish(nodes, "data_exfiltration"))
        nodes = [
            s_node,
            inv,
            cap_node("execution", "Shell execution", shells[:1], ("shell_execution",)),
            _node("outcome", "Potential command execution", "potential", evidence=["Outcome if the shell tool accepts attacker-influenced arguments; not demonstrated by static evidence."], confidence="low"),
        ]
        paths.append(_finish(nodes, "command_execution"))

    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for p in sorted(paths, key=lambda p: (not p["complete"], -p["evidence_ratio"])):
        sig = json.dumps([(n["stage"], n["status"], n["tools"]) for n in p["nodes"]], sort_keys=True)
        if sig in seen:
            continue
        seen.add(sig)
        unique.append(p)
    return unique[:limit]


def _finish(nodes: list[dict[str, Any]], kind: str) -> dict[str, Any]:
    evidenced = [n for n in nodes if n["status"] == "evidenced"]
    required = [n for n in nodes if n["status"] != "potential"]
    complete = all(n["status"] == "evidenced" for n in required)
    missing = [n["stage"] for n in nodes if n["status"] == "missing"]
    confs = [n["confidence"] for n in evidenced if n["confidence"]]
    pid = hashlib.sha1(json.dumps([(n["stage"], n["tools"]) for n in nodes]).encode(), usedforsecurity=False).hexdigest()[:10]
    return {
        "id": f"{kind}-{pid}",
        "kind": kind,
        "complete": complete,
        "label": "Potential attack path" if complete else "Potential attack path - incomplete evidence",
        "missing_stages": missing,
        "confidence": _min_conf(confs) if complete else "low",
        "evidence_ratio": round(len(evidenced) / max(1, len(required)), 2),
        "nodes": nodes,
    }


# --------------------------------------------------------------------------- compare
def _fkey(f: dict[str, Any]) -> str:
    return f"{f.get('rule_id')}|{','.join(sorted(str(t) for t in (f.get('affected_tools') or [])))}"


def _hash(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()[:12]


def compare_scans(
    a: dict[str, Any], a_tools: list[dict[str, Any]], a_findings: list[dict[str, Any]],
    b: dict[str, Any], b_tools: list[dict[str, Any]], b_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    fa = {_fkey(f): f for f in a_findings if _is_evidence(f)}
    fb = {_fkey(f): f for f in b_findings if _is_evidence(f)}

    def brief(f: dict[str, Any]) -> dict[str, Any]:
        return {"id": f.get("id"), "rule_id": f.get("rule_id"), "title": f.get("title"), "severity": f.get("severity"), "affected_tools": f.get("affected_tools") or [], "category": f.get("category")}

    new = [brief(f) for k, f in fb.items() if k not in fa]
    resolved = [brief(f) for k, f in fa.items() if k not in fb]
    changed = [{**brief(fb[k]), "from": fa[k].get("severity"), "to": fb[k].get("severity")} for k in fa if k in fb and fa[k].get("severity") != fb[k].get("severity")]
    ta = {t["name"]: t for t in a_tools}
    tb = {t["name"]: t for t in b_tools}
    tools_changed: list[dict[str, Any]] = []
    caps_changed: list[dict[str, Any]] = []
    for name in sorted(set(ta) & set(tb)):
        if _hash([ta[name].get("description"), ta[name].get("input_schema")]) != _hash([tb[name].get("description"), tb[name].get("input_schema")]):
            tools_changed.append({"name": name, "what": "description/schema"})
        ca, cb = set(ta[name].get("capabilities") or []), set(tb[name].get("capabilities") or [])
        if ca != cb:
            caps_changed.append({"name": name, "added": sorted(cb - ca), "removed": sorted(ca - cb)})

    def summary(s: dict[str, Any], fs: list[dict[str, Any]], tl: list[dict[str, Any]]) -> dict[str, Any]:
        ev = [f for f in fs if _is_evidence(f) and f.get("status") != "informational"]
        return {
            "id": s["id"], "label": s.get("target_label"), "created_at": s.get("created_at"),
            "risk_score": s.get("risk_score"), "findings": len(ev),
            "critical": sum(1 for f in ev if f.get("severity") == "critical"),
            "high": sum(1 for f in ev if f.get("severity") == "high"),
            "tools": len(tl),
        }

    return {
        "a": summary(a, a_findings, a_tools),
        "b": summary(b, b_findings, b_tools),
        "new_findings": new,
        "resolved_findings": resolved,
        "changed_severity": changed,
        "tools_added": sorted(set(tb) - set(ta)),
        "tools_removed": sorted(set(ta) - set(tb)),
        "tools_changed": tools_changed,
        "capabilities_changed": caps_changed,
        "note": "Findings are matched by rule id + affected tools. Scans of different targets are comparable only structurally.",
    }
