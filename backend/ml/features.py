"""Feature extraction for the ML assistance model.

Features are deterministic functions of a tool's metadata (name, description,
schema). No network, no LLM, no randomness. The feature list is versioned:
ML_FEATURE_SCHEMA_VERSION must match the trained artifact's version or the
runtime refuses to predict (mixing schemas would silently corrupt results).
"""

from __future__ import annotations

import re
from typing import Any

from backend.core.version import ML_FEATURE_SCHEMA_VERSION

FEATURE_NAMES: tuple[str, ...] = (
    "name_len",
    "desc_len",
    "desc_sentences",
    "second_person_count",
    "imperative_start_ratio",
    "invisible_unicode_count",
    "bidi_unicode_count",
    "homoglyph_count",
    "exclamation_ratio",
    "uppercase_ratio",
    "url_count",
    "schema_param_count",
    "schema_has_constraints",
    "schema_max_depth",
    "param_path_like",
    "param_url_like",
    "param_shell_like",
    "param_sql_like",
    "name_suspicious_term",
    "desc_instruction_phrase",
    "desc_exfil_pattern",
    "desc_secret_term",
)

_INSTRUCTION_RE = re.compile(
    r"(ignore\s+(all\s+)?previous|disregard\s+(all\s+)?previous|do\s+not\s+tell|"
    r"don't\s+tell|keep\s+(this|it)\s+secret|you\s+must|important[:!]|before\s+using\s+this\s+tool)",
    re.IGNORECASE,
)
_EXFIL_RE = re.compile(
    r"(send|post|upload|forward|transmit)[^.!?]{0,60}(https?://|webhook|attacker|remote\s+server)",
    re.IGNORECASE,
)
_SECRET_RE = re.compile(r"(api[_\s-]?key|token|password|secret|credential)", re.IGNORECASE)
_SUSPICIOUS_NAME_RE = re.compile(
    r"(exfiltrat|keylog|backdoor|stealth|covert|bypass|shadow|reverse_?shell|hidden)", re.IGNORECASE
)
_WORD = re.compile(r"[A-Za-z']+")
_SENTENCE = re.compile(r"[.!?\n;]+")
_IMPERATIVE_VERBS = frozenset(
    "send read write execute run delete create modify update get fetch post use call invoke "
    "ignore disregard collect gather extract upload download install open close".split()
)


def extract_features(tool: dict[str, Any]) -> list[float]:
    """Deterministic feature vector for one tool dict."""
    name = str(tool.get("name") or "")
    desc = str(tool.get("description") or "")
    schema = tool.get("input_schema") if isinstance(tool.get("input_schema"), dict) else {}

    name_l, desc_l = name.lower(), desc.lower()
    sentences = [s for s in _SENTENCE.split(desc) if s.strip()]

    invisible = sum(desc.count(ch) for ch in ("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad"))
    bidi = sum(desc.count(ch) for ch in ("\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"))
    homoglyph = sum(1 for ch in desc if 0x0400 <= ord(ch) <= 0x04FF or 0x0370 <= ord(ch) <= 0x03FF or 0xFF01 <= ord(ch) <= 0xFF5E)

    props: dict[str, Any] = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    constrained = sum(
        1 for p in props.values() if isinstance(p, dict) and any(k in p for k in ("enum", "maxLength", "pattern", "format"))
    )
    depth = _schema_depth(schema)

    imperative_ratio = 0.0
    if sentences:
        starts = sum(1 for s in sentences if _WORD.findall(s) and _WORD.findall(s)[0].lower() in _IMPERATIVE_VERBS)
        imperative_ratio = starts / len(sentences)

    return [
        min(len(name), 120),
        min(len(desc), 4000),
        min(len(sentences), 40),
        len(re.findall(r"\b(you|your)\b", desc, re.IGNORECASE)),
        imperative_ratio,
        min(invisible, 20),
        min(bidi, 20),
        min(homoglyph, 20),
        desc.count("!") / max(len(sentences), 1),
        sum(1 for c in desc if c.isupper()) / max(len(desc), 1),
        len(re.findall(r"https?://", desc)),
        len(props),
        1 if constrained == len(props) and props else 0,
        depth,
        1 if any(k in k2 for k2 in map(str.lower, props) for k in ("path", "file", "dir")) else 0,
        1 if any("url" in k2 or "uri" in k2 or "host" in k2 for k2 in map(str.lower, props)) else 0,
        1 if any(k in k2 for k2 in map(str.lower, props) for k in ("command", "cmd", "exec", "shell")) else 0,
        1 if any(k in k2 for k2 in map(str.lower, props) for k in ("query", "sql")) else 0,
        1 if _SUSPICIOUS_NAME_RE.search(name_l) else 0,
        1 if _INSTRUCTION_RE.search(desc_l) else 0,
        1 if _EXFIL_RE.search(desc_l) else 0,
        1 if _SECRET_RE.search(desc_l) else 0,
    ]


def _schema_depth(schema: dict[str, Any], depth: int = 0) -> int:
    if depth > 6 or not isinstance(schema, dict):
        return depth
    best = depth
    props = schema.get("properties")
    if isinstance(props, dict):
        for v in props.values():
            best = max(best, _schema_depth(v if isinstance(v, dict) else {}, depth + 1))
    items = schema.get("items")
    if isinstance(items, dict):
        best = max(best, _schema_depth(items, depth + 1))
    return best


def feature_schema_version() -> str:
    return ML_FEATURE_SCHEMA_VERSION
