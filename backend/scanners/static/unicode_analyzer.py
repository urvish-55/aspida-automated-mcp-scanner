"""Hidden/deceptive Unicode analysis.

Detects and *classifies* suspicious Unicode in tool-facing text:

- invisible formatting characters (zero-width, joiners, soft hyphen, BOM)
- bidirectional control characters (Trojan Source style spoofing)
- homoglyphs (Cyrillic/Greek/fullwidth look-alikes of ASCII)

The presence of a character is an objective, confirmable fact, so findings for
invisible/bidi characters are ``confirmed`` with high confidence. Homoglyph
detection is heuristic (context decides whether it is deceptive), so those are
``suspected`` findings. Original data is never rewritten: evidence carries both
the original and an escaped representation plus code point and category.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass

from backend.scanners.mcp_ingest import NormalizedTarget
from backend.scanners.static.base import Evidence, StaticAnalyzer, StaticFinding, iter_tool_text

# Invisible formatting characters that have no legitimate role in tool
# descriptions/names and are commonly used to hide instructions or spoof names.
INVISIBLE_CHARS: dict[str, str] = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE (BOM)",
    "\u00ad": "SOFT HYPHEN",
    "\u180e": "MONGOLIAN VOWEL SEPARATOR",
    "\u2061": "FUNCTION APPLICATION (invisible operator)",
    "\u2062": "MULTIPLICATION SIGN (invisible operator)",
    "\u2063": "SEPARATOR (invisible operator)",
    "\u2064": "PLUS SIGN (invisible operator)",
}

# Bidirectional controls: can reorder rendered text (Trojan Source / RTLO).
BIDI_CHARS: dict[str, str] = {
    "\u202a": "LEFT-TO-RIGHT EMBEDDING",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING",
    "\u202c": "POP DIRECTIONAL FORMATTING",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE",
    "\u2066": "LEFT-TO-RIGHT ISOLATE",
    "\u2067": "RIGHT-TO-LEFT ISOLATE",
    "\u2068": "FIRST STRONG ISOLATE",
    "\u2069": "POP DIRECTIONAL ISOLATE",
}

# Homoglyph maps: script look-alikes of common ASCII letters/digits.
HOMOGLYPHS: dict[str, str] = {
    # Cyrillic
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u0455": "s", "\u04bb": "h", "\u04d1": "a", "\u0101": "a",
    # Greek
    "\u03bf": "o", "\u03b1": "a", "\u03b5": "e", "\u03c1": "p",
    "\u03c5": "u", "\u03bd": "v", "\u03ba": "k", "\u03b9": "i",
    # Fullwidth forms
    **{chr(cp): chr(cp - 0xFEE0) for cp in range(0xFF01, 0xFF5F)},
}

RISK_REASON = {
    "invisible": (
        "Invisible characters are not rendered, so a human reviewing the text would not see "
        "anything unusual while an LLM still reads the hidden content. They are a common "
        "vector for hiding instructions or spoofing tool names."
    ),
    "bidi": (
        "Bidirectional control characters can reorder how text is displayed, so the rendered "
        "order can differ from the logical order that the model reads (Trojan-Source style "
        "spoofing)."
    ),
    "homoglyph": (
        "The text contains look-alike characters from other scripts; this can be legitimate "
        "international text, but in a tool name it can be used to impersonate another tool "
        "(see collision findings) or hide a keyword from human review."
    ),
}


@dataclass
class CharHit:
    char: str
    codepoint: str
    name: str
    category: str
    klass: str  # invisible|bidi|homoglyph
    field_name: str
    field_label: str
    context: str  # surrounding visible context
    position: int
    ascii_equivalent: str | None = None


def _context_around(text: str, pos: int, radius: int = 30) -> str:
    start = max(0, pos - radius)
    end = min(len(text), pos + radius + 1)
    snippet = text[start:end]
    # Escape for readable evidence display without altering stored data.
    return snippet.encode("unicode_escape").decode("ascii")


def scan_text(text: str, field_name: str, field_label: str) -> list[CharHit]:
    hits: list[CharHit] = []
    for pos, ch in enumerate(text):
        if ch in INVISIBLE_CHARS or 0xE0000 <= ord(ch) <= 0xE007F:  # U+E0000 tag block: invisible text smuggling
            hits.append(
                CharHit(
                    char=ch,
                    codepoint=f"U+{ord(ch):04X}",
                    name=INVISIBLE_CHARS.get(ch) or f"TAG CHARACTER ({unicodedata.name(ch, 'unnamed')})",
                    category=unicodedata.category(ch),
                    klass="invisible",
                    field_name=field_name,
                    field_label=field_label,
                    context=_context_around(text, pos),
                    position=pos,
                )
            )
        elif ch in BIDI_CHARS:
            hits.append(
                CharHit(
                    char=ch,
                    codepoint=f"U+{ord(ch):04X}",
                    name=BIDI_CHARS[ch],
                    category=unicodedata.category(ch),
                    klass="bidi",
                    field_name=field_name,
                    field_label=field_label,
                    context=_context_around(text, pos),
                    position=pos,
                )
            )
        elif ch in HOMOGLYPHS and ch not in ("\u0405",):  # exclude plain uppercase-ish oddities
            ascii_eq = HOMOGLYPHS[ch]
            # Only flag when mixed into predominantly-ASCII text (spoofing signal),
            # to avoid flagging legitimate non-English descriptions wholesale.
            hits.append(
                CharHit(
                    char=ch,
                    codepoint=f"U+{ord(ch):04X}",
                    name=f"HOMOGLYPH of '{ascii_eq}'",
                    category=unicodedata.category(ch),
                    klass="homoglyph",
                    field_name=field_name,
                    field_label=field_label,
                    context=_context_around(text, pos),
                    position=pos,
                    ascii_equivalent=ascii_eq,
                )
            )
    return hits


def _is_predominantly_ascii(text: str) -> bool:
    if not text:
        return False
    ascii_count = sum(1 for c in text if ord(c) < 128)
    return ascii_count / len(text) >= 0.6


class UnicodeAnalyzer(StaticAnalyzer):
    rule_id_prefix = "UNICODE"

    def analyze(self, target: NormalizedTarget) -> list[StaticFinding]:
        findings: list[StaticFinding] = []
        for tool in target.tools:
            hits: list[CharHit] = []
            for field_name, label, text in iter_tool_text(tool):
                field_hits = scan_text(text, field_name, label)
                if field_name == "name":
                    # For names, homoglyphs matter even in short strings.
                    hits.extend(field_hits)
                else:
                    hits.extend(field_hits)

            if not hits:
                continue

            invisible = [h for h in hits if h.klass == "invisible"]
            bidi = [h for h in hits if h.klass == "bidi"]
            homoglyphs = [h for h in hits if h.klass == "homoglyph" and _is_predominantly_ascii(tool.name + tool.description)]

            if invisible or bidi:
                klass = "bidi" if bidi else "invisible"
                chars = bidi or invisible
                evidence = [
                    Evidence(
                        kind="unicode_char",
                        summary=(
                            f"{h.codepoint} {h.name} at position {h.position} in {h.field_label}"
                            f" (context: …{h.context}…)"
                        ),
                        detail={
                            "codepoint": h.codepoint,
                            "char_name": h.name,
                            "unicode_category": h.category,
                            "original": h.char,
                            "escaped": h.char.encode("unicode_escape").decode("ascii"),
                            "field": h.field_label,
                            "position": h.position,
                            "context_escaped": h.context,
                            "class": h.klass,
                        },
                    )
                    for h in chars[:20]
                ]
                findings.append(
                    StaticFinding(
                        rule_id="UNICODE-001" if klass == "invisible" else "UNICODE-002",
                        category="unicode",
                        severity="medium" if klass == "invisible" else "high",
                        title=(
                            f"Hidden Unicode characters in tool '{tool.name}'"
                            if klass == "invisible"
                            else f"Bidirectional control characters in tool '{tool.name}'"
                        ),
                        description=(
                            f"The {chars[0].field_label} of tool '{tool.name}' contains "
                            f"{len(chars)} hidden character(s) ({chars[0].name} and similar)."
                        ),
                        status="confirmed",
                        confidence="high",
                        evidence=evidence,
                        affected_tools=[tool.name],
                        impact=RISK_REASON[klass],
                        remediation=(
                            "Remove invisible/bidirectional characters from tool metadata. Review "
                            "the full text in an editor that reveals Unicode. If the tool is "
                            "third-party, obtain its metadata from a trusted channel."
                        ),
                        reproduction={
                            "type": "static",
                            "steps": [
                                f"Open the tool '{tool.name}' definition",
                                f"Inspect the {chars[0].field_label} for {chars[0].codepoint}",
                                "Render with Unicode escapes visible (e.g. JSON dump with ensure_ascii=True)",
                            ],
                        },
                        references=[
                            "CWE-1289 (improper concealment)",
                            "Trojan Source: https://trojansource.codes/",
                        ],
                    )
                )

            for h in homoglyphs[:10]:
                findings.append(
                    StaticFinding(
                        rule_id="UNICODE-003",
                        category="unicode",
                        severity="low",
                        title=f"Possible homoglyph in tool '{tool.name}'",
                        description=(
                            f"The {h.field_label} of tool '{tool.name}' mixes look-alike characters "
                            f"into predominantly ASCII text ({h.codepoint} ≈ '{h.ascii_equivalent}')."
                        ),
                        status="suspected",
                        confidence="medium",
                        evidence=[
                            Evidence(
                                kind="unicode_char",
                                summary=f"{h.codepoint} in {h.field_label} (context: …{h.context}…)",
                                detail={
                                    "codepoint": h.codepoint,
                                    "unicode_category": h.category,
                                    "original": h.char,
                                    "escaped": h.char.encode("unicode_escape").decode("ascii"),
                                    "ascii_equivalent": h.ascii_equivalent,
                                    "field": h.field_label,
                                    "position": h.position,
                                    "context_escaped": h.context,
                                    "class": "homoglyph",
                                },
                            )
                        ],
                        affected_tools=[tool.name],
                        impact=RISK_REASON["homoglyph"],
                        remediation=(
                            "Verify the tool name/identity character-by-character. Prefer ASCII "
                            "identifiers for tool names. If this is legitimate localized text, "
                            "document that to reviewers."
                        ),
                        references=["Unicode spoofing: https://unicode.org/reports/tr36/"],
                    )
                )
        return findings
