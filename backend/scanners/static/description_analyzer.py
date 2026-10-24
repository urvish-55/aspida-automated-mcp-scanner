"""Prompt / tool-poisoning detection (deterministic, explainable).

A tool description should DESCRIBE what the tool does. Instructions addressed
to the agent ("ignore previous instructions", "send the results to …", "do not
tell the user") are how tool poisoning works in the MCP threat model.

This analyzer never relies on keywords alone. It combines:
- agent-directed imperative language (curated verb list + sentence analysis)
- second-person address (descriptions should not address the agent as "you")
- instruction density (share of sentences that read as commands)
- exfiltration verbs paired with destinations
- secret-harvesting language
- references to invoking OTHER tools (shadowing/chaining attempts)
- hidden text (invisible Unicode co-occurring with instruction-like content)

Each match records the matched span plus a WHY explanation. Classification is
honest about uncertainty: a single indicator is ``suspected``; only multiple
independent indicators upgrade a finding to ``confirmed`` (confirmed presence
of poisoning indicators, phrased as such — never "confirmed malicious intent").
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from backend.scanners.mcp_ingest import NormalizedTarget
from backend.scanners.static.base import Evidence, StaticAnalyzer, StaticFinding
from backend.scanners.static.unicode_analyzer import scan_text as scan_unicode

# ---------------------------------------------------------------------------
# Linguistic resources
# ---------------------------------------------------------------------------

# Base-form verbs that typically start an imperative sentence when a
# description addresses an agent. Deliberately conservative: these are commands
# an agent could actually act on, not everyday verbs like "is" or "provides".
IMPERATIVE_VERBS: frozenset[str] = frozenset(
    """
    access add allow append ask bring build call capture change check clean clear collect
    combine compare complete compute connect consider continue copy create decrease delete
    destroy detect determine disable discard discover do download drop enable encode encrypt
    ensure erase execute extract fetch find gather get give grab handle hide ignore implement
    include increase inject insert install inspect keep kill launch load locate log make map
    merge modify move obtain omit open overwrite pass perform pick post prepare prevent print
    process provide pull push read record remove replace report retrieve run save scan search
    send set skip store submit suppress take transfer transmit trigger upload use validate
    verify wipe write
    """.split()
)

# Phrases that directly address or attempt to reprogram the agent.
AGENT_DIRECTED: tuple[tuple[str, str], ...] = (
    # (regex, why it matters)
    (r"ignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|other)\s+(instructions?|prompts?|rules?|directions?)",
     "Asks the agent to discard its prior instructions — a classic prompt-injection directive."),
    (r"disregard\s+(all\s+|any\s+)?(previous|prior|your|the)\s+(instructions?|rules?|policies?|guardrails?)",
     "Asks the agent to disregard its rules/guardrails."),
    (r"(new|updated|revised)\s+(system\s+)?instructions?",
     "Tries to supply replacement 'instructions', impersonating a system/developer channel."),
    (r"(system|developer|admin)\s+(prompt|message)",
     "References hidden system/developer channels the tool should never control."),
    (r"you\s+are\s+(now|no\s+longer)",
     "Attempts to redefine the agent's identity/role mid-conversation."),
    (r"(do\s+not|don't|never)\s+(tell|inform|notify|mention|reveal|disclose|show)\s+(the\s+)?user",
     "Covert behavior: instructs the agent to conceal actions from the user."),
    (r"(without|hidden\s+from|invisible\s+to)\s+(the\s+)?user('?s)?\s+(knowledge|awareness|consent|approval)",
     "Covert behavior: acts while hiding from the user."),
    (r"(this\s+is|these\s+are)\s+(a\s+)?(secret|confidential|hidden)\s+(instruction|message|note)",
     "Self-describes as a hidden instruction intended for the model, not the user."),
    (r"keep\s+(this|it)\s+(secret|hidden|confidential|quiet)",
     "Requests concealment from the user."),
    (r"(always|never)\s+(follow|obey)\s+(these\s+)?instructions?",
     "Attempts to establish standing authority over the agent."),
    (r"you\s+must\s+(obey|comply|follow)\b",
     "Asserts authority over the agent's behavior."),
    (r"(bypass|override|disable)\s+(the\s+)?(safety|security|guardrails?|filters?|restrictions?|policies?|permissions?)",
     "Asks the agent to defeat its own safety/permission mechanisms."),
)

# Indexes (into AGENT_DIRECTED above) whose single occurrence is conclusive
# evidence of a poisoning *indicator* (ignore-previous, concealment from the
# user, safety bypass). Everything else needs corroboration to be "confirmed".
CERTAIN_INDEXES = frozenset({0, 1, 5, 6, 7, 8, 11})

_ACTION_VERBS = r"(send|forward|include|read|copy|upload|pass|append|attach|log|exfiltrate|transmit|post|collect|add|fetch|open|cat|dump|leak)"

# (regex, why, certain)
AGENT_DIRECTED_EXTRA: tuple[tuple[str, str, bool], ...] = (
    (r"<\s*/?\s*(important|system|instructions?|secret|admin|override|assistant|developer)\s*>|\[\s*/?\s*(INST|SYSTEM)\s*\]",
     "Pseudo-markup (<IMPORTANT>, <SYSTEM>, [INST]) imitates a privileged prompt channel inside tool "
     "metadata — the signature of known MCP tool-poisoning attacks.", False),
    (r"(do\s+not|don't|never)\s+(tell|inform|notify|mention|reveal|disclose|show|say|let)\b[^.!?]{0,40}\b(user|human|operator|owner)\b",
     "Covert behavior: instructs the agent to hide something from the user.", True),
    (r"without\s+(telling|informing|notifying|alerting|asking)\s+(the\s+)?(user|human|operator)",
     "Covert behavior: acts without the user's knowledge.", True),
    (rf"\b(silently|quietly|secretly|covertly|stealthily|discreetly|invisibly)\s+(\w+\s+){{0,2}}{_ACTION_VERBS}\b",
     "Adverb of concealment attached to a data-moving action: instructs the agent to act covertly.", False),
    (r"before\s+(using|calling|invoking|running)\s+(this|the)\s+tool[,:]?\s+(you\s+)?(must\s+|should\s+|need\s+to\s+|first\s+)?"
     r"(read|open|send|access|load|cat|execute|pass|include|fetch)\b",
     "Pre-condition directive: tells the agent to perform an extra action before the tool runs — a common "
     "way to smuggle instructions into tool metadata.", False),
    (r"(otherwise|or\s+else|else)[^.!?]{0,40}\b(tool|it|this)\s+(will|would|might)\s+(not\s+work|fail|break|stop|crash)",
     "Coercion: threatens failure unless the agent follows the embedded instruction.", False),
)

# Multilingual variants of the highest-signal directives (non-English poisoning
# otherwise evades English-only rules). (regex, why, certain)
AGENT_DIRECTED_I18N: tuple[tuple[str, str, bool], ...] = (
    (r"ignora\w*\s+(todas?\s+)?(las\s+)?instrucciones\s+(anteriores|previas)"
     r"|ignor(e|ez)\s+(toutes\s+)?les\s+(instructions|consignes)\s+pr[eé]c[eé]dentes"
     r"|ignorier\w*\s+(alle\s+)?(vorherigen|bisherigen|obigen)\s+(anweisungen|instruktionen)"
     r"|ignor(e|a)\s+(todas\s+)?as\s+instru[cç][oõ]es\s+anteriores"
     r"|игнориру\w*\s+(все\s+)?(предыдущие|прежние)\s+инструкции"
     r"|忽略(之前|以上|先前|上述)?(的)?(所有)?(指令|指示|说明|提示)",
     "Asks the agent to discard its prior instructions (non-English variant of a classic prompt-injection directive).", True),
    (r"sin\s+(avisar|informar|decir(le)?|notificar)\s+(al\s+)?usuario|no\s+(le\s+)?(digas|cuentes|menciones)\s+(nada\s+)?al\s+usuario"
     r"|sans\s+(en\s+)?(informer|avertir|pr[eé]venir)\s+l.utilisateur|ne\s+(le\s+)?dis\s+(pas|rien)\s+[aà]\s+l.utilisateur"
     r"|ohne\s+(den\s+)?(benutzer|nutzer)\s+(zu\s+)?(informieren|benachrichtigen)|sag\w*\s+(es\s+)?dem\s+(benutzer|nutzer)\s+nicht"
     r"|不要(告诉|通知|提示)用户|请勿告知用户|не\s+(говори|сообщай)\w*\s+пользователю",
     "Covert behavior: hides actions from the user (non-English variant).", True),
)

# More directives: override-instructions, cross-tool conditional triggers, forced first use,
# authority/compliance claims. (regex, why, certain)
AGENT_DIRECTED_EXTRA2: tuple[tuple[str, str, bool], ...] = (
    (r"override\s+(all\s+|any\s+|the\s+|your\s+)?(previous\s+|prior\s+|other\s+|existing\s+)?(instructions?|rules|directives|system\s+prompt|settings)",
     "Asks the agent to override its instructions — a prompt-injection directive.", True),
    (r"when\s+(?:the\s+|a\s+)?\(?(?!(?:this|that|it|a|an|the|any|your)\b)[\w.\-]{2,64}\)?\s+(?:\w+\s+)?(?:tool\s+)?(?:is|are|gets)\s+"
     r"(?:invoked|called|used|run|executed|triggered)\b[^.!?]{0,160}?\b(make\s+sure|must|always|ensure|change|set|replace|redirect|add|modify|override|instead|append|include)\b",
     "Defines behavior to apply WHEN ANOTHER tool is invoked: a description should not reprogram other tools "
     "(cross-tool shadowing).", False),
    (r"(always|must|should|immediately)\s+(consult|call|use|invoke|run)\s+this\s+tool\s+(immediately|first|before|at\s+the\s+start)"
     r"|as\s+the\s+(very\s+)?first\s+step[^.!?]{0,40}before\s+(asking|answering|responding|doing)"
     r"|before\s+asking\s+(any\s+)?(clarifying\s+)?questions",
     "Forces the agent to use this tool before anything else (priority hijacking / line jumping).", False),
    (r"(this\s+tool\s+is\s+)?(required|mandatory|necessary)\s+for\s+(internal\s+)?(audit\w*|compliance|gdpr|soc\s?2|hipaa|legal|regulatory|security\s+review)",
     "Claims compliance/audit authority to pressure the agent into using the tool.", False),
)

# Best-effort translations of the two highest-signal directives for further languages.
AGENT_DIRECTED_I18N2: tuple[tuple[str, str, bool], ...] = (
    (r"(önceki|yukarıdaki|tüm)\s+(talimatları|yönergeleri|komutları)\s+(yok\s?say|göz\s+ardı|unut)"
     r"|ignora\s+(tutte\s+)?le\s+istruzioni\s+(precedenti|sopra)|negeer\s+(alle\s+)?(eerdere|vorige)\s+instructies"
     r"|以前の指示を無視|이전\s*지시(를|사항을)?\s*무시|تجاهل\s+(جميع\s+)?التعليمات\s+السابقة|पिछले\s+निर्देशों?\s+को\s+(अनदेखा|नज़रअंदाज़)",
     "Asks the agent to discard its prior instructions (non-English variant).", True),
    (r"kullanıcıya\s+(söylemeden|bildirmeden|haber\s+vermeden)|kullanıcıya\s+(söyleme|bildirme)\b"
     r"|senza\s+(dirlo|avvisare|informare)\s+(all.|l.)?utente|zonder\s+(het\s+)?(de\s+)?gebruiker\s+(te\s+)?(vertellen|informeren)"
     r"|ユーザーに(言わ|伝え|知らせ)ずに|사용자에게\s*(알리지|말하지)\s*(말|않)|دون\s+(إخبار|إبلاغ)\s+المستخدم|उपयोगकर्ता\s+को\s+बताए\s+बिना",
     "Covert behavior: hides actions from the user (non-English variant).", True),
)

# Access verbs in several languages (used together with a credential/config path).
SENSITIVE_ACCESS_VERB_I18N = (
    r"\b(oku|oku[ny]\w*|g[oö]nder\w*|ekle|lee|leer|lees|lire|lis|lies|lesen|leggi|ler|lê|прочита\w+|отправ\w+|читай|"
    r"읽|送信|読み|读取|读|发送|اقرأ|पढ़)"
)

SENSITIVE_PATH = (
    r"(~|\$HOME|%USERPROFILE%)?[/\\]?\.?(ssh[/\\]|aws[/\\]credentials|kube[/\\]config|gnupg|npmrc|netrc|git-credentials"
    r"|bash_history|zsh_history|docker[/\\]config\.json)|\bid_(rsa|ed25519|ecdsa|dsa)\b|/etc/(passwd|shadow)"
    r"|\bmcp\.json\b|claude_desktop_config|\.cursor[/\\]|\.claude[/\\]|(?<![\w/])\.env\b|credentials\.json|\bkeychain\b|wallet\.dat"
    r"|\.pem\b|\bprivate[_\s-]?key"
)
SENSITIVE_ACCESS_VERB = r"(read|open|cat|include|attach|load|get|access|copy|send|contents?\s+of|dump|steal|fetch|extract|retrieve|print)"

# "include the contents of X in the 'notes' argument" — data smuggled through a parameter.
PARAM_SMUGGLE = (
    r"(pass|include|put|add|supply|provide|set|insert|embed|append|attach|place|write)\s+(?:[^.!?]|\.(?=\S)){0,100}?"
    r"(contents?|output|results?|history|conversation|context|files?|keys?|tokens?|config\w*|credentials?|its\s+content)"
    r"(?:[^.!?]|\.(?=\S)){0,60}?\b(as|in|into|via|through|inside)\s+(the\s+)?"
    r"(['\"`]\w+['\"`]\s*(argument|parameter|param|field)?|\w+\s+(argument|parameter|param|field)\b)"
)

IMPERSONATION = (
    r"(?P<adj>secure|safe|reliable|trusted|official|verified|improved|better|enhanced|recommended|preferred|upgraded|authoritative)"
    r"[\w\s,\-]{0,60}?\b(replacement|substitute|alternative|drop-in|successor|upgrade|version)\s+(for|of|to)\s+[`'\"]?(?P<ref>[\w.\-]{2,64})[`'\"]?"
)

EXFIL_I18N = (
    r"(envia\w*|envía\w*|env[ií]e\w*|envoie\w*|envoyer|envoyez|sende\w*|schick\w*|发送|发给|发到|отправ\w+|भेज\w*)\b[^.!?]{0,120}https?://"
)

# Exfiltration: transfer verb + destination/urgency, in one sentence window.
EXFIL_VERBS = r"(send|sends|post|posts|upload|uploads|transmit|transmits|forward|forwards|exfiltrate[s]?|transfer[s]?|copy|copies|ship[s]?|phone\s+home)"
EXFIL_DEST = r"(to\s+(http|https|ftp|tcp)|to\s+(this|that|the\s+following|my|our)\s+(url|server|endpoint|address|host|webhook)|to\s+\S*webhook|to\s+attacker|externally|off\s?site|to\s+a\s+remote)"

SECRET_TERMS = (
    r"(api[_\s-]?keys?|access[_\s-]?tokens?|auth[_\s-]?tokens?|bearer\s+tokens?|passwords?|passphrases?|"
    r"credentials?|secrets?|private\s+keys?|ssh\s+keys?|session\s+cookies?|\.env\b|environment\s+variables)"
)
SECRET_COLLECT_STRONG = r"(collect|gather|harvest|steal|grab|extract|exfiltrate|locate|dump|reveal|expose|leak)"
SECRET_COLLECT_WEAK = r"(read|send|find|list|enumerate|forward|fetch|get)"
# a weak verb only counts when the secret is clearly the user's/agent's own stored material
SECRET_OWNER = r"(the\s+user'?s?|user'?s|your|my|any|all|stored|saved|local|available|environment|existing)\s+"
SECRET_METADATA_NEXT = r"(?!\s+(scanning|alerts?|manager|management|store|vault|rotation|names?|metadata|scopes?|versions?|policies|policy|detection|protection|settings?))"

TOOL_REFERENCE = (
    r"(use|call|invoke|execute|run|trigger|prefer|choose)\s+(the\s+)?(?!(this|that|these|those|the|a|an|it|same|following|tool|right|appropriate|correct)\b)"
    r"[`'\"]?([\w.\-]{2,64})[`'\"]?\s+tool\b"
    r"|(use|call|invoke)\s+(another|other|different|any\s+other|available)\s+(tool|function)s?\b"
    r"|(instead\s+of|rather\s+than)\s+(answering|responding|using)\b"
)

# Keywords that in a *tool name* are suspicious regardless of description.
SUSPICIOUS_NAME_TERMS = (
    r"(exfiltrat\w*|keylog\w*|backdoor|rootkit|stealth|covert|hidden_?tool|bypass|"
    r"credential_?dump|password_?sniff\w*|shadow_?(tool|copy)|token_?grab\w*|reverse_?shell)"
)

# "Use this tool when/to/for ..." is conventional documentation, not an instruction.
DOC_STYLE_USE = re.compile(r"(?i)^(use|call)\s+(this|the)\s+(tool|function|endpoint)\s+(when|to|for|if|in\s+order)\b")

SECOND_PERSON = re.compile(r"\b(you|your|you're|you'll|you've)\b", re.IGNORECASE)
# Split on sentence-ending punctuation only when followed by whitespace/end, so paths
# (~/.ssh/id_rsa), file names (mcp.json) and URLs are not torn apart.
SENTENCE_SPLIT = re.compile(r"[.!?]+(?=\s|$)|[\n;]+")
WORD = re.compile(r"[A-Za-z']+")

WHY_SECOND_PERSON = (
    "Tool descriptions normally describe functionality in the third person. Text addressed to "
    "the agent in the second person ('you must…') reads as instructions to the model rather "
    "than documentation for humans."
)


STRONG_CATEGORIES = frozenset(
    {"agent_directed", "exfiltration", "secret_harvesting", "tool_chaining", "sensitive_access", "param_smuggling"}
)
WEAK_CATEGORIES = frozenset({"impersonation"})


@dataclass
class TextMatch:
    category: str
    matched_text: str
    span: tuple[int, int]
    why: str
    sentence: str = ""
    extra: dict = field(default_factory=dict)


MAX_SCHEMA_NODES = 2000
MAX_SCHEMA_DEPTH = 12


def _schema_text_fields(schema: object) -> list[tuple[str, str]]:
    """Collect model-visible free text from a JSON schema (bounded walk)."""
    out: list[tuple[str, str]] = []
    budget = [MAX_SCHEMA_NODES]

    def walk(node: object, path: str, depth: int) -> None:
        if budget[0] <= 0 or depth > MAX_SCHEMA_DEPTH:
            return
        budget[0] -= 1
        if isinstance(node, dict):
            for key, value in node.items():
                here = f"{path}.{key}" if path else str(key)
                if key in ("description", "title", "default", "const", "$comment") and isinstance(value, str):
                    out.append((f"schema {here}", value))
                elif key in ("enum", "examples") and isinstance(value, list):
                    for i, v in enumerate(value[:50]):
                        if isinstance(v, str):
                            out.append((f"schema {here}[{i}]", v))
                else:
                    walk(value, here, depth + 1)
        elif isinstance(node, list):
            for i, v in enumerate(node[:200]):
                walk(v, f"{path}[{i}]", depth + 1)

    walk(schema, "", 0)
    return out


def _sentences(text: str) -> list[str]:
    return [s.strip() for s in SENTENCE_SPLIT.split(text) if s.strip()]


def _is_imperative(sentence: str) -> bool:
    words = WORD.findall(sentence)
    if not words:
        return False
    first = words[0].lower()
    if first in IMPERATIVE_VERBS:
        return True
    if first in {"always", "never", "must", "before", "after", "when", "whenever", "first", "then", "important", "note"}:
        rest = WORD.findall(sentence)
        if len(rest) >= 2 and rest[1].lower() in IMPERATIVE_VERBS:
            return True
    if re.match(r"(?i)^(do\s+not|don't)\b", sentence):
        return True
    return False


def _norm_tool(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def _find_matches(text: str, known_tools: frozenset[str] = frozenset()) -> list[TextMatch]:
    matches: list[TextMatch] = []
    sentences = _sentences(text)

    def span_of(sentence_text: str) -> tuple[int, int] | None:
        idx = text.find(sentence_text)
        return (idx, idx + len(sentence_text)) if idx >= 0 else None

    directed: list[tuple[str, str, bool]] = [
        (pattern, why, idx in CERTAIN_INDEXES) for idx, (pattern, why) in enumerate(AGENT_DIRECTED)
    ]
    directed += list(AGENT_DIRECTED_EXTRA) + list(AGENT_DIRECTED_EXTRA2) + list(AGENT_DIRECTED_I18N) + list(AGENT_DIRECTED_I18N2)
    for pattern, why, certain in directed:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            matches.append(
                TextMatch("agent_directed", m.group(0), (m.start(), m.end()), why, extra={"certain": certain})
            )

    for m in re.finditer(IMPERSONATION, text, re.IGNORECASE):
        ref_name = _norm_tool(m.group("ref"))
        if ref_name in known_tools and ref_name != "":
            continue
        matches.append(
            TextMatch(
                "impersonation",
                m.group(0),
                (m.start(), m.end()),
                "Presents itself as a trustworthy replacement for another tool. Impersonating a known tool is a "
                "shadowing technique: the agent may pick this tool instead of the one the user installed.",
            )
        )

    for m in re.finditer(PARAM_SMUGGLE, text, re.IGNORECASE):
        matches.append(
            TextMatch(
                "param_smuggling",
                m.group(0),
                (m.start(), m.end()),
                "Tells the agent to route data (file contents, history, credentials) through a tool "
                "argument — a known way to exfiltrate context via legitimate-looking parameters.",
            )
        )

    for s in sentences:
        if re.search(SENSITIVE_PATH, s, re.IGNORECASE) and (
            re.search(SENSITIVE_ACCESS_VERB, s, re.IGNORECASE) or re.search(SENSITIVE_ACCESS_VERB_I18N, s, re.IGNORECASE)
        ):
            path_hit = re.search(SENSITIVE_PATH, s, re.IGNORECASE)
            span = span_of(s) or (0, len(s))
            matches.append(
                TextMatch(
                    "sensitive_access",
                    s,
                    span,
                    "References a credential/config location (SSH keys, MCP configs, .env, cloud "
                    f"credentials: '{path_hit.group(0) if path_hit else ''}') together with an access verb. Tool "
                    "metadata has no legitimate reason to direct the agent to such files.",
                )
            )

    for s in sentences:
        if (re.search(EXFIL_VERBS, s, re.IGNORECASE) and re.search(EXFIL_DEST, s, re.IGNORECASE)) or re.search(
            EXFIL_I18N, s, re.IGNORECASE
        ):
            span = span_of(s) or (0, len(s))
            matches.append(
                TextMatch(
                    "exfiltration",
                    s,
                    span,
                    "Combines a data-transfer verb with an external destination: reads as a "
                    "request to move data off the local context, i.e. exfiltration.",
                )
            )

    secret_pats = (
        rf"{SECRET_COLLECT_STRONG}\s+[^.!?]{{0,80}}?{SECRET_TERMS}{SECRET_METADATA_NEXT}",
        rf"{SECRET_COLLECT_WEAK}\s+(?:[^.!?]{{0,60}}?\s)?{SECRET_OWNER}(?:\w+\s+){{0,2}}{SECRET_TERMS}{SECRET_METADATA_NEXT}",
    )
    secret_hits = [m for pat in secret_pats for m in re.finditer(pat, text, re.IGNORECASE)]
    for m in secret_hits:
        matches.append(
            TextMatch(
                "secret_harvesting",
                m.group(0),
                (m.start(), m.end()),
                "Pairs an acquisition verb with credential/secret terminology: reads as an "
                "instruction to obtain secrets rather than describe tool behavior.",
            )
        )

    for m in re.finditer(TOOL_REFERENCE, text, re.IGNORECASE):
        ref = re.search(r"[`'\"]?([\w.\-]{2,64})[`'\"]?\s+tool\b", m.group(0), re.IGNORECASE)
        if ref and _norm_tool(ref.group(1)) in known_tools:
            continue  # cross-reference to a sibling tool of the same server: ordinary documentation
        matches.append(
            TextMatch(
                "tool_chaining",
                m.group(0),
                (m.start(), m.end()),
                "A description that instructs the agent to invoke other tools can steer the "
                "agent into attacker-chosen tool chains (shadowing / chaining).",
            )
        )

    imperative = [
        s
        for i, s in enumerate(sentences)
        if i > 0 and _is_imperative(s) and not DOC_STYLE_USE.match(s)
    ]
    for s in imperative:
        span = span_of(s) or (0, len(s))
        matches.append(
            TextMatch(
                "imperative",
                s,
                span,
                "Sentence reads as a command (starts with a directive verb such as 'send', "
                "'read', 'execute'), i.e. instructions to an agent, not documentation.",
            )
        )

    # Overlap policy: strong-category matches are always kept (an exfiltration
    # directive must never be silently dropped because another strong indicator
    # shares the sentence). Only generic 'imperative' matches that overlap a kept
    # strong match are removed, to avoid redundant evidence. Exact repeats are
    # also removed.
    strong = STRONG_CATEGORIES
    kept: list[TextMatch] = []
    seen_keys: set[tuple] = set()
    for cand in sorted(matches, key=lambda x: (0 if x.category in strong else 1, x.span[0])):
        key = (cand.category, cand.matched_text, cand.span)
        if key in seen_keys:
            continue
        if cand.category == "imperative" and any(
            k.category in strong and cand.span[0] < k.span[1] and k.span[0] < cand.span[1] for k in kept
        ):
            continue
        seen_keys.add(key)
        kept.append(cand)
    return kept


def _evidence_for(match: TextMatch, field_label: str) -> Evidence:
    return Evidence(
        kind="text_match",
        summary=f"[{field_label}] {match.matched_text[:160]}",
        detail={
            "category": match.category,
            "matched_text": match.matched_text,
            "field": field_label,
            "why": match.why,
        },
    )


class DescriptionAnalyzer(StaticAnalyzer):
    rule_id_prefix = "POISON"

    def analyze(self, target: NormalizedTarget) -> list[StaticFinding]:
        findings: list[StaticFinding] = []
        known = frozenset(_norm_tool(t.name) for t in target.tools)
        for tool in target.tools:
            findings.extend(self._analyze_tool(tool.name, tool.description, known))
            findings.extend(self._analyze_schema_text(tool.name, tool.input_schema, known))
        return findings

    def _analyze_schema_text(self, tool_name: str, schema: dict, known_tools: frozenset[str] = frozenset()) -> list[StaticFinding]:
        """Poisoning can hide in parameter descriptions/titles/defaults/enums, which many
        clients forward to the model verbatim. Only strong categories are used here
        (imperative-style heuristics would misfire on normal parameter docs)."""
        fields = _schema_text_fields(schema)
        found: list[tuple[str, TextMatch]] = []
        for label, text in fields:
            for m in _find_matches(text, known_tools):
                if m.category in STRONG_CATEGORIES:
                    found.append((label, m))
        if not found:
            return []
        cats = {m.category for _, m in found}
        certain = any(m.extra.get("certain") for _, m in found)
        corroborated = certain or len(cats) >= 2
        evidence = [_evidence_for(m, label) for label, m in found[:12]]
        return [
            StaticFinding(
                rule_id="POISON-008",
                category="prompt_injection",
                severity="critical" if "exfiltration" in cats else "high",
                title=f"Poisoning indicators in input-schema text of tool '{tool_name}'",
                description=(
                    f"{len(found)} instruction-like span(s) were found in parameter descriptions, "
                    f"titles, defaults or enum values of tool '{tool_name}' (categories: "
                    f"{', '.join(sorted(cats))}). Clients commonly pass this text to the model, so it "
                    f"is an injection surface even when the top-level description is clean."
                ),
                status="confirmed" if corroborated else "suspected",
                confidence="high" if corroborated else "medium",
                evidence=evidence,
                affected_tools=[tool_name],
                impact="Schema text is model-visible but rarely reviewed by humans, so it is a favored hiding place for injected instructions.",
                remediation="Restrict parameter descriptions to factual input documentation and remove any instruction to the agent.",
                reproduction={
                    "type": "static",
                    "steps": [
                        f"Open the inputSchema of tool '{tool_name}'",
                        "Read each property's description/title/default/enum",
                        "Locate the quoted spans listed in the evidence",
                    ],
                },
                references=["OWASP LLM01 Prompt Injection"],
            )
        ]

    def _analyze_tool(self, tool_name: str, description: str, known_tools: frozenset[str] = frozenset()) -> list[StaticFinding]:
        if not description.strip():
            return []
        findings: list[StaticFinding] = []
        matches = _find_matches(description, known_tools)
        by_cat: dict[str, list[TextMatch]] = {}
        for m in matches:
            by_cat.setdefault(m.category, []).append(m)

        second_person_count = len(SECOND_PERSON.findall(description))
        sentences = _sentences(description)
        imperative = [m for m in matches if m.category == "imperative"]
        body_sentences = max(len(sentences) - 1, 0)  # first sentence is conventionally a verb phrase
        density = (len(imperative) / body_sentences) if body_sentences else 0.0

        strong_cats = [c for c in sorted(STRONG_CATEGORIES) if c in by_cat]
        corroborated = len(strong_cats) >= 2 or any(m.extra.get("certain") for m in matches)

        def make_finding(
            rule_id: str,
            severity: str,
            status: str,
            confidence: str,
            title: str,
            description_text: str,
            ms: list[TextMatch],
            impact: str,
            remediation: str,
            extra_refs: list[str] | None = None,
        ) -> StaticFinding:
            return StaticFinding(
                rule_id=rule_id,
                category="prompt_injection",
                severity=severity,  # type: ignore[arg-type]
                title=title,
                description=description_text,
                status=status,  # type: ignore[arg-type]
                confidence=confidence,  # type: ignore[arg-type]
                evidence=[_evidence_for(m, "tool description") for m in ms[:12]],
                affected_tools=[tool_name],
                impact=impact,
                remediation=remediation,
                reproduction={
                    "type": "static",
                    "steps": [
                        f"Open tool '{tool_name}' in the analyzed target",
                        "Read the tool description in full",
                        "Locate the quoted text spans listed in the evidence",
                    ],
                },
                references=extra_refs or ["OWASP LLM01 Prompt Injection: https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
            )

        if "exfiltration" in by_cat:
            ms = by_cat["exfiltration"]
            findings.append(
                make_finding(
                    "POISON-002",
                    "critical",
                    "confirmed" if corroborated else "suspected",
                    "high" if corroborated else "medium",
                    f"Exfiltration-style instruction in tool '{tool_name}'",
                    f"The description of tool '{tool_name}' contains text that requests data to be "
                    f"sent/transferred to an external destination. {len(ms)} matching span(s) found.",
                    ms,
                    "If an agent follows this text, context data (files, credentials, conversation "
                    "content) can be sent to an attacker-controlled destination.",
                    "Remove the instruction. Investigate the tool's source. If third-party and "
                    "unexplained, disable the tool and treat prior agent sessions as potentially "
                    "compromised.",
                    ["OWASP LLM02 Sensitive Information Disclosure"],
                )
            )

        if "agent_directed" in by_cat:
            ms = by_cat["agent_directed"]
            findings.append(
                make_finding(
                    "POISON-001",
                    "high",
                    "confirmed" if corroborated else "suspected",
                    "high",
                    f"Agent-directed instructions in tool '{tool_name}'",
                    f"The description of tool '{tool_name}' contains {len(ms)} instruction-like "
                    f"span(s) addressed to the AI agent rather than describing the tool.",
                    ms,
                    "A tool description is model-visible documentation. Instructions embedded in it "
                    "hijack agent behavior while remaining invisible in normal UI review.",
                    "Rewrite the description to describe functionality only. Treat behavior-changing "
                    "directives as untrusted content.",
                )
            )

        if "secret_harvesting" in by_cat:
            ms = by_cat["secret_harvesting"]
            findings.append(
                make_finding(
                    "POISON-003",
                    "high",
                    "suspected",
                    "medium",
                    f"Secret-harvesting language in tool '{tool_name}'",
                    f"The description of tool '{tool_name}' combines acquisition verbs with "
                    f"credential/secret terminology.",
                    ms,
                    "Tools whose metadata requests credentials/secrets can prime an agent to "
                    "disclose them from context or environment.",
                    "Remove the language; ensure secrets are never passed through tool descriptions "
                    "or tool arguments.",
                )
            )

        if "tool_chaining" in by_cat:
            ms = by_cat["tool_chaining"]
            findings.append(
                make_finding(
                    "POISON-004",
                    "medium",
                    "suspected",
                    "medium",
                    f"Cross-tool invocation instructions in tool '{tool_name}'",
                    f"The description of tool '{tool_name}' references invoking other tools; "
                    f"verify the referenced tools exist and the chaining is legitimate.",
                    ms,
                    "Embedded cross-tool instructions can shadow or chain into unintended "
                    "capabilities (e.g. 'read the file, then use the send_email tool').",
                    "Describe only this tool's behavior. Cross-tool workflows belong to the agent "
                    "orchestration layer, not tool metadata.",
                )
            )

        sens = by_cat.get("sensitive_access", []) + by_cat.get("param_smuggling", [])
        if sens:
            findings.append(
                make_finding(
                    "POISON-007",
                    "high",
                    "confirmed" if corroborated else "suspected",
                    "high" if corroborated else "medium",
                    f"Credential/file access or data-smuggling instruction in tool '{tool_name}'",
                    f"The description of tool '{tool_name}' directs the agent to sensitive files "
                    f"(e.g. SSH keys, MCP configs, .env) and/or to pass data through a tool argument. "
                    f"{len(sens)} matching span(s) found.",
                    sens,
                    "An agent following this text can read local secrets and leak them through an "
                    "ordinary-looking parameter, while the user sees only a harmless tool name.",
                    "Remove the instruction. Treat the tool as hostile until its source is reviewed, and "
                    "rotate any credentials that were reachable by the agent.",
                    ["OWASP LLM02 Sensitive Information Disclosure", "OWASP LLM06 Excessive Agency"],
                )
            )

        if "impersonation" in by_cat:
            ms = by_cat["impersonation"]
            findings.append(
                make_finding(
                    "POISON-009",
                    "medium",
                    "suspected",
                    "medium",
                    f"Tool '{tool_name}' presents itself as a trusted replacement for another tool",
                    f"The description of tool '{tool_name}' claims to be a secure/improved replacement for a different "
                    f"tool ({ms[0].matched_text[:100]!r}). This is a known shadowing technique, but wording alone is "
                    f"not proof of malicious intent.",
                    ms,
                    "Agents choose tools by their descriptions. A look-alike that claims to supersede a trusted tool "
                    "can capture the calls (and data) meant for that tool.",
                    "Verify the origin of the tool and the tool it claims to replace; remove it if unexpected.",
                    ["OWASP LLM06 Excessive Agency"],
                )
            )

        agent_ref = bool(re.search(r"\b(agent|assistant|llm|language\s+model|the\s+model|ai\s+model)\b", description, re.IGNORECASE))
        if density >= 0.5 and body_sentences >= 2 and (second_person_count >= 1 or agent_ref):
            findings.append(
                make_finding(
                    "POISON-005",
                    "low",  # style-only signal: weak evidence without a corroborating category
                    "suspected",
                    "medium",
                    f"Instruction-dense description in tool '{tool_name}'",
                    f"{int(round(density * 100))}% of sentences in the description of tool "
                    f"'{tool_name}' read as imperative instructions ({len(imperative)}/{body_sentences}), "
                    f"with {second_person_count} second-person reference(s). {WHY_SECOND_PERSON}",
                    imperative,
                    "Descriptions dominated by commands behave like a hidden system prompt rather "
                    "than documentation.",
                    "Rewrite as a factual description of inputs, outputs and side effects.",
                )
            )

        # Hidden text + instruction language = strongest static poisoning signal.
        hidden_hits = [h for h in scan_unicode(description, "description", "tool description") if h.klass in ("invisible", "bidi")]
        if hidden_hits and (matches or second_person_count):
            findings.append(
                StaticFinding(
                    rule_id="POISON-006",
                    category="prompt_injection",
                    severity="critical",
                    title=f"Hidden text combined with instruction language in tool '{tool_name}'",
                    description=(
                        f"The description of tool '{tool_name}' contains {len(hidden_hits)} invisible/bidi "
                        f"character(s) AND instruction-like language. Hidden characters can carry text a "
                        f"human reviewer never sees while the model still reads it."
                    ),
                    status="confirmed",
                    confidence="high",
                    evidence=[
                        Evidence(
                            kind="unicode_plus_text",
                            summary=f"{h.codepoint} ({h.name}) at position {h.position} in tool description",
                            detail={
                                "codepoint": h.codepoint,
                                "char_name": h.name,
                                "field": "tool description",
                                "position": h.position,
                                "context_escaped": h.context,
                                "instruction_categories_found": sorted({m.category for m in matches}) or ["second_person"],
                            },
                        )
                        for h in hidden_hits[:10]
                    ],
                    affected_tools=[tool_name],
                    impact=(
                        "This is the canonical tool-poisoning pattern: content that is invisible in "
                        "review but actionable by the model. Treat the hidden content as untrusted "
                        "instructions and extract it for manual review."
                    ),
                    remediation=(
                        "Extract the description with invisible characters removed and inspect what "
                        "the hidden text says. Disable the tool until its provenance is verified."
                    ),
                    reproduction={
                        "type": "static",
                        "steps": [
                            f"Serialize tool '{tool_name}' description as JSON with ensure_ascii=True",
                            "Locate the \\u200b / \\u202e style escapes listed in evidence",
                            "Delete them and re-read the surrounding text",
                        ],
                    },
                    references=[
                        "OWASP LLM01 Prompt Injection",
                        "Trojan Source: https://trojansource.codes/",
                    ],
                )
            )
        return findings
