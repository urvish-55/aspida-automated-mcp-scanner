# LIMITATIONS.md — what this scanner can and cannot do

Read this before trusting any output. The scanner is designed to be honest
about coverage; this page is the authoritative list of known limits.

## The mandatory statement

> **A scan cannot prove the absence of all vulnerabilities.**
> "No vulnerabilities were detected by the enabled tests" means exactly that —
> nothing more. It is never equivalent to "this MCP server is secure."

## Static analysis limits

- Metadata-only: static rules see names, descriptions, schemas, annotations —
  never server-side behavior. A tool with a pristine description and a
  malicious implementation produces **no** static finding.
- Heuristics: false positives and false negatives are expected. Capability
  inference is name/description/parameter-name based and can mislabel.
- Linguistic poisoning detection is English-first. The highest-signal directives
  (ignore-previous-instructions, concealment from the user, exfiltration to a URL)
  are also covered in Spanish, French, German, Portuguese, Russian and Chinese;
  other languages, paraphrases and homoglyph tricks may still evade it.
- Prompt-injection "confirmation" means *confirmed presence of poisoning
  indicators*, not confirmed malicious intent — that judgment stays human.
- Unicode detection covers the documented invisible/bidi/homoglyph sets;
  exotic look-alikes outside the maps are not classified.

## Dynamic testing limits

- Coverage: a handful of inert probes per tool (traversal sentinels, echo
  markers, bounded oversized/malformed/enum-violating values). The input
  space actually exercised is a tiny, deliberately safe fraction.
- Ambiguity is preserved: no sentinel and no rejection ⇒ *inconclusive*, not
  "passed".
- Only Streamable-HTTP MCP targets are supported for dynamic scans; stdio
  servers are analyzed statically from their configs (the scanner never
  launches them).
- Findings depend on the live server's responses; a target that detects and
  evades probes can mask behavior (the scanner announces itself via User-Agent).

## Scanner self-security limits (see SECURITY.md §8)

- **DNS rebinding**: closed for dynamic scans by DNS pinning (see SECURITY.md §2). Residual: scans
  that must go through an HTTP proxy are not supported (a proxy would resolve names itself).
- Authentication is one shared API key: no per-user identity, roles or audit trail. Use TLS
  (reverse proxy) when the API is reachable from other machines.
- Rate limiting and the failed-auth throttle are per-process (single node).
- Upload protection is size/parse based; extremely hostile JSON is depth-
  bounded but should additionally pass an edge proxy in adversarial settings.

## ML limits

See ML.md — in short: synthetic-only training, perfect-on-synthetic score
treated as "NOT PRODUCTION READY", advisory only, never authoritative.

## Semantic layer limits

Disabled by default; requires an explicit provider. When configured, LLM
opinions are annotations with their own failure modes (hallucination,
sycophancy); they never alter findings. Provider unavailability is reported
honestly (`unavailable` + reason), never papered over.

## Product limits

- Uploads: `POST /api/uploads` returns a stored name that can be passed to
  `POST /api/scans` as `uploaded_file` (config scans).
- Single-process deployment (in-process asyncio runner). Horizontal scaling
  requires extracting the pipeline to a queue worker (repository/pipeline
  separation anticipates this).
- SQLite storage by default; PostgreSQL-ready schema but untested against a
  live Postgres.
- E2E browser automation of the UI is not in CI (manually verified).

## Evidence-status semantics (recap)

| Status | Meaning |
|---|---|
| `confirmed` | objective evidence observed (character present, marker returned, sentinel content seen) |
| `suspected` | indicator present but interpretation depends on context |
| `informational` | observation without risk judgment |
| `not_tested` | coverage gap — explicitly not performed |
| `not_applicable` | test doesn't apply to this target/configuration |
| `error` | the check itself failed; it is NOT a pass |

Skipped and errored tests are always counted and displayed — never converted
into passes, never silently dropped.
