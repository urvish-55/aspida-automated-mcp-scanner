# ARCHITECTURE

## System overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Frontend (React 18 + TypeScript + Vite, HashRouter)                    │
│  Dashboard · New Scan · Progress · Results · Findings · Tools ·         │
│  Risk · Reports · History · Settings · About                            │
└────────────▲────────────────────────────────────────────────────────────┘
             │ /api/* (fetch; same origin; Vite dev proxy in dev)
┌────────────┴────────────────────────────────────────────────────────────┐
│  FastAPI (backend/api)                                                  │
│  routes.py (REST) · middleware.py (rate limit) · uploads.py (safe files)│
│  app.py (lifespan: init_db; serves frontend/dist)                       │
└────────────▲────────────────────────────────────────────────────────────┘
             │ ScanRepository (async SQLAlchemy)
┌────────────┴────────────────────────────────────────────────────────────┐
│  Workers (backend/workers)                                              │
│  runner.py: asyncio task registry + cancel events                       │
│  pipeline.py: stage orchestration, real progress events, terminal states│
└──┬───────────┬──────────────┬───────────────┬───────────────┬──────────┘
   │           │              │               │               │
┌──▼─────┐ ┌───▼────┐  ┌──────▼──────┐  ┌─────▼─────┐  ┌──────▼───────┐
│ mcp_   │ │ static │  │ dynamic     │  │ semantic  │  │ ml           │
│ ingest │ │ engine │  │ engine      │  │ engine    │  │ (advisory)   │
│ (norm) │ │ 6 rules│  │ probes+safe │  │ provider  │  │ sklearn      │
└────────┘ └────────┘  │ controller  │  │ abstraction│ └──────────────┘
                       └─────────────┘  └───────────┘
   │
┌──▼──────────────────────┐   ┌──────────────────────────────────────────┐
│ risk/fusion.py          │   │ reports/builder.py → JSON                │
│ (dedup by topic+tools)  │──▶│ reports/pdf.py      → 14-section PDF     │
│ risk/engine.py (RISK-1) │   └──────────────────────────────────────────┘
└─────────────────────────┘
```

## Data model (backend/models/db.py)

- **scans** — one row per job: status machine (`queued→running→completed|failed|cancelled`),
  target info, effective configuration snapshot (incl. enabled stages and the
  raw inline target for the worker), reproducibility metadata (scanner/ruleset/
  ML versions), final risk score + full breakdown, semantic/ML status.
- **scan_findings** — deduplicated findings with full evidence JSON, affected
  tools, reproduction, impact/remediation, references, detector sources.
- **scan_tools** — tool inventory with inferred capability tags.
- **dynamic_tests** — one row per probe: status (`passed|failed|skipped|error|
  not_applicable|timeout`), detail, evidence, duration.
- **scan_events** — append-only audit/progress log (`seq`, `stage`, `event`,
  `message`, `level`, `progress`, `duration_ms`).

SQLite via aiosqlite; no SQLite-specific column types, UUIDs as strings,
JSON columns — the schema is PostgreSQL-portable.

## Scan pipeline stages (weights sum to 100)

`initializing(2) → parsing_target(8) → enumerating_tools(10) →
static_analysis(30) → dynamic_testing(25) → semantic_analysis(10) →
risk_aggregation(8) → report_generation(5) → completed(2)`

Progress percentages are computed from completed stage weights — never
extrapolated or faked. Every stage writes started/completed events (with
duration and message) that the UI polls.

Failure policy: ingest failure → scan `failed` with clear error; analyzer
crash → `ENGINE-001` informational finding (coverage gap, scan continues);
dynamic connection failure → honest `error` test record (scan completes);
semantic/ML unavailability → status fields, never scan errors; cancellation →
`cancelled` with partial data kept.

## Static analysis (backend/scanners/static)

Six analyzers run in deterministic order; each is a pure function over the
normalized target with per-analyzer error isolation:

| Analyzer | Rule IDs | Highlights |
|---|---|---|
| UnicodeAnalyzer | UNICODE-001/002/003 | invisible (11 char classes), bidi (9), homoglyphs (Cyrillic/Greek/fullwidth) with original+escaped+codepoint+category evidence; status confirmed for presence, suspected for deceptive-use interpretation |
| DescriptionAnalyzer | POISON-001…006 | agent-directed regexes, imperative-verb sentence analysis, instruction density, exfil verb+destination pairing, secret-harvest verbs, tool chaining, hidden-text+instructions combination (critical) |
| ToolNameAnalyzer | NAME-001 | covert/malicious naming patterns |
| SchemaAnalyzer | SCHEMA-000/001/010-013 | missing schema, unconstrained strings, path/command/URL/SQL-like parameters with concrete recommendations |
| CapabilityAnalyzer | CAP-001/010/020/021 | capability inference (name/description/params), 6 dangerous combinations with required-evidence statements, env-key and stdio-command informational findings (values never read) |
| CollisionAnalyzer | COLLISION-001…004 | exact/case-insensitive/normalized/near-duplicate names + near-identical descriptions |

## Dynamic testing (backend/scanners/dynamic)

- `connector.py` — MCP Streamable HTTP client: initialize handshake,
  tools/list, tools/call; manual redirect validation; session re-establish on
  404. No shell-outs, no subprocesses, ever.
- `safety.py` — SafetyController: max requests, payload cap, per-test timeout,
  min request interval (rate limit), cooperative cancellation, full audit log
  of allowed/refused requests. Refusals become `skipped` test records with
  reasons — never silent.
- `probes.py` — inert probe generation: traversal sentinels (`/etc/passwd`,
  `win.ini` lookups, URL-encoded), echo-marker command injection (per-scan
  random nonce; `; echo MARKER`, `$(echo …)`, backticks, `&&`, `|`, newline —
  nothing destructive), bounded oversized input, wrong-type/null/empty/missing/
  extra-field malformed probes, enum/pattern violations.
- `response_analyzer.py` — conservative verdicts: command injection confirmed
  only on unique-marker return; traversal confirmed only on sentinel content;
  ambiguous outcomes stay ambiguous; empty-string/extra-field acceptance is
  informationally recorded, not flagged (calibration against false positives).

## Evidence fusion & risk (backend/risk)

`fusion.py` merges findings that share a conservative issue *topic* mapping and
the same affected tools: severity = max, status upgrades only via dynamic
confirmation, confidence = max, evidence and detector sources are unioned, and
a `fusion_note` documents the merge. Distinct issues are never merged; engine
findings never merge.

`engine.py` (formula RISK-1) — documented weights and caps:
static (crit 20/high 12/med 6/low 2, cap 40) + dynamic confirmed (crit 30/high
20/med 10/low 4, cap 35) + capability combination (crit 15/high 10/med 5, +2
per extra, cap 20) + confidence threshold adjustment (−2…+2). Bands: 0–24 low,
25–49 moderate, 50–74 high, 75–100 critical. The full breakdown is stored per
scan and rendered in the UI and PDF.

## Semantic layer (backend/scanners/semantic)

Provider abstraction: `disabled` (default) | `local` (Ollama's OpenAI-compatible
endpoint) | `external` (any OpenAI-compatible API). The engine converts every
failure (unreachable, bad output, timeout, misconfiguration) into
`status="unavailable"|"error"` with a reason. Output is parsed defensively and
attached to matching findings as `semantic_review` metadata — it can never
create, upgrade, downgrade or remove a finding.

## ML (backend/ml)

Advisory-only prioritization. Features are deterministic functions of tool
metadata (22 features, versioned). Training uses a seeded synthetic corpus
(benign vs. poisoned templates with controlled perturbations). Because the
corpus is trivially separable, the honest `model_status` is
"NOT PRODUCTION READY — synthetic separation too easy…"; the runtime treats
predictions as advisory context and refuses version mismatches. See ML.md.

## Reports (backend/reports)

`builder.py` produces the canonical structure (14 sections, mandatory
limitations, coverage/skipped/error accounting, reproducibility metadata).
`pdf.py` renders it with ReportLab (free), XML-escaping all dynamic text;
failures raise `PdfReportError` → HTTP 500 with a clear message.

## Deployment notes

Single-process deployment (uvicorn workers=1) is the supported shape: the
in-process runner owns scan tasks. For horizontal scaling, move the pipeline to
a queue worker (Celery/Arq/RQ + Redis) and Postgres — the repository/pipeline
separation is designed for that extraction; nothing else in the codebase
assumes in-process execution.
