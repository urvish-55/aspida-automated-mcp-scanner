# Automated MCP Pentester

An evidence-first security scanner for **Model Context Protocol (MCP)** servers
and configurations. Free, open-source, fully functional **without any LLM or
paid API**.

> **What it can and cannot guarantee**
> This tool reports evidence-backed findings from the checks that actually ran.
> It can **never** certify a target as "secure". A scan cannot prove the
> absence of all vulnerabilities. See [LIMITATIONS.md](LIMITATIONS.md).

## What it does

| Capability | Mode | Notes |
|---|---|---|
| Hidden/deceptive Unicode detection (zero-width, bidi, homoglyphs) | static | confirmed presence; classified, not just "Unicode found" |
| Prompt / tool-poisoning detection (agent-directed instructions, exfiltration wording, secret harvesting, tool chaining) | static | linguistic + structural analysis, every match carries a WHY |
| Tool-name collision / shadowing (exact, case-insensitive, near-duplicate, similar descriptions) | static | honest confirmed/potential/informational levels |
| Input-schema weakness (missing schema, unconstrained strings, path/command/URL/SQL-like parameters) | static | per-parameter evidence and recommendations |
| Capability graph + dangerous combinations (e.g. read+network, shell+network) | static | reported as attack surface, never as proven exploitability |
| Dynamic probing (path-traversal sentinels, inert echo-marker command injection, oversized/malformed/enum-violating input) | dynamic, optional | safe-by-default, inert payloads only, full safety controller |
| Optional semantic second opinion | both | provider abstraction (disabled / Ollama / external); never authoritative |
| Advisory ML prioritization | both | trained on a synthetic corpus; never creates/overrides findings |
| Deterministic risk score (0–100) with full formula breakdown | both | documented weights, no opaque AI number |
| JSON + professional 14-section PDF report | both | includes mandatory limitations section |
| Web dashboard (React + TypeScript) | — | real data only; empty state says "No scans performed yet." |

Evidence statuses are always explicit: `confirmed` / `suspected` /
`informational` / `not_tested` / `not_applicable` / `error`. Skipped work is
never reported as passed.

## Architecture (one paragraph)

FastAPI backend with an async scan pipeline (queued → running → completed/failed/cancelled)
persisting to SQLite (PostgreSQL-ready schema). The pipeline ingests MCP
metadata into a normalized model, runs six deterministic static analyzers,
optionally connects to a live server (SSRF-guarded) and executes inert probes
under a safety controller (request budget, payload caps, timeouts, rate limit,
cancellation, audit log), optionally consults an LLM provider, fuses and
deduplicates evidence, scores risk deterministically, and serves results + PDF
to a React/TS dashboard served by the same process. Details:
[ARCHITECTURE.md](ARCHITECTURE.md). Threat model: [THREAT_MODEL.md](THREAT_MODEL.md).

## Install (free setup)

Requirements: Python 3.11+ (3.13 tested), Node.js 18+ (22 tested). All
dependencies are free/open-source (see "Dependencies" below).

```bash
python -m venv .venv
# Windows (PowerShell/cmd):
.venv\Scripts\python -m pip install -r requirements.txt
# Linux/macOS:
.venv/bin/python -m pip install -r requirements.txt

# frontend deps + build (the backend serves the built SPA)
cd frontend && npm install --no-fund --no-audit && npm run build && cd ..

# optional: train the advisory ML model
.venv\Scripts\python -m backend.ml.train   # Linux: .venv/bin/python -m backend.ml.train
```

## Run

```bash
# from the project root
.venv\Scripts\python -m uvicorn backend.api.app:app --host 127.0.0.1 --port 8000
# Linux/macOS:
.venv/bin/python -m uvicorn backend.api.app:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000/ — the dashboard is served by the same process
(API docs at `/api/docs`).

## Docker

```bash
docker compose up --build
```

This starts the API + dashboard on port 8000. To also run the deliberately
vulnerable test fixture (TEST FIXTURE ONLY):

```bash
docker compose up --build api vulnerable-fixture
# fixture: http://127.0.0.1:8101/mcp
```

To let the API scan the local fixtures, enable local targets **for your lab**:
`ALLOW_LOCAL_TARGETS=true` in `.env` (see [.env.example](.env.example)). Keep it
`false` in production.

## API key

Authentication is on by default. On first start the server creates a random key in `data/api_key`
(or set `API_KEY=<16+ chars>` in `.env`). The dashboard asks for it once per browser tab. For scripts:
`curl -H "X-API-Key: $(cat data/api_key)" http://127.0.0.1:8000/api/scans`.
The validation script reads the same file/variable automatically.

## Run your first scan

1. Dashboard → **New Scan**.
2. Paste an MCP config (`mcpServers` JSON), a tools/list result, or choose
   *Server URL* for dynamic testing. "Load example" buttons insert clearly
   labeled synthetic fixtures.
3. Keep the defaults for a first look: **safe mode ON, dynamic OFF, LLM OFF**.
4. Watch the live progress page (real pipeline stages, real percentages), then
   explore Results / Findings / Tool Explorer / Risk / Report.

CLI equivalents (examples):

```bash
# clean fixture demo
python fixtures/clean_server.py &                # terminal 1
# then create a URL scan against http://127.0.0.1:8100/mcp via the UI/API
```

## Run the tests

```bash
.venv\Scripts\python -m pytest -q        # 121 tests: unit + integration + security + detection regressions
cd frontend && npm run build             # strict TS typecheck + bundle
.venv\Scripts\python -m ruff check backend fixtures

# final acceptance (API + both fixtures must be running):
python fixtures/clean_server.py & python fixtures/vulnerable_server.py &
.venv\Scripts\python -m uvicorn backend.api.app:app --port 8000 &
# with ALLOW_LOCAL_TARGETS=true in .env (local fixtures only):
.venv\Scripts\python backend\tests\validation_ah.py    # writes validation_report.json
```

## Demo flow (synthetic, clearly labeled)

- **Clean fixture** → scan → no findings from enabled tests + explicit
  "cannot prove absence" language.
- **Vulnerable fixture** → scan → multiple evidence-backed findings
  (poisoning, hidden Unicode, schema weakness, shadowing; dynamically confirmed
  traversal + command-marker detection) → high risk score → PDF report.

## Security of the scanner itself

- No arbitrary command execution; uploaded files are parsed, never run.
- SSRF-guarded egress: scheme allowlist, private/link-local/metadata ranges
  blocked unless explicitly allowed, redirects re-validated, no auto-follow.
- Safe-by-default dynamic testing with audited safety controller.
- Secret redaction in logs; env values are never ingested (keys only).
- Rate limiting, size limits, generated upload filenames, non-root Docker.
  Details: [SECURITY.md](SECURITY.md).

## Detection benchmark

`python -m benchmark.evaluate` measures the poisoning detectors on 373 real tool definitions from open-source
MCP servers (false positives), plus published attack excerpts and a third-party synthetic set (recall), each
reported separately with confidence intervals. See [benchmark/RESULTS.md](benchmark/RESULTS.md) for what is
out-of-sample and what is not.

## Dashboard (v0.3)

The UI is a full investigation workspace: Overview, scan wizard, live scan console, findings explorer with an
investigation drawer and remediation tracking (open / acknowledged / in progress / resolved / false positive /
accepted risk), tool explorer (cards, graph, capability heatmap), evidence-based attack paths, risk analysis,
security insights, ML analysis, evidence viewer with a Unicode inspector, scan comparison, reports and system health.
`Ctrl+K` opens the command palette. Everything is computed from stored scan data; where something was not analyzed
the UI says so. Scans of local test targets are labelled DEMO DATA.

Development: `cd frontend && npm install && npm run dev` (http://localhost:5173, proxies `/api` to :8000).
After pulling this version run `npm install` once for the new dependencies.

## 3D Command Center (v0.4)

Open `3D Command Center` in the sidebar. It draws the selected scan's server, tools, capabilities and findings in 3D, with attack paths,
a finding-category galaxy, a capability network, a risk terrain and the scan pipeline. Everything is built from stored scan data; see
`FRONTEND_3D.md` for what each shape means and what is deliberately not shown. Run `npm install` in `frontend/` after upgrading (new
dependencies: three, @react-three/fiber, @react-three/drei, zustand). `npm test` runs the frontend unit tests.

## Documentation map

[ARCHITECTURE.md](ARCHITECTURE.md) · [SECURITY.md](SECURITY.md) ·
[THREAT_MODEL.md](THREAT_MODEL.md) · [DEVELOPMENT.md](DEVELOPMENT.md) ·
[TESTING.md](TESTING.md) · [API.md](API.md) · [ML.md](ML.md) ·
[LIMITATIONS.md](LIMITATIONS.md) · [fixtures/README.md](fixtures/README.md)

## License note

Built entirely on free/open-source components (FastAPI, SQLAlchemy, ReportLab,
scikit-learn, React, Vite). No paid APIs, no paid datasets, no accounts.
