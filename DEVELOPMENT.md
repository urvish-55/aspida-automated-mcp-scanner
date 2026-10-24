# DEVELOPMENT.md

## Project layout

```
backend/
  api/          FastAPI app, routes, middleware, upload security
  core/         config (env), logging (redaction), version constants
  database/     async engine/session, ScanRepository
  models/       SQLAlchemy 2.0 ORM (scans, findings, tools, tests, events)
  schemas/      Pydantic request/response models
  scanners/
    mcp_ingest.py      normalizer (mcpServers/manifest/tools-list/single tool)
    static/            6 analyzers + engine (error isolation)
    dynamic/           connector, probes, safety controller, response analyzer
    semantic/          provider abstraction (disabled/local/external)
  risk/         fusion (dedup) + deterministic scoring (RISK-1)
  ml/           features, synthetic dataset, train/evaluate/predict
  reports/      canonical builder + ReportLab PDF
  workers/      pipeline orchestrator + asyncio task registry
  tests/        pytest suites (unit/integration/security)
frontend/       React 18 + TypeScript (Vite), pages/components/services
fixtures/       clean + deliberately vulnerable TEST FIXTURE servers
ml/artifacts/   trained model + metadata.json (generated)
.github/workflows/  CI (lint, typecheck, tests, frontend, security)
```

## Setup (Windows PowerShell shown; Linux/macOS: use `.venv/bin/`)

```bash
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
cd frontend; npm install; npm run build; cd ..
.venv\Scripts\python -m backend.ml.train
```

## Dev loop

```bash
# backend (serves API + built frontend)
.venv\Scripts\python -m uvicorn backend.api.app:app --reload --port 8000

# frontend hot-reload (proxies /api to :8000)
cd frontend && npm run dev        # http://localhost:5173

# tests
.venv\Scripts\python -m pytest -q
.venv\Scripts\python -m ruff check backend fixtures
.venv\Scripts\python -m mypy backend   # gating (see mypy.ini)
```

## Conventions & invariants (enforced by tests, not just docs)

1. **Await chaining**: `(await session.execute(q)).scalars().all()` — never
   `await session.execute(q).scalars()` (precedence bug).
2. **Evidence-first**: every finding carries evidence with a WHY; static
   analyzers are pure functions; per-analyzer crashes become ENGINE-001
   findings, never aborts.
3. **Honest statuses**: `confirmed|suspected|informational|not_tested|
   not_applicable|error`; skipped ≠ passed; progress = completed stage weights.
4. **No secrets**: env **values** are never ingested (keys only); logs redact;
   API never echoes settings.
5. **Inert payloads only**: forbidden-token invariant unit-tested
   (`rm`, `format`, `kill`, `curl`, … must never appear in probe payloads).
6. **Determinism**: analyzers run in registration order; fusion/risk are pure;
   same input ⇒ same findings, order, score.
7. **Versions**: RULESET_VERSION bumps with any rule-logic change;
   ML artifacts are version-locked to the feature schema at runtime.

## Adding a static rule

1. Implement in the relevant analyzer (or add a new `StaticAnalyzer` class +
   register it in `static/engine.py::ANALYZER_CLASSES`).
2. Evidence: kind/summary/detail(dict with `why`).
3. Map new rule_ids in `risk/fusion.py::_RULE_TOPIC` (or deliberately leave
   unmapped — distinct topics never merge).
4. Add unit tests (positive, negative, evidence-shape) under `backend/tests/`.
5. Bump `RULESET_VERSION` if detection behavior changes.

## Adding a dynamic probe family

1. Extend `ProbeGenerator` (keep payloads inert; add rationale + indicators).
2. Map the family prefix in `dynamic/engine.py::FAMILY_PREFIX`.
3. Add rejection/success indicators conservatively — ambiguity must stay
   ambiguous in `ResponseAnalyzer`.
4. Extend the fixture server + dynamic integration tests.

## Releasing

- `APP_VERSION` in `backend/core/version.py` (semver); `/api/version` and
  every report carry it.
- CI (`.github/workflows/ci.yml`) must pass: lint, typecheck (gating mypy),
  frontend build, full pytest, dependency audit, secret scan.
