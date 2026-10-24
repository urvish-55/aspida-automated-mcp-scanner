# TESTING.md — what is tested and what the results are

Run everything:

```bash
.venv\Scripts\python -m pytest -q
cd frontend && npm run build      # strict TypeScript check + bundle
.venv\Scripts\python -m ruff check backend fixtures
```

## Current results (actual, from this repository)

- **pytest: 150 tests** (includes 10 investigation-API tests; 1 DNS-dependent test skips automatically when offline) — unit + integration + security + detection-regression suites.
- **Final validation A–H: 8/8 PASS** (script: `python backend/tests/validation_ah.py`
  against a running API + fixtures; durable record written to
  `validation_report.json`).
- **Frontend build: passes** under `"strict": true` TypeScript (tsc -b + vite).
- **Ruff: clean** on `backend/` and `fixtures/` (default rule set).
- **mypy**: clean on `backend/` (`mypy.ini`) and a **gating** CI job. The experimental ML package and test files are excluded from the gate.

## Suite map

| File | Covers |
|---|---|
| `test_unicode.py` | invisible/bidi/homoglyph detection, codepoint+category+position evidence, original-data preservation, clean-text negatives |
| `test_description.py` | poisoning categories (agent-directed, exfiltration, secret harvesting, tool chaining, density, hidden-text combo), WHY-explanations, benign negatives |
| `test_schema_capability_collision.py` | schema rules incl. constrained-schema negatives; capability inference + dangerous combos (suspected-not-confirmed, env values never captured); collision levels (exact/case/near) |
| `test_risk_fusion.py` | RISK-1 arithmetic (caps, bands, confidence thresholds, error/not_tested exclusion), dedup merging (same-topic/same-tools, no cross-tool merge, no score inflation) |
| `test_ingest_and_probes.py` | all ingest shapes, JSON-error tolerance, env-value exclusion, fingerprint stability; probe generation incl. forbidden-token invariant, bounded sizes, omission-probe correctness |
| `test_detection_regressions.py` | publicly documented attack patterns the scanner previously missed (`<IMPORTANT>` poisoning, paraphrased/multilingual exfiltration, poisoning in parameter text), documentation-style false-positive guards, schema severity/dedup, upload-to-scan flow |
| `test_auth.py` | API-key enforcement (missing/wrong/valid via Bearer and X-API-Key), public endpoints, preflight, failed-attempt throttling, no key leakage, key generation/permissions |
| `test_benchmark.py` | loose regression bounds on the real-data benchmark (skipped if corpora absent) |
| `test_security.py` | SSRF policy (10 blocked targets incl. metadata endpoint, scheme allowlist, credentials-in-URL, unresolvable host), upload validation (size/extension/JSON/traversal), server-side authorization gate, SafetyController budget/payload/cancel, rate-limit middleware flood |
| `test_api_integration.py` | full pipeline on poisoned + clean configs, findings filters, report JSON structure, PDF validity, validation errors (auth/SSRF/broken JSON), unreachable-target graceful failure, broken-target clear failure, delete, dashboard truthfulness, uploads |
| `test_dynamic_integration.py` | live fixture servers: vulnerable fixture yields confirmed DYN-PATH-001 + DYN-CMDI-001 with evidence+reproduction; **clean fixture yields zero dynamic findings** (false-positive guard) |

## Validation tests A–H (final acceptance)

Run: start API (`python -m uvicorn backend.api.app:app --port 8000`) + both
fixtures, then `python backend/tests/validation_ah.py`. Latest actual run:
**8/8 PASS** — A clean (0 non-informational findings) · B unicode evidence ·
C poisoning (`POISON-002`) · D capability (`CAP-010`, suspected) · E weak schema
(`SCHEMA-001/011/013`) · F dynamic (`DYN-PATH-001` + `DYN-CMDI-001`, 34 probes) ·
G graceful 422 on unresolvable host · H no-LLM (semantic `skipped`, scan works).

## Gaps

- No E2E browser automation of the React UI in CI (manually verified; pages
  render live data, empty states, filters). Playwright would be the next step.
- Load/performance testing not performed; limits are enforced but throughput
  characteristics on a "normal workstation" are unbenchmarked.
- mypy runs in non-strict mode (`check_untyped_defs`); `backend/ml` and tests are excluded.

## Frontend verification (0.3.0)

Run against a real backend and the local fixtures in headless Chromium: full scan journey (wizard -> live console ->
findings -> investigation drawer -> triage persisted across reload), tools graph/heatmap, attack paths, evidence viewer,
command palette, notifications, light theme, compare, login with auth enabled (wrong key rejected, sign-out), 1,500-finding
scan (list virtualized: ~11 cards in the DOM), axe-core WCAG 2.0 A/AA on every page in both themes (0 violations), and
no horizontal overflow at 390px and 768px. Test scans against local fixtures are labelled DEMO DATA in the UI.

## Frontend unit tests (0.4.0)

`cd frontend && npm test` runs vitest (60 tests): security-graph transform, node/edge generation, severity mapping, filtering,
attack-path highlighting, selection sync between the store, the 2D fallback and the list, scan-event derivation (no animation unless the
backend says running), quality resolution incl. reduced motion, safe text, layout at 10/100/500 tools, empty states, and WebGL-unavailable
fallback. Browser checks (Playwright, headless Chromium with SwiftShader): 3D renders in all six modes, canvas picking, Esc, Ctrl+K focus,
no-WebGL fallback, 390px layout without overflow, reduced motion, axe-core with 0 violations on `/command` and `/unicode` in both themes.
Idle 60 fps with 1,004 objects (500 tools + 500 findings) in software rendering.
