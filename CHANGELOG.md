# Changelog

## 0.5.1
- Story rebuilt around an MCP Security Core with layered environment, data streams, scanner passes, threat containment, click-to-focus, boot overlay, "Skip 3D experience", real stage list and evidence fields, and the new copy (THREAT DETECTED, ATTACK PATH NOT VERIFIED, REMEDIATION NOT VERIFIED).
- Fix: unmounting the 3D canvas no longer counts as a lost WebGL context.

## 0.5.0
- New scroll-driven 3D story at `#/journey`: 12 sections, central timeline, real scan data, labelled illustrative example, 2D/reduced-motion fallbacks, SEO meta.
- Shell renders `/journey` full-bleed; sidebar entry "3D Journey".

## 0.4.0 - 3D investigation interface

- **Fix: URL scans now run static analysis on the live tool metadata.** Live servers were enumerated by name only (empty
  description/schema), so poisoning, schema and capability rules never fired. Descriptions, schemas and annotations from
  `tools/list` are now stored and analysed.
- Unicode rule now flags invisible tag characters (U+E0000 block).
- New fixture `fixtures/vulnerable_server_2.py` (port 8102): poisoning, fake credentials, SQL echo, SSRF-style fetch, email
  exfil channel, dangerous capabilities, rug pull, hidden tag characters. All inert.

- **3D Command Center** (`#/command`): React Three Fiber scene (lazy-loaded, separate `three` chunk) over the existing scan data.
  Six modes: Security Graph, Attack Paths, Threat Galaxy, Capability Network, Risk Terrain, Scan Mode. Details in `FRONTEND_3D.md`.
- Selection, hover, filters, search and attack-path state live in one zustand store shared by the 3D scene, the 2D fallback, the
  object list and the inspector, so 2D and 3D always agree. Ctrl+K focuses nodes; "View in 3D" from findings; "Open 3D Investigation" from Overview/Reports.
- Inspector for server / tool / capability / finding / attack-path stage / risk cell / pipeline stage; full finding drawer reused.
- Scan comparison overlay (new / changed findings highlighted; "no longer detected" is never called resolved).
- Complete 2D fallback (no WebGL, context lost, small screens, user choice), accessible object list, text severity everywhere.
- Quality (Auto/Low/Medium/High) and Effects (Full/Reduced/Off) settings; `prefers-reduced-motion` disables animation.
- Unicode Inspector page + `POST /api/unicode/inspect` (code point, Unicode name, category, script, bidi, UTF-8, suspicious flags).
- Untrusted MCP text is sanitised before it reaches a 3D label (`safeLabel`: invisible/bidi characters shown as `⟦U+XXXX⟧`).
- Frontend unit tests (vitest, 60 tests): graph transform, layout at 10/100/500 nodes, filters, highlighting, selection sync,
  scan-event derivation, quality resolution, 2D fallback, a11y names, safe text.

## 0.3.0

- **ML model retrained on real data** (`python -m backend.ml.train_real`): MCPTox (485 poisoned tool descriptions) plus
  ~28.7k real registry tools as benign candidates; description-text input, grouped cross-validation, thresholds at fixed
  false-positive rates, independent evaluation. Honest result: 5 of 10 independent hand-written attacks caught; status
  EXPERIMENTAL. The old synthetic model moved to `ml/artifacts_synthetic/` and is no longer loaded.
- ML advisory now scores the scan's actual tool descriptions and lists `flagged_tools` in the report and PDF.
- ML Analysis page shows cross-validation, independent check, thresholds and caveats. `/api/ml/info` gained the same fields.
- Known gap documented in ML.md: the static poisoning rules flag only 16.5% of MCPTox attacks.

- **New dashboard UI** (React + Tailwind + Radix + Framer Motion + Recharts + TanStack Query/Virtual):
  collapsible sidebar app shell with mobile drawer, Ctrl+K command palette (tools, findings, scans, reports, actions),
  notification centre, dark/light theme, system-health indicator.
- Pages: Overview (risk gauge, live activity, capability heatmap, tool graph), 5-step scan wizard (with offline
  discovery preview and safety review), live scan console, Active scans, Scan history, Findings explorer
  (URL-driven filters, virtualized list, investigation drawer with triage), Tools (cards / graph / heatmap / detail),
  Attack paths, Risk analysis, Security insights, ML analysis, Evidence viewer (Unicode inspector), Reports (preview +
  downloads), Scan comparison, System health, Settings, About, Login.
- **New API endpoints** (see API.md "Investigation API"): `/scans/{id}/analysis`, `/compare`, `/findings` (cross-scan),
  `/findings/{id}`, `PATCH /findings/{id}/triage`, `/search`, `/activity`, `/notifications`, `POST /discover`,
  `/tools/history`, `/ml/info`, `/system/health`.
- **Remediation tracking** persisted in a new `finding_triage` table (created automatically; no migration needed).
- Attack paths are evidence-only: a path is "complete" only if every non-potential stage has evidence; invocation and
  outcome stages are always labelled "potential".
- Accessibility: axe-core (WCAG 2.0 A/AA) reports 0 violations on all pages in both themes; no horizontal scroll at 390px.
- Breaking for developers: run `npm install` in `frontend/` (new dependencies) and rebuild.

## 0.2.0

- **API authentication on by default** (API key; see SECURITY.md §2b). Breaking: clients/scripts must send the key.
- **DNS pinning** for dynamic scans (closes the rebinding window).
- **Detection benchmark** (`benchmark/`): 373 real tools, published attack excerpts, third-party synthetic set;
  first-run numbers and tuning history in `benchmark/RESULTS.md`.
- Ruleset 1.2.0: override-instructions, cross-tool conditional triggers, forced first use, compliance claims,
  trust-adjective impersonation (`POISON-009`), more languages, sibling-tool references no longer flagged,
  secret-harvesting wording requires user/stored-secret context, density rule gated on agent/second-person
  address and reported as low severity.
- Dashboard: sign-in screen, config file upload, authenticated report downloads.
- SPA static path check and upload path checks use `Path.is_relative_to`.

## 0.1.1

Detection
- POISON-001: added pseudo-markup (`<IMPORTANT>`, `<SYSTEM>`, `[INST]`), concealment-from-user variants,
  covert-adverb actions, pre-condition directives and coercion; multilingual (es/fr/de/pt/ru/zh) variants.
  A single unambiguous directive (ignore-previous, hide-from-user, bypass-safety) is now `confirmed`
  (presence of the indicator, not proof of intent).
- POISON-007 (new): references to credential/config files (SSH keys, MCP configs, `.env`, cloud credentials)
  with an access verb, and data smuggled through a tool argument.
- POISON-008 (new): same detectors applied to input-schema text (parameter descriptions, titles, defaults,
  enums, examples).
- Fixed false positives: first sentence verb phrases, "Use this tool when/to/for ...", and the
  tool-chaining rule matching "use this tool".
- Sentence splitting no longer breaks paths, file names or URLs.
- SCHEMA-001 downgraded to `low` and no longer duplicates parameters reported by SCHEMA-010..013;
  SCHEMA-010..013 skip parameters restricted by enum/const/pattern; SCHEMA-013 is `low`.
- SCHEMA-020 (new): free-form objects, untyped parameters, arrays without `items`.

Product
- `uploaded_file` accepted by `POST /api/scans` (config scans).
- Upload path checks use `Path.is_relative_to` instead of string prefix comparison.

Quality
- Fixed a crash when a server declared `capabilities` as an object.
- mypy is clean and now gates CI; CI no longer swallows `ruff format`, mypy or pip-audit failures;
  tests run on Python 3.11 and 3.12.
- 21 new regression tests.
