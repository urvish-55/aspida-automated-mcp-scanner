# API.md

Base URL: `http://127.0.0.1:8000` · Interactive docs: `/api/docs` · OpenAPI: `/api/openapi.json`

All endpoints validate input server-side (Pydantic). Errors return
`{"detail": "..."}` with appropriate 4xx/5xx codes.

**Authentication:** every route except `/api/health`, `/api/version` and the docs requires the API key
(`API_KEY`, or the auto-generated `data/api_key`): `Authorization: Bearer <key>` or `X-API-Key: <key>`.
Missing/wrong key -> 401 with `WWW-Authenticate`; too many failures from one IP -> 429. `GET /api/auth/check`
returns 200 for a valid key. Disable only for local experiments with `AUTH_REQUIRED=false`.

## Meta

### `GET /api/health`
Liveness + component availability. Example:
```json
{"status":"ok","database":"ok","llm_provider":"disabled","llm_available":false,
 "ml_available":true,"safe_mode_default":true,"time_utc":"2026-10-01T15:00:00+00:00"}
```

### `GET /api/version`
```json
{"app_name":"Automated MCP Pentester","version":"0.1.0","ruleset_version":"1.0.0",
 "ml_model_version":"0.1.0","scanner_schema_version":"1"}
```

## Scans

### `POST /api/scans` → 201
Creates an async scan job; returns the scan row. Body:

| Field | Type | Default | Notes |
|---|---|---|---|
| `target_type` | `"config"\|"url"` | `config` | |
| `target_config` | object\|array\|string | — | required for config mode; JSON string is parsed server-side |
| `server_url` | string | — | required for url mode; SSRF-validated **at creation** |
| `safe_mode` | bool | `true` | |
| `dynamic_enabled` | bool | `false` | requires `authorization_confirmed=true` (422 otherwise) |
| `authorization_confirmed` | bool | `false` | explicit human acknowledgement |
| `semantic_enabled` | bool | `false` | runs only if the server has an LLM provider configured; otherwise reports `unavailable` |

Validation failures (422): missing config, malformed JSON string, missing URL,
dynamic-without-authorization, and targets rejected by the SSRF policy (detail
names the reason, e.g. resolution to non-public address).

### `GET /api/scans?limit=&offset=&status=` → paginated list (newest first)

### `GET /api/scans/{id}`
Full detail: scan fields + `events` (progress/audit), `findings`, `tools`,
`tests`. 404 if unknown. Safe to poll while running.

### `POST /api/scans/{id}/cancel`
Cooperative cancellation; the pipeline persists `cancelled` status. 409 if the
scan is not running.

### `DELETE /api/scans/{id}` → 204
Cancels (if running) then deletes the scan and all child rows. 404/409 as
appropriate.

### `GET /api/scans/{id}/findings?severity=&category=&status=&tool=&confidence=`
Filtered findings (all filters optional, combinable).

### `GET /api/scans/{id}/tools`
Tool inventory with inferred capabilities.

## Reports

### `GET /api/scans/{id}/report`
Canonical JSON report (14 sections: meta, scan, configuration, risk with full
breakdown, severity/status breakdowns, tool inventory, findings, dynamic tests
with summary, static analyzer statuses, semantic, ML, recommendations,
limitations, events). 409 while the scan is still running.

### `GET /api/scans/{id}/report/pdf`
Same structure rendered as a 14-section PDF (ReportLab).
`Content-Disposition: attachment; filename="mcp-pentest-report-<id12>.pdf"`.
500 with a clear message if generation fails (never a corrupt file).

## Uploads

### `POST /api/uploads` (multipart field `file`) → 200
Stores a **JSON** config file: extension allowlist (`.json/.jsonc/.txt`),
strict UTF-8/JSON validation, size cap, generated random filename.
Returns `{"stored_filename": "<24-hex>.json", "size_bytes": N}`. 422 on any
violation. Uploaded content is data only — it is never executed.
Pass the returned name to `POST /api/scans` as `"uploaded_file"` (config scans only; mutually exclusive
with `target_config`; the name must match `^[0-9a-f]{24}\.json$` and exist, otherwise 422).

## Dashboard

### `GET /api/dashboard`
Aggregates over real rows only: totals, high/critical count, average risk of
completed scans, latest scan, tools analyzed, tests executed/skipped, and a
`security_status` sentence that never claims security ("No scans performed
yet." on an empty system).

## Investigation API

All endpoints are under `/api` and require the API key when auth is enabled. Everything is derived from stored scan
data; nothing is synthesized. Fields that were not analyzed are `null`/"not analyzed".

| Endpoint | Purpose |
|---|---|
| `GET /scans/{id}/analysis` | Per-tool exposure ranking, capability heatmap, tool graph, evidence-based attack paths (`complete` flag, `missing_stages`). |
| `GET /compare?a=&b=` | Diff of two scans: new / resolved / unchanged findings, risk delta. |
| `GET /findings` | Cross-scan findings. Filters: `severity, category, status, tool, confidence, scan_id, triage, q, since, include_info`; `limit` ≤ 500, `offset`; returns facets. |
| `GET /findings/{id}` | One finding with evidence, reproduction and triage state. |
| `PATCH /findings/{id}/triage` | Body `{"status": "open|acknowledged|in_progress|resolved|false_positive|accepted_risk", "note": "..."}`. |
| `GET /search?q=` | Search tools, findings, scans and reports. |
| `GET /activity` | Recent real events (scan started/completed/failed, triage changes). |
| `GET /notifications` | Notifications derived from real scan outcomes. |
| `POST /discover` | Offline preview of a pasted/uploaded config (tool count and names). Resources and prompts are `null` (not analyzed). |
| `GET /tools/history?name=` | Appearances of a tool name across scans. |
| `POST /unicode/inspect` | Body `{"text": "..."}` (1-5000 chars). Per-character code point, Unicode name, category, script, bidi class, UTF-8 bytes and suspicious classification, from Python `unicodedata`. Stateless; nothing is stored. |
| `GET /ml/info` | Model metadata, grouped-CV and independent-evaluation results, operating thresholds and caveats. `real_world_training_samples` is 0 when trained on synthetic data. |
| `GET /system/health` | Backend, database, connector, ML, LLM, worker and report-engine status. Optional components do not degrade `overall`. |


## Status vocabularies

- Scan: `queued | running | completed | failed | cancelled`
- Finding: severity `critical|high|medium|low|info`; confidence `high|medium|low`;
  status `confirmed|suspected|informational|not_tested|not_applicable|error`
- Dynamic test: `passed | failed | skipped | error | timeout | not_applicable`
- Semantic: `completed | unavailable | skipped | error`
- ML: `completed | unavailable | not_applicable | disabled | error`

## Rate limiting

All `/api/*` requests are rate-limited per client IP (default 60/min,
`RATE_LIMIT_PER_MINUTE`). Exceeding returns 429 with `Retry-After`.
