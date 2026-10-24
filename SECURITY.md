# SECURITY.md — how the scanner protects itself (and its operator)

This project is a security tool; its own attack surface is treated as
first-class. Below is what is enforced in code today, where, and what is
explicitly out of scope.

## 1. No arbitrary execution

- The scanner **never executes** uploaded files, target configs, tool
  descriptions, or any content derived from a scan target
  ([uploads.py](backend/api/uploads.py): uploads are parsed JSON stored as
  data; nothing is ever handed to an interpreter or shell).
- No `subprocess`/`os.system` anywhere in the runtime path. The only "command"
  the product knows about is metadata describing a target's configured stdio
  command (stored as strings, never run).
- Dynamic probes use inert payloads only
  ([probes.py](backend/scanners/dynamic/probes.py)): echo markers with a
  per-scan random nonce, read-only path sentinels, bounded oversized strings,
  type/enum violations. Destructive payload classes (deletion, disk format,
  credential theft, persistence, ransomware behavior) are neither sent nor
  implemented in fixtures; a unit test asserts the forbidden-token invariant.

## 2. SSRF defenses ([security/network.py](backend/security/network.py))

- Scheme allowlist: `http`/`https` only; userinfo in URLs rejected.
- Every resolved address is validated: loopback, private, link-local (incl.
  `169.254.169.254` cloud metadata), reserved, multicast, unspecified ranges
  blocked unless `ALLOW_LOCAL_TARGETS=true` (a lab-only switch, default off).
- Redirects are **never** auto-followed; each hop is re-validated against the
  same policy (`validate_redirect`).
- **DNS pinning**: the addresses validated for a hostname are the only addresses
  the connection may use (`PinnedTransport` / `PinnedNetworkBackend`). The name is
  never resolved a second time at connect time, so a rebinding flip after validation
  has no effect; the policy is re-checked at connect time, unvalidated hosts and unix
  sockets are refused, and TLS still verifies the certificate against the original
  hostname. Environment proxies are ignored in this mode (a proxy would re-resolve).

## 2b. API authentication ([auth.py](backend/security/auth.py))

- ON by default (`AUTH_REQUIRED=true`). Every `/api/*` route needs the key except `/api/health`,
  `/api/version` and the OpenAPI docs; CORS preflight and the static dashboard bundle pass through.
- Key source: `API_KEY` (>= 16 chars) or `data/api_key`, auto-generated on first start (256-bit, mode 0600).
  The key is never logged, never returned by any endpoint, and compared in constant time on SHA-256 digests.
- Send `Authorization: Bearer <key>` or `X-API-Key: <key>`. Failed attempts are throttled per IP
  (`AUTH_MAX_FAILURES_PER_MINUTE`, default 10 -> HTTP 429).
- The dashboard stores the key in `sessionStorage` (cleared when the tab closes).

## 3. Dynamic testing safety ([safety.py](backend/scanners/dynamic/safety.py))

- `safe_mode=true` default; dynamic testing **off** by default; explicit
  authorization acknowledgement required server-side (validator rejects
  `dynamic_enabled` without `authorization_confirmed` — the frontend checkbox
  is UX, not the control).
- SafetyController on every probe: global request budget, per-payload byte
  cap, per-test timeout, minimum request interval (rate limit), cooperative
  cancellation, and an audit trail (`request_allowed` / `request_refused` /
  `budget_exhausted` / `cancelled`) persisted with the scan.
- Refused/timeout probes become `skipped`/`error` test records with reasons —
  never silently dropped, never counted as passes.
- Overall scan timeout aborts long-running scans (`SCAN_TIMEOUT`).

## 4. Input validation & upload security

- Every API input is re-validated server-side with Pydantic
  ([schemas/api.py](backend/schemas/api.py)); frontend validation is treated
  as UX only.
- Uploads: extension allowlist (`.json/.jsonc/.txt`), UTF-8 + strict JSON
  parsing, size cap (`MAX_UPLOAD_SIZE`), generated random filenames (original
  name never touches disk), path-traversal-proof resolution, stored outside
  any executable path, never served back as executable content.
- Enforced limits elsewhere: `MAX_TOOLS_PER_SCAN`, `MAX_PAYLOAD_SIZE`,
  `MAX_DYNAMIC_REQUESTS`, per-test timeout, description length caps in the
  ingester (100k chars), tool-name caps.

## 5. Secrets handling

- `LLM_API_KEY` lives in process memory only; never echoed by any endpoint,
  never written to scans, never logged. Structured logging redacts
  secret-shaped keys and inline `key=value` fragments
  ([logging.py](backend/core/logging.py)).
- MCP server `env` values are **never ingested** — only key names are kept
  (unit-tested).
- Fixture/test data uses synthetic secrets only; the secret-scan CI job greps
  for hardcoded high-entropy assignments.

## 6. Abuse resistance of the API

- In-memory per-IP rate limiting (default 60 req/min; front with a real
  gateway limiter for multi-worker deployments).
- All state-changing endpoints validate before acting; scans run as background
  jobs, so no endpoint blocks on scan work.
- CORS restricted to the configured dashboard origin; `allow_credentials=False`.

## 7. Storage & logging

- SQLite in `data/db` (volume in Docker); reports/JSON are generated on
  demand, not written by default. Runs under a non-root user in the image.
- Structured JSON logs with scan_id/stage correlation; request bodies are
  never logged (they may contain customer config data); errors are logged
  with types, secrets redacted.

## 8. Known gaps (honest)

- Rate limiter (and the failed-auth throttle) is per-process (single-node).
- Authentication is a single shared API key (no users/roles/audit identity). Put the API
  behind TLS (a reverse proxy) before exposing it beyond localhost: the key travels in a header.
- Upload DoS protections are size/count-based; CPU-heavy JSON nesting is
  bounded by depth limits in the ingester, but extremely hostile inputs should
  be screened at an edge proxy in hostile environments.
