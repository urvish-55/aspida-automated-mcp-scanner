# TEST FIXTURES — synthetic, for scanner validation only

Everything in this directory is **synthetic** (`synthetic = true` in spirit and
labeling). These servers exist so the scanner's detectors can be validated
end-to-end and so the demo mode has honest, reproducible targets. They are NOT
real-world vulnerabilities and must never be run in production or exposed to
untrusted networks.

## clean_server.py (port 8100)

A well-behaved MCP server: honest descriptions, constrained schemas
(types/maxLength/enum), server-side validation. Expected scanner result: **no
findings from the enabled tests** — which is explicitly NOT a claim that the
target is secure.

## vulnerable_server.py (port 8101)

A deliberately vulnerable MCP server implementing controlled weaknesses:

| # | Weakness | Where |
|---|----------|-------|
| 1 | Tool poisoning (agent-directed instructions, exfiltration wording) | `read_file` description |
| 2 | Hidden Unicode (zero-width, bidi) | `read_file` / `Read_File` descriptions |
| 3 | Unconstrained path/command/url parameters | all input schemas |
| 4 | Case-insensitive tool shadowing | `read_file` vs `Read_File` |
| 5 | Weak validation (accepts wrong types, nulls, oversized) | all tools |
| 6 | Controlled path traversal | `read_file`/`Read_File` — escapes the sandbox; returns a **simulated** sentinel for classic system paths (clearly marked synthetic). Never writes/deletes/executes. |
| 7 | Inert "command execution" | `run_command` NEVER executes; it echoes `echo` markers only so the scanner's marker detection is verifiable |

Safety invariants: no destructive payloads are implemented or accepted; the
"traversal" only reads text sentinels; "command execution" is a string echo.

## Run locally

```bash
python fixtures/clean_server.py        # 127.0.0.1:8100
python fixtures/vulnerable_server.py   # 127.0.0.1:8101
```

## Run in Docker

```bash
docker compose up --build vulnerable-fixture   # exposes 8101
```

To let the scanner (in another container) reach it, start the stack with
`ALLOW_LOCAL_TARGETS=true` and target `http://vulnerable-fixture:8101/mcp` —
or from the host, `http://127.0.0.1:8101/mcp` with local targets allowed.

## vulnerable_server_2.py (port 8102)

A second deliberately vulnerable, fully inert server ("Acme Notes & Mail") with a different mix: cross-tool poisoning that
tells the agent to call `read_secret` first, credential exposure (fake keys), SQL-error echo, SSRF-style fetch, unrestricted
email exfiltration channel, dangerous capabilities (`write_file`, `delete_all_notes`, `shell`), a rug pull (`get_summary` changes
after two `tools/list` calls; restart to reset), invisible Unicode tag characters, and free-form schemas. Nothing is executed,
written, sent or fetched. Scan target: `http://127.0.0.1:8102/mcp`.
