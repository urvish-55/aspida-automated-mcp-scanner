# THREAT MODEL

Scope: the Automated MCP Pentester as a **defensive analysis tool** — what it
defends against, what it defends itself from, and what it deliberately does not
attempt.

## Assets (what can be harmed)

| Asset | Owner | Notes |
|---|---|---|
| Agent context / conversation data | user | the primary exfiltration target in the MCP threat model |
| Credentials & secrets (env vars, API keys, tokens) | user | readable by any MCP server process the user runs |
| Files on the user's machine | user | reachable via file-capable tools |
| Server access & privileges | user | stdio MCP servers run with the user's account |
| Tool metadata integrity | user/ecosystem | descriptions steer agent behavior |
| Scanner's own host/network | operator | the scanner must not become an attack vector itself |
| Scan data (findings, configs) | operator | may contain sensitive server metadata |

## Threat actors

1. **Malicious MCP server author** — publishes a tool/server whose metadata or
   behavior attacks agents that connect.
2. **Compromised legitimate server** — a trusted server whose update/supply
   chain injects malicious metadata or behavior.
3. **Malicious scan target** — anyone operating the endpoint the scanner
   dynamically probes; may try to attack the scanner (SSRF into the operator's
   network, parse bombs, redirect games, oversized responses).
4. **Malicious configuration supplier** — hands the operator a poisoned config
   file to upload ("scan this for me").

## Attack classes & mitigations

### Against MCP users (what the scanner detects)

| Attack class | Detector(s) | Evidence basis |
|---|---|---|
| Prompt/tool poisoning (instructions hidden in descriptions) | POISON-001…006 | linguistic + structural matches, each with a WHY; hidden-Unicode+instructions = critical |
| Unicode obfuscation (zero-width, bidi/Trojan Source, homoglyph tool names) | UNICODE-001/002/003 | character presence is objective; classification distinguishes invisible vs. bidi vs. suspected-deceptive |
| Tool shadowing / name collision | COLLISION-001…004 | exact/case/normalized = confirmed; near-duplicates = suspected; similar descriptions = low/informational |
| Excessive capability combinations (read+network, shell+network, cred+network, shell+write) | CAP-010 | attack surface reporting with required-evidence statements; never auto-called a vulnerability |
| Input-validation weakness (unconstrained strings, path/command/URL/SQL-like params, missing schema) | SCHEMA-000/001/010-013 + dynamic families | static exposure + optional dynamic confirmation with inert probes |
| Over-privileged server config (env injection, local command launch) | CAP-020/021 | informational; keys only, values never read |
| Dynamically-confirmed traversal / command-marker execution / missing validation | DYN-PATH/CMDI/OVER/MALF/VIOL-001 | marker/sentinel proof from the live target |

### Against the scanner (self-defense)

| Attack | Mitigation (code) |
|---|---|
| SSRF into operator's network via target URL | scheme allowlist + resolution validation + private-range block + manual re-validated redirects (security/network.py); target re-validated at scan-creation time |
| DNS rebinding | mitigated: validated IPs are pinned at the socket layer; policy re-checked at connect time (SECURITY.md §2) |
| Redirect bypass | `follow_redirects=False` everywhere; per-hop `validate_redirect` |
| Malicious/oversized config (parse bombs) | strict JSON parse, size caps, tool-count cap, field-length caps, per-analyzer error isolation |
| Malicious tool responses (huge/odd content) | response text capped at 10k chars in connector; probes bounded by SafetyController payload cap |
| Making the scanner execute code | impossible by construction: no eval/exec/subprocess of target-derived content; uploads parsed as JSON only |
| Metadata/env secrets leakage | env **values** never ingested; logs redact secret-shaped keys; API never echoes configuration secrets |
| Resource exhaustion via scans | SCAN_TIMEOUT, per-test timeout, request budget, payload caps, rate limit, MAX_TOOLS_PER_SCAN |
| Unauthorized dynamic scanning | server-side authorization validator; safe-mode default; local-target switch default off |
| UI injection from finding text | React escapes by default; no `dangerouslySetInnerHTML` anywhere |

## Out of scope (honest boundaries)

- Runtime behavioral analysis of arbitrary server code (the scanner never runs
  target code, so it cannot observe what a stdio server does when actually
  executed by the MCP client).
- Network-level compromise of the operator (assumes a reasonably trusted
  workstation; no EDR/AV claims).
- Multi-tenancy, per-user identity/roles, and horizontal scaling (single-operator tool with one shared API key;
  see SECURITY.md §8 for deployment gaps).
- Real-world exploitability guarantees: capability findings are surface, not
  proof; dynamic coverage is a deliberately small, safe sample.
