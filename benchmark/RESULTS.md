# Detection benchmark — methodology and results

Scope: the **static poisoning detectors** (`POISON-*`) on tool *name + description*. It does not measure
schema, capability, collision or dynamic testing, and it does not measure the optional ML model.

## Corpora (all with provenance in the JSONL records)

| Corpus | n | Origin | Real-world? |
|---|---|---|---|
| `real_benign_dev` | 220 | tool definitions extracted from `modelcontextprotocol/servers`, `github/github-mcp-server`, `exa-labs/exa-mcp-server`, `firecrawl/firecrawl-mcp-server`, `Flux159/mcp-server-kubernetes`, `upstash/context7` (MIT / Apache-2.0) | yes, benign **candidates** (no evidence of malice; *not* "proven secure") |
| `real_benign_holdout` | 153 | `executeautomation/mcp-playwright`, `GLips/Figma-Context-MCP`, `mark3labs/mcp-filesystem-server`, `cloudflare/mcp-server-cloudflare` — collected and **never inspected at sample level while tuning** | yes |
| `published_attacks` | 7 | excerpts from Invariant Labs, Trail of Bits, Elastic Security Labs write-ups | researcher proofs of concept, **not** observed in the wild; retrieved via a summarizing fetch tool, so text may be abridged |
| `external_synthetic` | 25 | third-party HF dataset `fevziegeyurtsevenler/mcp-tool-poisoning` (Apache-2.0) | **synthetic**, template-generated: 5 payloads x 10 tool names |

Real-world *malicious* MCP tool descriptions are not publicly available in usable quantity, so recall can only be
measured on published proofs of concept and a synthetic set. Synthetic and real data are never pooled.

Extraction notes: code was read as text (never executed). Extractors are best-effort; some real tools are not
captured (e.g. `github-mcp-server:update_issue` is absent, which causes one cross-reference false positive).
Evaluation analyses each repository as one server so references to sibling tools resolve as in a real scan.

## Alert definitions
`any-flag` = any prompt-injection finding (suspected or confirmed). `medium+` = such a finding with severity >= medium
(how a human would triage). `confirmed` = status confirmed. 95% Wilson intervals are shown in the JSON.

## Results

| Run | Real benign dev: any / medium+ / confirmed | Real benign holdout: any / medium+ / confirmed | Published attacks recall (any / confirmed) | Synthetic recall (any / confirmed) |
|---|---|---|---|---|
| Baseline before tuning (ruleset 1.1.0) | 15/220 / – / 0 | **5/153 / – / 0** | 2/7 / 1/7 | 20/25 / 15/25 |
| After tuning (ruleset 1.2.0) | 4/220 / 1/220 / 0 | **1/153 / 0/153 / 0** | 7/7 / 2/7 | 25/25 / 20/25 |

(`–` = metric not recorded in the baseline run; see `results/baseline_before_tuning.json` for the raw record.)

How to read this honestly
- **Only the holdout false-positive row is a fair out-of-sample number** (153 real tools): 3.3% -> 0.7% any-flag and 0/153 medium+.
  Part of that gain comes from fixes that are general (sibling-tool references, weak-verb secret wording), but the
  holdout was *also* summarised as an aggregate count once before tuning, so treat it as "mostly held out".
- **Attack recall is in-sample.** The first run recalled 2/7 published and 20/25 synthetic samples; the misses were then
  fixed by adding detector *categories* (override-instructions, cross-tool conditional triggers, forced first use,
  compliance claims, trust-adjective impersonation, more languages). 7/7 and 25/25 therefore show the misses were closed,
  not that unseen attacks are caught. With n=7 the 95% interval for 7/7 is still 65%-100%.
- `confirmed` recall stays low (2/7): the scanner only calls something *confirmed* when an unambiguous directive or two
  independent indicators appear. That is intended.
- Remaining false positives are stylistic (`POISON-005`, low severity: legitimate descriptions that tell the agent how
  to behave, e.g. "include a confidence level reflecting how certain you are") and one sibling-tool reference whose target
  was not extracted.
- Known blind spots: tools whose description is clean but whose implementation is malicious; attacks phrased without
  instruction language; languages beyond those covered; Unicode or encoding tricks outside the detector tables.

Reproduce:
```
python -m benchmark.build_corpora                          # attack corpora
git clone --depth 1 <repos listed in benchmark/data/real_benign_manifest.json> into ~/net
python -m benchmark.collect_real_tools --root ~/net        # real tools + manifest (commits, licenses, hashes)
python -m benchmark.evaluate --json benchmark/results/latest.json
```
