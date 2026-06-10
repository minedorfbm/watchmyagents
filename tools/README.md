# WMA Tools

Internal/integration utilities. **Not shipped in the npm tarball** —
`tools/` is not in `package.json#files[]`. Use these scripts from the
repo working tree.

## `wma-to-guardian-export.js`

Bridges WMA's local NDJSON capture (`watchmyagents-logs/<agent>/<day>.ndjson`,
written by `wma-fetch` / Watch) into the action-export JSON format that
the **Guardian agent** in the sibling repo
[`openai-agent-sdk-test`](https://github.com/minedorfbm/openai-agent-sdk-test)
consumes.

### Why it exists

The Guardian Core scoring + policy proposal engine (WGS taxonomy
R01→R12, OWASP-Agentic-mapped) currently runs against the synthetic
fixture `fixtures/example-export.json`. To validate Guardian on REAL
agent activity, we need to feed it data captured by WMA from real
Anthropic Managed Agents.

This converter is the bridge. **Zero deps, plain Node 20+ ESM.**

### Usage

```bash
node tools/wma-to-guardian-export.js \
  --input watchmyagents-logs/agent_01XaNB.../2026-06-10.ndjson \
  --output ../openai-agent-sdk-test/exports/deep-researcher-2026-06-10.json \
  --tenant tenant-arma \
  --fleet fleet-research \
  --agent-type data_rag
```

Options :

| Flag | Default | Description |
|---|---|---|
| `--input` | (required) | Path to WMA NDJSON capture |
| `--output` | (required) | Path to Guardian-compatible JSON |
| `--tenant` | `tenant-local` | Logical tenant_id |
| `--fleet` | `fleet-default` | Logical fleet_id |
| `--agent-type` | `generic` | One of: `coding`, `devops_infra`, `data_rag`, `customer_facing`, `browser_web`, `orchestrator`, `workflow_backoffice`, `personal_assistant`, `transactional_financial`, `generic` |
| `--start` | first event ts | ISO-8601 lower bound |
| `--end` | last event ts | ISO-8601 upper bound |
| `--redaction` | `pii_masked` | One of: `none`, `pii_masked`, `params_hashed`, `full` |

### End-to-end flow (Anthropic agent → Guardian report)

```bash
# 1. WMA captures the agent's activity (already in place)
wma-fetch --agent-id agent_01XaNB4M88ZvcW8FoQ5GC14A --since 1h

# 2. Convert NDJSON to Guardian's input format
node tools/wma-to-guardian-export.js \
  --input watchmyagents-logs/agent_01XaNB.../2026-06-10.ndjson \
  --output ../openai-agent-sdk-test/exports/deep-researcher-2026-06-10.json \
  --tenant tenant-arma \
  --fleet fleet-research \
  --agent-type data_rag

# 3. Drop into Guardian's watched dir. If `npm run watch` is running in
#    openai-agent-sdk-test, this triggers analysis automatically.
#    The watcher writes:
#      exports/processed/<stem>.findings.json   (machine-readable findings)
#      exports/processed/<stem>.report.md       (human-readable French report)
cd ../openai-agent-sdk-test
ls exports/processed/
```

### Mapping

| WMA `action_type` | Guardian `type` | Notes |
|---|---|---|
| `llm_call` | `llm_call` | tokens + digests preserved |
| `tool_use` / `custom_tool_use` / `mcp_tool_use` | `tool_call` | category guessed from tool name |
| `user_message` / `user_interrupt` | `user_message` | |
| `handoff` | `agent_handoff` | parent_agent_id → parent_span_id |
| `tool_confirmation` | `policy_event` | |
| `shield_decision` | `policy_event` | WMA's own enforcement events |
| `session_error` | `tool_call` | with `result.status: "error"` |
| `message` / `thinking` / `state_transition` / `session_end` / `config_change` / `context_compacted` / `thread_*` | *(dropped)* | not relevant to security analysis |

The converter **re-classifies `tool_call` → `network_egress`** when the
tool clearly moves data out of the trust boundary (HTTP, browser, email,
or URL detected in input). This is what triggers Guardian's exfiltration
scoring rules.

### Heuristic data classification

The converter infers `security_context.data_classification` from
payload content:

- `secret` if it sees Anthropic/OpenAI key shapes (`sk-...`), AWS keys,
  GitHub PATs, private key blocks, or `password/secret/token = "..."`
  patterns.
- `pii` if it sees email addresses, US SSN shape, credit card shape,
  or phone numbers.
- `internal` otherwise.

False positives that promote sensitivity are acceptable (safer for
security analysis). False negatives are acceptable too (the operator
can hand-edit the export). If you don't want this auto-inference, pass
`--redaction full` and the labels are kept verbatim.

### What the human-readable output looks like

The Guardian agent (in `openai-agent-sdk-test`) is already configured
to produce a **concise French report** with:
- Summary (number of events, findings by severity)
- Findings sorted by severity, each with WGS-R taxonomy id, OWASP
  reference, score + confidence, evidence event_ids, suggested policies
  with measurable objectives
- Recommended actions

The watcher (`npm run watch`) writes this report to
`exports/processed/<stem>.report.md` automatically once it consumes
the Guardian export this tool produced.

For one-shot CLI use (without the watcher), `npm start <export-path>`
prints the report to stdout. Redirect to a file with:

```bash
npm start exports/deep-researcher-2026-06-10.json > report.md 2> /dev/null
```

(stderr captures the prefix lines `Modèle :` and `Export :` so stdout
stays clean for the markdown report.)
