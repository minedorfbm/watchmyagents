# Watch My Agents

**Security observability for AI agents.** A zero-dependency CLI + SDK that captures every action your AI agents take — tool calls, prompts, state transitions, errors, multi-agent comms — into local NDJSON logs. Built for security audits, not just token counting.

Designed around three guarantees:

1. **Local-first.** Raw payloads (prompts, outputs, tool arguments) stay 100% on your machine. Nothing leaves unless you explicitly opt in.
2. **Trace everything, not just what costs tokens.** A `web_fetch` to a suspicious URL carries zero tokens but is exactly what a security audit needs to see.
3. **Zero dependencies.** Only Node.js 18+ built-ins. No telemetry, no phone-home, no hidden network calls.

---

## Install

```bash
npm install -g watchmyagents
```

## Quickstart — monitor an Anthropic Managed Agent

You'll need:
- An Anthropic API key (`sk-ant-…`)
- The `agent_id` of the agent you want to monitor (from [console.anthropic.com](https://console.anthropic.com))

```bash
export ANTHROPIC_API_KEY="sk-ant-..."

wma-fetch --agent-id agent_01XaN... --since 1h
wma-inspect
```

That's it. You'll see a security-focused summary of everything the agent did:

```
━━━ WatchMyAgents log inspector ━━━
entries          : 90
sessions         : 2 (session_end entries: 2)
model            : claude-sonnet-4-6
window           : 2026-05-23T05:32:08Z → 2026-05-23T06:12:40Z
status           : ok=90  error=0

── Tokens ──
total            : 811,798  (in=26 out=22,996 cache_r=492,220 cache_w=296,556)

── By tool ──
  web_search                               calls=  20  tokens=       0
  web_fetch                                calls=   2  tokens=       0

── By action_type ──
  llm_call                                 calls=  12  tokens=  811798
  state_transition                         calls=  28
  user_message                             calls=   7
  thinking                                 calls=   9
  message                                  calls=  10
  tool_use                                 calls=  22

── Top destinations (tool inputs) ──
    1×  web_search       "AI agent security attack vectors prompt injection..."
    1×  web_fetch        https://genai.owasp.org/2025/12/09/owasp-genai-...

── Action sequences (top transitions) ──
   19×  22.1%  state_transition → state_transition
   17×  19.8%  tool_use → tool_use
   ...

── Tool latency ──
  web_search           n= 20  p50=3,744 ms  p95=4,009 ms  max=4,009 ms
  web_fetch            n=  2  p50=1,477 ms  p95=1,477 ms

── Rate metrics ──
  tokens/min       : 721
  calls/min        : 0.08
```

## What gets logged

Each line of the NDJSON file is one agent action. The 18 `action_type` values captured today:

| `action_type` | When emitted |
|---|---|
| `user_message` | A prompt is sent to the agent |
| `user_interrupt` | Manual mid-execution stop |
| `tool_confirmation` | Approve / deny a tool call gated by a permission policy |
| `custom_tool_result` | Orchestrator returns a custom tool result |
| `message` | Agent text response |
| `thinking` | Agent reasoning block |
| `llm_call` | Model inference call (with token usage) |
| `tool_use` | Pre-built agent tool invoked (web_search, web_fetch, bash, …) |
| `mcp_tool_use` | MCP server tool invoked |
| `custom_tool_use` | Custom tool defined by the orchestrator |
| `context_compacted` | Context window saturated — history compacted |
| `thread_created` | A multi-agent thread was created |
| `thread_message_sent` / `_received` | Inter-agent communication in multi-agent sessions |
| `config_change` | Session config (system prompt, tools, …) was updated mid-flight ⚠️ |
| `state_transition` | Session/thread `running`/`idle`/`rescheduled`/`terminated` |
| `session_error` | Error during session processing |
| `session_end` | Synthetic marker at end of each fetch (tokens summary) |

Each entry carries: `id`, `agent_id`, `framework`, `timestamp`, `action_type`, `tool_name`, `model`, `duration_ms`, `tokens_used`, `input_tokens`, `output_tokens`, `cache_read_tokens`, `cache_creation_tokens`, `status`, `error`, `sequence_number`, `session_id`, `input`, `output`.

**The `input` and `output` fields contain the raw payload** (tool arguments, agent responses, queries). They never leave your machine.

## CLI reference

### `wma-fetch` — pull events from Anthropic Managed Agents

```bash
wma-fetch --agent-id <agent_id> [--session-id <sess_id>] [--since 1h]
         [--log-dir ./watchmyagents-logs] [--dump-raw]
```

| Flag | Effect |
|---|---|
| `--agent-id agent_xxx` | Required — Anthropic agent identifier |
| `--since 1h` / `24h` / `7d` | Fetch window (default: all) |
| `--session-id sesn_xxx` | Limit to a single session |
| `--log-dir ./logs` | Where to write NDJSON (default `./watchmyagents-logs`) |
| `--dump-raw` | Also save raw API events alongside (forensic / debugging) |
| `--api-key sk-ant-…` | Override the `ANTHROPIC_API_KEY` env var |

Logs land in `./watchmyagents-logs/<agent_id>/<date>.ndjson` (file mode `0600`, dir `0700`).

### `wma-inspect` — audit the logs

```bash
wma-inspect [path]
```

`path` can be a single `.ndjson` file or a directory (default: `./watchmyagents-logs`).

Outputs sections aligned with security audit needs: tokens summary, by-tool / by-action-type breakdowns, top tool destinations (URLs / queries), action-sequence transitions, tool error rates, p50/p95/max latency per tool, rate metrics.

## Automating (cron)

For continuous monitoring, run `wma-fetch` on a cron:

```cron
# Every 15 minutes
*/15 * * * * cd /path/to/project && wma-fetch --agent-id agent_01XaN... --since 20m
```

Or for daily reports:

```cron
# Once per night, fetch the full last 24h
5 0 * * * cd /path/to/project && wma-fetch --agent-id agent_01XaN... --since 25h
```

## Data sovereignty model

WatchMyAgents is built so that **your prompts and outputs never have to leave your machine**:

| Where | What lives there |
|---|---|
| **Your machine** (`./watchmyagents-logs/`) | Full NDJSON with all prompts, tool inputs, agent outputs. `chmod 600` on every file. |
| **Anthropic API** | Where the agent runs. WMA pulls events via the public REST API only. |
| **WMA infrastructure** | **Nothing today.** Future opt-in telemetry will ship only anonymized metadata (counts, timings, hashes) — never raw payloads. |

This is the "local-first" guarantee. It is the product, not a marketing claim.

## Security

WMA requires your Anthropic API key to call the Managed Agents REST API on your behalf. The key:

- Is read from the `ANTHROPIC_API_KEY` env var or the `--api-key` flag
- Is **never** written to disk, **never** logged, **never** transmitted anywhere except `api.anthropic.com` over HTTPS
- Is only ever held in process memory for the duration of a `wma-fetch` run

For added safety, generate a **workspace-scoped** API key with read-only permissions on the agents you want to monitor: [console.anthropic.com → API Keys](https://console.anthropic.com/settings/keys).

Report vulnerabilities via [SECURITY.md](./SECURITY.md).

## Shield — real-time policy enforcement

`wma-shield` (shipped in v0.2.0) is the real-time enforcement companion to Watch. It streams agent events live, evaluates them against a local JSON policy file, and blocks tool calls that violate the policy via `user.tool_confirmation` (when the agent has `permission_policy: always_ask` configured) or `user.interrupt` (zero-setup fallback).

```bash
# Agent-wide mode — attaches to ALL active sessions of the agent automatically.
# Run under a process supervisor (systemd, pm2, docker) for production.
wma-shield --agent-id agent_xxx --policy ./policies.json
```

Shield auto-detects the best enforcement mode at startup:
- **tool_confirmation** (precise, pre-execution blocking) when at least one tool has `permission_policy: always_ask`
- **interrupt** (degraded, post-execution termination) otherwise

For the precise mode setup instructions:
```bash
wma-shield --setup-guide --agent-id agent_xxx
```

Decisions are logged to the same NDJSON stream as Watch (`action_type: shield_decision`), so `wma-inspect` surfaces them in its audit summaries.

## Status

- ✅ Watch SDK — Anthropic Managed Agents post-hoc fetch + local audit
- ✅ Shield SDK — real-time enforcement (interrupt mode + tool_confirmation mode)
- 🚧 Encrypted upload to customer's own cloud (S3/GCS/Azure with `age` public-key encryption)
- 🚧 Anonymized telemetry to WMA cloud (opt-in, freemium model)
- 🚧 Guardian AI (cloud) — automatic policy suggestions from observed behavior
- 🚧 Fortress (cloud) — dashboard + human-in-the-loop validation queue
- 🚧 Adapters for in-process agents (Claude SDK, OpenAI, LangChain, generic) — code present in `src/adapters/` but unverified against the new Modèle C architecture; documentation will follow once re-validated

## License

[MIT](./LICENSE)
