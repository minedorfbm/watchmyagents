# OpenAI Agents SDK adapter (TypeScript / JavaScript)

**Status: v1.3.0 (Phase 2.A) — first adapter that observes a runtime which executes locally on the customer machine.**

This adapter integrates `watchmyagents` with the [OpenAI Agents SDK](https://openai.github.io/openai-agents-js/) (`@openai/agents` on npm). Customers add two lines to their existing agent code; WMA logs every lifecycle event locally and can block tool calls before execution via Shield policies.

## Why customer-instrumented and not "paste your API key"

OpenAI's agent runtime executes **on the customer's machine**, not on OpenAI's servers. There is no `listAgents` / `listConversations` endpoint on the OpenAI API that would let WMA pull events from outside — the SDK is the agent. So WMA has to live inside the same process.

This is the same model used by Datadog APM, Sentry, Langfuse, and OpenLLMetry for OpenAI observability. The integration is two lines of code; the rest is automatic.

## Setup

### 1. Install

```bash
npm install @openai/agents zod watchmyagents
```

`watchmyagents` declares `@openai/agents` as a peer dependency — the customer installs both; WMA ships zero runtime deps of its own.

### 2. Get a WMA API key

Sign in to the Fortress dashboard → **Settings → API Keys → Generate** → copy the `wma_xxx` value. Give it a label that maps to one of your environments (e.g. `production`, `staging`).

### 3. Environment variables

```bash
# .env
WMA_API_KEY=wma_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
WMA_LOG_DIR=./watchmyagents-logs          # optional; default shown
WMA_TEAM_ID=customer-support              # optional; manual team tagging
# WMA_POLICIES_SOURCE handling for Fortress-pulled policies arrives in 1.3.1
```

Today the adapter loads policies from a local file via `policiesPath`. Fortress-pulled policies for this adapter land in a 1.3.x patch.

### 4. Wire it up — two patterns

The `@openai/agents` SDK exposes two EventEmitter surfaces and lets you
pick how to run an agent. WMA supports both:

**Pattern A — explicit Runner (RunHooks):**

```typescript
import { Agent, Runner } from '@openai/agents';
import {
  wmaToolInputGuardrail,
  attachWmaWatch,
} from 'watchmyagents/src/sources/openai-agents-js.js';

const wmaShield = wmaToolInputGuardrail({
  policiesPath: './examples/policies/mitre-starter.json',
});

const agent = new Agent({
  name: 'support_bot',
  instructions: '...',
  tools: [...],
  toolInputGuardrails: [wmaShield],          // ← Shield enforcement
});

const runner = new Runner();
attachWmaWatch(runner);                       // ← Watch via RunHooks

await runner.run(agent, 'How do I reset my password?');
```

**Pattern B — convenience `run()` function (AgentHooks):**

```typescript
import { Agent, run } from '@openai/agents';
import {
  wmaToolInputGuardrail,
  attachWmaWatchToAgent,
} from 'watchmyagents/src/sources/openai-agents-js.js';

const wmaShield = wmaToolInputGuardrail({
  policiesPath: './examples/policies/mitre-starter.json',
});

const agent = new Agent({
  name: 'support_bot',
  tools: [...],
  toolInputGuardrails: [wmaShield],          // ← Shield (unchanged)
});

attachWmaWatchToAgent(agent);                 // ← Watch via AgentHooks

await run(agent, 'How do I reset my password?');
```

**Which to pick?** Use the function name (`Runner` vs `run`) as your
heuristic. They behave identically from a Watch/Shield perspective —
same NDJSON output, same audit chain, same team_id propagation. Under
the hood, the SDK fires lifecycle events through two different event
emitters with slightly different argument layouts (e.g. AgentHooks
omits the agent from `agent_end` / `agent_tool_*` because the listener
is registered on the agent itself); the two `attachWma…` variants
handle those differences.

That is the entire customer change.

## What you get

### Watch (observability)

Every lifecycle event the SDK emits flows to a daily-rotated NDJSON log at `./watchmyagents-logs/openai-agents/YYYY-MM-DD.ndjson`. Five event types are captured:

| @openai/agents event | WMA `action_type` | Notes |
|---|---|---|
| `agent_start` | `message` (kind=agent_start) | Agent received turn input |
| `agent_end` | `message` (kind=agent_end) | Agent produced final output |
| `agent_handoff` | `handoff` | One agent passes control to another |
| `agent_tool_start` | `custom_tool_use` | Tool is about to fire |
| `agent_tool_end` | `custom_tool_result` | Tool returned a result |

Containment: tool arguments and tool results are captured in `input` / `output` and stay LOCAL. The anonymizer is the single gate to Fortress.

### Shield (enforcement)

The `wmaToolInputGuardrail()` returned object slots into the Agent's `toolInputGuardrails: [...]` array. Before every tool call, the SDK awaits our `run()` and respects the result:

| Shield decision | OpenAI `behavior` | Effect on the tool call |
|---|---|---|
| `allow` | `{ type: 'allow' }` | Tool runs as if no guardrail existed |
| `deny` | `{ type: 'rejectContent', message }` | Tool is BLOCKED; `message` returned in place of the tool result; the model sees the rejection and can decide next steps |
| `interrupt` | `{ type: 'throwException' }` | Tool is blocked AND the agent loop aborts with an exception |
| `shadow` mode | `{ type: 'allow' }` with diagnostic outputInfo | Tool runs; decision logged for calibration but not enforced |

### Team correlation (Legions UI)

Three resolution channels for `team_id`, in precedence order:

1. **Customer override** — set `WMA_TEAM_ID` env var or pass `getTeamId` to the guardrail options.
2. **Auto-detect via handoff** — when the SDK emits `agent_handoff(fromAgent, toAgent)`, every subsequent event in the same run shares the from-agent's team id. Useful for multi-agent flows without any customer config.
3. **None** — events get `team_id: null` and appear under "Untagged" in the Fortress Legions view.

### Audit chain (tamper-evidence)

Every `shield_decision` row carries `prev_hash` + `chain_hash` (SHA-256). The audit chain is local-only tamper-evidence. Verify with:

```typescript
import { verifyDecisionChain } from 'watchmyagents/src/shield/decision-chain.js';
import { readFile } from 'node:fs/promises';

const lines = (await readFile('./watchmyagents-logs/openai-agents/2026-06-09.ndjson', 'utf8'))
  .trim().split('\n').map((l) => JSON.parse(l))
  .filter((l) => l.action_type === 'shield_decision');

console.log(verifyDecisionChain(lines));
// → { ok: true, count: N, segments: 1 }
```

Limits: tail truncation (removing the most recent rows) is invisible to an append-only chain. Cross-process replay would re-derive the chain from scratch. Fortress-side append-only ingest closes both gaps (planned).

## Options reference

```typescript
wmaToolInputGuardrail({
  // Policy source — pick ONE:
  policiesPath?: string,         // local JSON file path
  ruleset?: object,              // in-memory ruleset object

  // Storage:
  logDir?: string,               // default WMA_LOG_DIR or ./watchmyagents-logs
  sessionId?: string,            // default auto-minted UUID

  // Behavior:
  failOpen?: boolean,            // on Shield internal error: allow (true) or
                                 // deny (false). Default: false (fail-CLOSED)
  recentWindowSize?: number,     // ctx.recent_error_rate window. Default: 20
  getTeamId?: () => string|null, // custom team resolver

  // Injection (for tests):
  logger?: Logger,
  decisionLogger?: DecisionLogger,
  tracker?: ContextTracker,
});

attachWmaWatch(runner, {
  logDir?: string,               // default same as guardrail
  sessionId?: string,            // default auto-minted UUID
  logger?: Logger,
  teamTracker?: TeamTracker,
});
// → returns a `detach()` function the customer can call on shutdown.
```

## What gets sent to Fortress

Tool arguments and results stay LOCAL. The anonymizer converts WMAAction → signals payload (salted hashes, no raw values) and pushes to `WMA_FORTRESS_BASE_URL/upload-signals` if `WMA_API_KEY` is set. See [CONTAINMENT.md](../CONTAINMENT.md) for the full egress model.

## Compatibility

- Node.js: **20+** (matches the WMA SDK baseline and `@openai/agents`'s requirement)
- TypeScript: any version — types live in `src/sources/openai-agents-js.d.ts`
- `@openai/agents` version range: **`^0.2.0`** (declared in `package.json#peerDependencies`). Real fixtures in `test/fixtures/openai-agents-events/` were captured against 0.2.x and the adapter's lifecycle event signatures match that line. Older 0.1.x lacked AgentHooks ergonomics the adapter relies on.

## Limits + known gaps (v1.3.0)

| Gap | Workaround |
|---|---|
| Streaming mode behavior under Tool Input Guardrails not formally verified | We expect the SDK to honor guardrails in streaming mode (the SDK code paths are the same); the test fixtures cover non-streaming today. Verification with a streaming smoke test before v1.3.1. |
| Fortress-pulled policies via `WMA_POLICIES_SOURCE=fortress` not wired in this adapter yet | Use `policiesPath` with a local file in v1.3.0; Fortress pull lands in v1.3.x patch |
| Tool Output Guardrails (post-execution filter) not exposed | Add only if customer demand — Shield's pre-tool deny covers 95% of the exfil-prevention use case |
| Python Agents SDK | Separate package `watchmyagents-py` planned for v1.4.0 (Pattern 2 — pip-installable thin client that talks to a Node Shield daemon over UNIX socket) |

## Troubleshooting

**"no policy ruleset configured — guardrail will allow all"** stderr warning
You passed neither `policiesPath` nor `ruleset` to `wmaToolInputGuardrail()`. The guardrail is loaded but every tool call is allowed. Pass one of the two options to enforce.

**Tool calls succeed but never appear in NDJSON**
Check that you also called `attachWmaWatch(runner)`. The guardrail handles Shield decisions; Watch handles the event log. Customers who only need enforcement can skip Watch (the guardrail still logs `shield_decision` rows itself).

**Audit chain verification reports `chain_hash recomputation mismatch`**
Someone modified an NDJSON row after write. The `broken_at` index points to the first tampered row. Investigate; do not delete the file (it IS the evidence).

**Guardrail latency feels high**
Policy eval is sub-millisecond for small rulesets. The audit chain hash takes <1ms. If you see >50ms, the log directory may be on slow storage — point `logDir` at a local SSD or in-memory tmpfs.

## See also

- [examples/adapters/openai-agents-js-quickstart.ts](../../examples/adapters/openai-agents-js-quickstart.ts) — runnable customer reference
- [docs/adapters/](.) — sibling adapter docs
- [docs/SOURCE-ADAPTER-CONTRACT.md](../SOURCE-ADAPTER-CONTRACT.md) — the contract every adapter follows
- [docs/MITRE-ATTCK-COVERAGE.md](../MITRE-ATTCK-COVERAGE.md) — what the policy starter bundle covers
- [docs/CONTAINMENT.md](../CONTAINMENT.md) — what stays local vs goes to Fortress
