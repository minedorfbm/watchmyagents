# Source Adapter Contract — V1

> **Audience**: anyone writing a new SDK adapter (OpenAI Agents, AWS Bedrock AgentCore, LangGraph, CrewAI, AutoGen, Hermes Agent, OpenClaw, custom DIY, etc.).
>
> **Goal**: make sure your adapter slots into the existing pipe (Watch → anonymizer → Fortress → Guardian → Shield) without anyone having to refactor the rest of WMA.

---

## 1. The big picture in 1 paragraph

WMA is provider-agnostic by construction. The only place vendor-specific code is allowed to live is in a `Source` subclass. A Source's job is to translate the provider's native events into a single canonical shape — `WMAAction` — and to declare its own enforcement capability. The anonymizer, typology classifier, Guardian scoring engine, and Shield enforcement layer all read `WMAAction` and don't care which provider produced it.

```
┌──────────────────┐         ┌──────────────┐         ┌──────────────┐
│ Vendor events    │   →    │ YOUR Source   │   →    │ WMAAction    │   →   (the rest of WMA)
│ (Anthropic,      │ adapt  │  (translate +  │ yield  │ canonical    │
│  OpenAI, ADK…)   │        │   enforce)     │        │ shape        │
└──────────────────┘         └──────────────┘         └──────────────┘
```

If you stay inside the contract, **nothing in WMA needs to change** when you add a new adapter.

---

## 2. The minimum you write

A new adapter is one file (`src/sources/<your-provider>.js`) that does three things:

```js
import { Source, PROVIDERS, ENFORCEMENT_MODES } from './contract.js';

export class YourProviderSource extends Source {
  static providerName = PROVIDERS.YOUR_PROVIDER;       // (add to PROVIDERS in contract.js)
  static enforcementMode = ENFORCEMENT_MODES.SYNC_CONFIRM; // or sync_interrupt / detect_only

  constructor({ apiKey, ...rest } = {}) {
    super({ apiKey, ...rest });
    if (!apiKey) throw new Error('YourProviderSource requires an apiKey');
    this.apiKey = apiKey;
  }

  async listAgents() {
    // Discover agents accessible with the customer's creds.
    // Return: Array<{ id: string, name?: string|null, native?: object }>
  }

  async *streamEvents(agentId, opts) {
    // Yield one WMAAction per observed event. Order matters
    // (consumers compute Markov sequences).
    // for await (const native of pollVendorAPI(agentId)) {
    //   yield translateToWMAAction(native);
    // }
  }

  async enforce(action, decision) {
    // ONLY required if enforcementMode != detect_only.
    // Translate WMA's canonical {decision: 'allow'|'deny'} into the
    // vendor's native confirm/interrupt call.
    // Return { enforced: boolean, native_response?: object }
  }
}
```

That's it. Don't touch the anonymizer, the typology classifier, the Guardian scoring, or Fortress. They consume `WMAAction` and don't care which Source emitted it.

---

## 3. The `WMAAction` canonical shape

Every event your adapter yields MUST satisfy this shape. The full typedef is in `src/sources/contract.js`.

### Required fields (every event)

| Field | Type | What it means |
|---|---|---|
| `id` | string | Stable, dedup-friendly event id from the vendor |
| `provider` | string | Your `static providerName` (e.g. `'openai-agents'`) |
| `agent_id` | string | The native agent id |
| `session_id` | string | The native session/thread/run id |
| `action_type` | string | One of `ACTION_TYPES` (see §4) |
| `timestamp` | ISO-8601 string | When the event happened |
| `status` | `'ok'` \| `'error'` \| `'blocked'` | Outcome |

### Optional fields (populate when applicable)

| Field | When |
|---|---|
| `tool_name` | tool_use family events |
| `model` | llm_call events |
| `duration_ms` | When you can pair a start/end event |
| `tokens_used`, `input_tokens`, `output_tokens`, `cache_*` | llm_call events |
| `error` | truncated to ≤500 characters |
| `input`, `output` | Raw payloads — **STAY LOCAL** (see §6 Containment) |
| `parent_agent_id` | Sub-agent events (PR-C) |
| `composition_pattern` | `'solo'` \| `'hierarchy'` \| `'graph'` \| `'peer'` (PR-C) |

### Validation

Run `validateWMAAction(obj)` in your test suite. In dev, set `WMA_DEV_VALIDATE=1` to validate at runtime.

---

## 4. Canonical `action_type` vocabulary

Defined in `ACTION_TYPES` in `src/sources/contract.js`. Map your vendor's native events onto these — don't invent new ones inline. If a new kind of action genuinely doesn't fit, propose adding to the constant.

| Constant | When to emit |
|---|---|
| `LLM_CALL` | An LLM inference happened (yield once per call with token counts + latency) |
| `TOOL_USE` | Built-in/provider tool called (e.g. web_search, web_fetch, bash) |
| `MCP_TOOL_USE` | MCP server tool called |
| `CUSTOM_TOOL_USE` | Customer-defined tool called |
| `CUSTOM_TOOL_RESULT` | Customer returned the result of a custom tool |
| `TOOL_CONFIRMATION` | Human approved/denied a tool call (audit) |
| `USER_MESSAGE` | User sent input to the agent |
| `USER_INTERRUPT` | User cancelled mid-execution |
| `MESSAGE` | Agent emitted a final/intermediate response |
| `THINKING` | Agent produced internal reasoning (extended thinking, scratchpad) |
| `CONTEXT_COMPACTED` | The thread was compacted (data loss event — security relevant) |
| `THREAD_CREATED` | A sub-thread or sub-conversation was spawned |
| `THREAD_MESSAGE_SENT` / `THREAD_MESSAGE_RECEIVED` | Multi-agent message passing |
| `CONFIG_CHANGE` | Session/agent configuration changed mid-flight |
| `STATE_TRANSITION` | Session/thread changed lifecycle state (running/idle/terminated/…) |
| `SESSION_ERROR` | Session-level error |
| `SHIELD_DECISION` | WMA itself blocked an action (Shield emits these) |

---

## 5. Enforcement mode — what your adapter promises

Declared via `static enforcementMode`. It determines what Shield will be able to do:

| Mode | What it means | Examples |
|---|---|---|
| `sync_confirm` | Adapter can confirm/deny a tool call **before** it executes. Strongest. | Anthropic Managed `user.tool_confirmation`; AWS Bedrock AgentCore Gateway REQUEST interceptors |
| `sync_interrupt` | Adapter can interrupt the agent mid-execution (e.g. after an LLM call) but cannot pre-confirm individual tools. | Anthropic Managed `user.interrupt` (as a fallback) |
| `detect_only` | Adapter can only observe, not block. Watch + Guardian still work; Shield UI shows "detect_only — enforcement disabled". | E2B lifecycle webhooks; any pure observability sink |

**Don't lie**. If your provider only exposes post-hoc audit logs, declare `detect_only` honestly — overstating leads to silent UI bugs in Shield.

---

## 6. Containment invariant

This is non-negotiable. WMA promises customers that raw payloads **never leave their machine**. Your adapter MUST:

1. Yield `WMAAction` objects that MAY carry raw bytes in `input` / `output` / `error` — these are written to the **local NDJSON file only**.
2. Never send those raw fields to any WMA-controlled cloud endpoint directly. The anonymizer (`src/anonymizer.js`) is the single gate between local NDJSON and Fortress signals.
3. If your adapter runs **in-process inside the customer's agent runtime** (pattern #2 — instrumentation), it must call the anonymizer before any network egress to WMA. It is forbidden to ship raw NDJSON entries from inside the customer's process; the only thing that may leave is the anonymized signals payload.

See `docs/CONTAINMENT.md` (PR-E) for the full invariant statement and the per-pattern test suite.

---

## 7. Testing your adapter

At minimum:

```js
import { assertImplementsSource, validateWMAAction } from '../src/sources/contract.js';
import { YourProviderSource } from '../src/sources/your-provider.js';

test('contract', () => assertImplementsSource(YourProviderSource));

test('emits valid WMAAction', async () => {
  const s = new YourProviderSource({ apiKey: 'fake' });
  // mock the vendor API…
  for await (const ev of s.streamEvents('agent_x', { sessionId: 's' })) {
    const r = validateWMAAction(ev);
    assert.ok(r.valid, r.errors.join('; '));
  }
});
```

See `test/source-contract.test.js` for the AnthropicManagedSource reference test.

---

## 8. Checklist before opening a PR

- [ ] `static providerName` added to `PROVIDERS` in `contract.js`
- [ ] `static enforcementMode` declared honestly
- [ ] `assertImplementsSource(YourSource)` passes
- [ ] Every yielded action passes `validateWMAAction`
- [ ] Raw payloads never leave the customer process (Containment)
- [ ] `docs/CONTAINMENT.md` updated for your pattern if novel
- [ ] One reference test exercising the full lifecycle (mock vendor → yield → validate)
- [ ] Provider added to the README "supported frameworks" table
