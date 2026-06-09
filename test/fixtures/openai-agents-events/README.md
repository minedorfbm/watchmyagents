# OpenAI Agents SDK event fixtures

Real captures from a live `@openai/agents` runtime. Used by
`test/sources-openai-agents-js.test.js` to verify the adapter normalizes
the EXACT shapes the SDK emits — not synthetic stand-ins that may drift.

## Capture protocol

The fixture capture script lives in `examples/adapters/capture-fixtures.ts`
(in this repo). Run against a real OpenAI account:

```bash
export OPENAI_API_KEY=sk-proj-...
node --import tsx examples/adapters/capture-fixtures.ts
```

It writes one JSON file per event type to this directory:

| Event | File | Notes |
|---|---|---|
| `agent_start` | `agent_start.json` | First event in any run |
| `agent_end` | `agent_end.json` | Last event in any run |
| `agent_handoff` | `agent_handoff.json` | Multi-agent example required |
| `agent_tool_start` | `agent_tool_start.json` | One sample with `function_tool` call |
| `agent_tool_end` | `agent_tool_end.json` | Matching end for tool_start |

Each file contains the raw event arguments as the SDK passes them to the
listener, plus a `meta` block with the SDK version + Node version.

## When to re-capture

- After bumping the `@openai/agents` peer-dep version
- When a Codex audit flags adapter-event drift
- When the SDK changelog mentions any lifecycle event change

## Until real fixtures exist

The tests fall back to synthetic fixtures embedded in the test file
itself — those are intentionally close to the documented shape from
`@openai/agents` source (`packages/agents-core/src/lifecycle.ts`,
`packages/agents-core/src/runner/toolExecution.ts`). Once real captures
land here, the tests load from disk and the synthetics get deleted.
