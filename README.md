# watchmyagents

**Cybersecurity for AI Agents.** A universal, zero-dependency JavaScript SDK to collect, anonymize, store locally, and securely export the logs of any AI agent (Claude, OpenAI, LangChain, custom).

- Zero external dependencies (only Node.js 18+ built-ins: `fs/promises`, `crypto`, `https`, `path`, `os`)
- Dual ESM + CJS exports
- Local NDJSON log storage with daily rotation
- Two-pass anonymization (PII regex + SHA-256 hashing of identifiers)
- AES-256-GCM encrypted batch export over HTTPS, with retry & local fallback
- Silent by default — no console output in production

## Install

```bash
npm install watchmyagents
```

## Quick start

```js
import WatchMyAgents, { watch } from 'watchmyagents'

const wma = new WatchMyAgents({
  apiKey: 'wma_xxx',
  agentId: 'my-agent',
  logDir: './watchmyagents-logs',
  exportUrl: 'https://ingest.watchmyagents.io/v1/logs',
  silent: true,
  batchInterval: 30000,
})

const result = await watch('search_web', { query: 'hello' }, async () => {
  return await myAgent.search('hello')
})
```

## Claude adapter

```js
import Anthropic from '@anthropic-ai/sdk'
import { createClaudeMonitor } from 'watchmyagents/adapters/claude'

const monitor = createClaudeMonitor({ apiKey: 'wma_xxx', agentId: 'claude-agent' })
const claude = monitor.wrap(new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY }))

await claude.messages.create({ model: 'claude-3-5-sonnet-20241022', /* ... */ })
```

## What is logged

Each NDJSON entry contains:

```
id, agent_id, framework, timestamp, action_type, tool_name,
model, duration_ms,
tokens_used, input_tokens, output_tokens,
cache_read_tokens, cache_creation_tokens, cost_usd,
status, error, sequence_number, session_id, input, output
```

`input` and `output` are written **only to local logs**. They are **never** included in the encrypted export — only metadata is sent.

## Token & cost monitoring

Per-action token usage is split into `input_tokens`, `output_tokens`,
`cache_read_tokens`, `cache_creation_tokens` and `tokens_used` (total). When
the model is known (Claude 3.5 / 3 / Haiku / Opus, GPT-4o / 4-turbo / 3.5),
`cost_usd` is estimated from a built-in pricing table. Override pricing via:

```js
new WatchMyAgents({
  tokenPricing: {
    'my-model': { input: 1.0, output: 4.0, cache_read: 0.1, cache_write: 1.25 },
  },
})
```

Get aggregated stats at any time:

```js
wma.tokenStats()
// {
//   total: { input, output, cache_read, cache_creation, sum, cost_usd },
//   by_tool:   { 'get_weather':       { ..., calls: 2 } },
//   by_action: { 'llm_call':          { ..., calls: 3 } },
//   by_model:  { 'claude-3-5-sonnet-...': { ..., calls: 2 } },
// }
```

The Claude, OpenAI and LangChain adapters auto-populate token splits from
each provider's `usage` payload. For custom agents, pass them via the
`watch()` `meta` argument or `logAction()`.

## Anonymization

Before any export, the SDK applies two passes:

1. **PII regex scrubbing** — `[EMAIL]`, `[TOKEN]`, `[API_KEY]`, `[CARD]`, `[PHONE]`, `[URL]`, `[IP]`
2. **SHA-256 hashing** of `user_id`, `session_id`, `agent_id` (irreversible, consistent for correlation)

## Encrypted export

Batches are flushed every `batchInterval` ms (default 30s) using AES-256-GCM with a key derived via `scryptSync(apiKey, salt, 32)` and a random 16-byte IV per batch. Failed sends retry x3 with exponential backoff and remain in local logs on failure. HTTPS only, certificate verification enabled.

## Local-only pilot mode

For a first test on a live agent — no remote endpoint, no API key, all
logs stay on disk:

```js
import WatchMyAgents from 'watchmyagents'

const wma = new WatchMyAgents({ agentId: 'deep-research-pilot', silent: true })
// no apiKey, no exportUrl → exporter stays disabled, nothing leaves the host
// the in-memory queue is bypassed (no memory growth)

// … run your agent for N hours …

await wma.shutdown()  // writes the session_end entry
```

Logs land in `./watchmyagents-logs/{agent_id}/{YYYY-MM-DD}.ndjson` with
file permissions `0600` (dir `0700`) so other users on the host can't
read them.

Inspect the run with the bundled CLI:

```bash
npx wma-inspect ./watchmyagents-logs
# or, when developing in this repo:
npm run inspect -- ./watchmyagents-logs
```

It prints total actions, status breakdown, token usage, estimated cost,
top tools/models/actions, errors, slowest calls, and per-session summary
read from `session_end` entries.

## Run the example

```bash
cp .env.example .env  # add ANTHROPIC_API_KEY
npm install
node examples/claude-agent/index.js
```

## License

MIT
