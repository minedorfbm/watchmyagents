# WMA Adapter Authoring — context for a parallel session

> **Paste this whole file into a fresh Claude Code session before starting.**
> You are building ONE WatchMyAgents source adapter for a specific agent
> framework. It is a **Pattern 1** adapter (built natively in the Node SDK —
> like the already-shipped Anthropic Managed and OpenAI adapters; *not* the
> planned **Pattern 2** = `watchmyagents-py` Python bridge). This brief targets
> the **in-process integration shape**, so the **OpenAI Agents adapter is your
> reference** — copy its structure. A separate "main session" owns the shared
> contract, integration, and all releases. You produce the adapter; you do NOT
> bump versions or publish.

---

## 1. The 30-second mental model

WatchMyAgents (WMA) is a **horizontal security layer for AI agents**, zero
runtime dependencies, local-first. Two functions:

- **Watch** — observe EVERY action an agent takes (tool calls, prompts, results,
  state) → append to a local NDJSON log.
- **Shield** — evaluate each tool call against a policy ruleset and **block**
  the disallowed ones live, BEFORE they execute.

Everything in WMA operates on ONE canonical object: the **`WMAAction`** (defined
in `src/sources/contract.js`). Your adapter's whole job is: **translate your
framework's native events → `WMAAction`**, and **wire the Shield interception**.

**Terminology (be precise):** *Pattern 1* = an adapter built natively in this
Node SDK (all of ours so far). *Pattern 2* = the future `watchmyagents-py`
Python thin-client → Node daemon bridge. ALL the adapters below are **Pattern 1**.

Within Pattern 1 there are three **integration SHAPES** — they only decide which
existing adapter you copy:
- **In-process library** (template: `src/sources/openai-agents-js.js`) — OpenAI
  Agents SDK, Vercel AI SDK, LangGraph.js, Google GenAI… WMA is wired into the
  agent code via the framework's hooks/middleware. **← this brief is for this shape.**
- **Poll / managed cloud** (template: `src/sources/anthropic-managed.js`) —
  Anthropic Managed, Vertex Agent Engine, Bedrock AgentCore… WMA polls a cloud API.
- **Hook command** (template: `src/sources/claude-code.js`) — Claude Code / Cowork.

---

## 2. Repo + commands

- Repo: `minedorfbm/watchmyagents` (Node.js, **zero runtime deps**). `git remote -v` must show `minedorfbm/watchmyagents` before any push (NOT armafbm/anything).
- Run tests: `node --test` (whole suite). Run it before AND after your change.
- **Reference adapter (READ THESE FIRST):**
  - `src/sources/openai-agents-js.js` — normalizers + `attachWmaWatch` + `wmaToolInputGuardrail`.
  - `src/openai-agents.js` — the stable factory entry (`openaiAgents({...}) → { shield, watch, meta, mode }`).
  - `src/openai-agents.d.ts` — TS types for the factory.
  - `test/sources-openai-agents-js.test.js` + `test/openai-agents-entrypoint.test.js` — copy the test shape.
  - `docs/adapters/openai-agents-js.md` — copy the doc shape.

---

## 3. The contract (READ `src/sources/contract.js`)

- **`PROVIDERS`** — add yours (e.g. `VERCEL_AI: 'vercel-ai'`). Lowercase-kebab string.
- **`ACTION_TYPES`** — the canonical vocabulary. The ones you'll use most:
  - `tool_use` (provider/built-in tool), `mcp_tool_use` (MCP tool), `custom_tool_use` (customer-wired tool), `tool_result`/`custom_tool_result` (a tool returned).
  - `llm_call`, `message`, `user_message`, `handoff`, `state_transition`.
- **`WMAAction` shape** — `{ id, provider, agent_id, agent_name, session_id, session_thread_id, action_type, timestamp, status('ok'|'error'|'blocked'), tool_name, model, duration_ms, parent_agent_id, composition_pattern, team_id, input, output }`.
  **Every action you emit MUST pass `validateWMAAction()`** — assert it in your tests.
- **`TOOL_USE_FAMILY` (F-38, critical security invariant)** — a policy keyed on the generic `tool_use` MUST also catch `mcp_tool_use` and `custom_tool_use` (the matcher expands it). So map a built-in tool → `tool_use`, an MCP tool → `mcp_tool_use`, a customer tool → `custom_tool_use`. Never collapse them all to one type unless they genuinely are one.

---

## 4. NON-NEGOTIABLE rules (these are load-bearing — do not bend them)

1. **Containment.** Raw payloads (prompts, tool ARGUMENTS, tool OUTPUTS, file
   contents) go in `WMAAction.input` / `WMAAction.output` and stay **LOCAL**
   (the NDJSON file). They are NEVER sent to Fortress. The anonymizer
   (`src/anonymizer.js`) is the ONLY gate from raw → cloud. **Do not add any
   network call that ships raw data.** If you upload anything, it's salted
   hashes + counts only.
2. **Zero runtime dependencies.** Node built-ins only. The agent framework is a
   `peerDependency`, never a `dependency`. Adding anything to
   `package.json#dependencies` is forbidden.
3. **Real fixtures before publish.** Build against the framework's documented
   event shape, but you MUST validate the normalizer against a **REAL captured
   event** from the framework before it ships. Do NOT trust your memory of the
   API — capture a real event (a fixture) and test against it. (We've been
   burned by this: Claude Code Cowork turned out not to fire hooks at all.)
4. **Fail-closed.** Shield defaults to **deny** on an internal error, never
   allow. `enforce` mode must FAIL LOUD at config time if no policy source is
   configured (don't silently degrade to allow-all).
5. **Test discipline.** Unit tests for the normalizer (every output validates) +
   the Shield decision mapping (allow/deny/shadow). End-to-end test of the
   attach + a deny scenario. Mirror the OpenAI test files.
6. **Stable factory entry via `package.json#exports`.** Expose
   `watchmyagents/<framework>` → `src/<framework>.js` (the factory). No deep
   imports in docs/examples (`watchmyagents/src/...` is blocked for npm
   consumers — use the public entry).

---

## 5. The in-process integration shape — what to actually build

**STEP 0 — VERIFY FIRST (don't skip).** Before writing any adapter code, confirm
your framework actually exposes:
- (a) a **tool-call observability** hook/callback/middleware (for Watch), and
- (b) a **pre-tool interception** point that runs BEFORE the tool executes and
  can **block** it (for Shield).
Read the framework's real docs / a working example. If it can only observe (no
pre-tool block) → Shield is **detect-only**, document it honestly. If it has no
hook at all → STOP and flag the main session; the adapter may not be viable
(this is exactly what killed the Cowork hook plan).

**Then build (copy the OpenAI adapter):**
- **Watch** — attach a listener to the framework's tool-start/tool-end event;
  normalize → `WMAAction` → `Logger.write()` (NDJSON). Track `team_id` /
  multi-agent (handoffs) if the framework has them.
- **Shield** — at the pre-tool interception point: normalize the about-to-fire
  tool call → `evaluate(action, ruleset, ctx)` (from `src/shield/policy.js`) →
  map the verdict to the framework's block mechanism (throw / reject / return a
  blocked result). `deny`/`interrupt` → block; `allow` → proceed; `shadow` →
  log only, proceed. Record the decision via `DecisionLogger`. Set
  `enforcement_delivered: true` when the block is synchronous/guaranteed.

---

## 6. Your deliverable (PR-ready, conflict-free)

Create ONLY these NEW files (do not touch shared files — see §7):
- `src/sources/<framework>.js` — normalizers + watch attach + shield guardrail.
- `src/<framework>.js` — the factory entry (copy `src/openai-agents.js`).
- `src/<framework>.d.ts` — TS types (copy `src/openai-agents.d.ts`).
- `test/<framework>-normalize.test.js` + `test/<framework>-entrypoint.test.js` —
  normalizer (with `validateWMAAction` asserts) + factory + decision tests.
- `docs/adapters/<framework>.md` — setup, what's captured, the Containment note.
- A short note listing any `package.json` `exports`/`bin` entry you need + any
  new `ACTION_TYPE`/`PROVIDER`. The MAIN SESSION applies those centrally.

Run `node --test` — your new tests pass, the existing suite still passes.

---

## 7. Coordination (CRITICAL for parallel work)

- **DO NOT edit these shared files** (the main session owns them; editing them in
  parallel = merge conflicts): `src/sources/contract.js`, `src/shield/policy.js`,
  `src/shield/decisions.js`, `src/shield/upload.js`, `src/anonymizer.js`,
  `src/logger.js`, `package.json`, and the existing adapters.
- If you need a new `PROVIDER`, `ACTION_TYPE`, an `exports` entry, or a shared
  helper change → **write it down in your final summary**; the main session adds
  it centrally and wires your `exports`.
- Only **ADD** your adapter's own new files. Stay in your lane.
- The **main session** (the human's primary Claude) does ALL integration,
  versioning, audits, and npm publishing. You build + test the adapter and hand
  it back. **Never bump the version or push/publish.**

---

## 8. The one-line task

> Build the WMA **Pattern-1** adapter for **`<FRAMEWORK NAME>`**, using the
> OpenAI Agents adapter as the template. Verify the framework's tool-observe +
> pre-tool-block surfaces FIRST. Normalize to `WMAAction` (validate every one),
> wire Watch + Shield, write tests + a doc, and hand back a PR-ready set of NEW
> files plus a note of any shared-contract change the main session must apply.
