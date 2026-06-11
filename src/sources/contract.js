// ────────────────────────────────────────────────────────────────────────
// WatchMyAgents — Source contract (V1)
// ────────────────────────────────────────────────────────────────────────
//
// THIS FILE IS THE CONTRACT every adapter MUST follow.
//
// Why this exists:
//   The SDK shipped today integrates Anthropic Managed Agents via the
//   functions in `./anthropic-managed.js`. To add OpenAI / LangGraph /
//   CrewAI / Bedrock / etc. without rewriting the pipe each time, the
//   contract between "fetching events" and "the rest of WMA" has to be
//   explicit.
//
//   Everything in WMA (anonymizer, typology classifier, Guardian scoring,
//   Shield enforcement, Fortress signals payload) operates on `WMAAction`
//   objects — the canonical shape defined below. Each Source adapter is
//   responsible for translating its provider's native events into this
//   shape, and nothing else.
//
// Containment invariant:
//   A Source's `streamEvents()` yields WMAAction objects that MAY carry
//   raw payload bytes in `input`/`output` — these are written to the
//   LOCAL NDJSON file but NEVER sent to Fortress. The anonymizer is the
//   single gate between WMAAction (raw) and the signals payload (cloud).
//   See `src/anonymizer.js` and `docs/SOURCE-ADAPTER-CONTRACT.md`.

// ── Canonical vocabulary ────────────────────────────────────────────────

// Every WMAAction.action_type MUST be one of these. New adapters that
// emit a novel kind of action should propose adding a new constant here
// (and document it) rather than inventing one inline.
//
// Audit note (Phase 1.A, v1.1.3): the vocabulary is grouped into two
// tiers to make the contract honest about which types are framework-
// agnostic vs which originated from one specific framework (Anthropic
// Managed Agents was the seed adapter). New adapters can:
//   1. Use UNIVERSAL types directly — they're always meaningful.
//   2. Use FRAMEWORK-SPECIFIC types ONLY if the new framework has a
//      genuinely equivalent concept. Otherwise emit a UNIVERSAL type
//      (e.g., OpenAI handoffs → HANDOFF, NOT THREAD_MESSAGE_SENT).
//   3. Propose a new constant via a PR when their framework exposes a
//      genuinely new category of event.
export const ACTION_TYPES = Object.freeze({
  // ── UNIVERSAL (every adapter should be able to emit these) ─────────────
  /** Model inference call (with token usage + duration). */
  LLM_CALL: 'llm_call',
  /** Provider-built-in tool invocation (web_search, web_fetch, bash, code_exec, …). */
  TOOL_USE: 'tool_use',
  /** MCP server tool invocation. */
  MCP_TOOL_USE: 'mcp_tool_use',
  /** Customer-defined tool invocation (the agent calls a tool the user wired). */
  CUSTOM_TOOL_USE: 'custom_tool_use',
  /** Customer returned the result of a custom tool. */
  CUSTOM_TOOL_RESULT: 'custom_tool_result',
  /** Human (or orchestrator) approved/denied a pending tool call. */
  TOOL_CONFIRMATION: 'tool_confirmation',
  /** User sent input to the agent (prompt, follow-up question, …). */
  USER_MESSAGE: 'user_message',
  /** User cancelled execution mid-flight. */
  USER_INTERRUPT: 'user_interrupt',
  /** Agent emitted an output message (final reply or intermediate). */
  MESSAGE: 'message',
  /** Agent emitted internal reasoning (extended thinking / scratchpad). */
  THINKING: 'thinking',
  /** Session-level error from the provider runtime. */
  SESSION_ERROR: 'session_error',
  /** Agent A passes control to agent B (OpenAI Agents handoffs, AgentCore
   *  multi-agent, CrewAI manager delegation, Hermes spawn_subagent, LangGraph
   *  subgraph spawn). For Anthropic Task tool, this is typically emitted as
   *  THREAD_MESSAGE_SENT — both are valid for that framework. */
  HANDOFF: 'handoff',
  /** Graph-flavored frameworks (LangGraph, AutoGen state machine,
   *  conditional workflow engines) emit this when execution moves from one
   *  node/state to another. Carries `from_node`/`to_node` in `output`. */
  GRAPH_NODE_TRANSITION: 'graph_node_transition',
  /** Shield-internal — emitted when WMA itself blocks/allows/interrupts
   *  an action. Always carries the decision in `output`. */
  SHIELD_DECISION: 'shield_decision',

  // ── FRAMEWORK-SPECIFIC (Anthropic Managed Agents-origin, may map cleanly to
  //    other frameworks but were named after the Anthropic event vocabulary) ──
  /** Anthropic-specific: emitted when the context window saturates and the
   *  thread is compacted (some history lost). OpenAI/CrewAI/LangGraph
   *  generally roll the window silently without an explicit event. */
  CONTEXT_COMPACTED: 'context_compacted',
  /** Anthropic-specific: a sub-thread was spawned within a session (Task
   *  tool delegation). Other frameworks model this as HANDOFF + a new
   *  agent identity. */
  THREAD_CREATED: 'thread_created',
  /** Anthropic-specific: inter-agent message in a thread (parent → sub-agent). */
  THREAD_MESSAGE_SENT: 'thread_message_sent',
  /** Anthropic-specific: reply from a sub-agent in a thread (sub → parent). */
  THREAD_MESSAGE_RECEIVED: 'thread_message_received',
  /** Anthropic-specific: session configuration changed mid-flight
   *  (`session.updated` event with a diff). Other frameworks generally
   *  don't expose live config edits as events. */
  CONFIG_CHANGE: 'config_change',
  /** Anthropic-specific: session/thread lifecycle state change (running/
   *  idle/rescheduled/terminated). Other frameworks have different state
   *  machines; map cautiously. */
  STATE_TRANSITION: 'state_transition',
});

// v1.4.2 F-38 (P0 audit) — the three tool-INVOCATION action_types form one
// security-equivalent family. WHICH surface a tool call came through
// (provider built-in vs MCP server vs customer-wired custom tool) is an
// adapter implementation detail, not a security distinction: all three are
// "the agent invoked a tool." A deny/allowlist policy keyed on the generic
// `tool_use` MUST catch all three, or it silently misses MCP + custom tool
// calls — exactly where an attacker pivots. The policy matcher
// (src/shield/policy.js) expands a generic `tool_use` target to this family;
// matching a SPECIFIC member (mcp_tool_use / custom_tool_use) stays exact so
// an operator can still target one surface when they mean to.
// SignalsAggregator (src/anonymizer.js) uses the same set for IoC capture.
export const TOOL_USE_FAMILY = Object.freeze([
  ACTION_TYPES.TOOL_USE,
  ACTION_TYPES.MCP_TOOL_USE,
  ACTION_TYPES.CUSTOM_TOOL_USE,
]);

export const STATUS_VALUES = Object.freeze({
  OK: 'ok',
  ERROR: 'error',
  BLOCKED: 'blocked',
});

// A Source declares how strongly it can enforce policies. This drives
// what Shield can do on its events:
//   sync_confirm    → can confirm/deny a tool call before execution
//                     (Anthropic user.tool_confirmation, AgentCore
//                     Gateway interceptor with transformedResponse)
//   sync_interrupt  → can interrupt mid-execution after an LLM call
//                     (Anthropic user.interrupt)
//   detect_only     → can observe but cannot block — post-hoc audit
//                     (E2B lifecycle webhooks, pure observability sinks)
export const ENFORCEMENT_MODES = Object.freeze({
  SYNC_CONFIRM: 'sync_confirm',
  SYNC_INTERRUPT: 'sync_interrupt',
  DETECT_ONLY: 'detect_only',
});

// How the agent composes with other agents — drives the WMA dashboard
// tree view and the policy `subtree` surface (PR-C).
//   solo       → no sub-agents, one tool-loop
//   hierarchy  → boss + workers (CrewAI manager, Anthropic Task tool,
//                Hermes Agent spawn-subagent)
//   graph      → nodes + edges (LangGraph)
//   peer       → N agents converse on equal footing (AutoGen)
export const COMPOSITION_PATTERNS = Object.freeze({
  SOLO: 'solo',
  HIERARCHY: 'hierarchy',
  GRAPH: 'graph',
  PEER: 'peer',
});

// Known provider identifiers. Adapters should register their provider
// name here as they land so consumers can build provider-specific UI.
export const PROVIDERS = Object.freeze({
  ANTHROPIC_MANAGED: 'anthropic-managed',
  // v1.3.0 (Phase 2.A) — OpenAI Agents SDK (TypeScript/JS).
  // Customer-instrumented (not auto-discovery). Push-model via:
  //   - Tool Input Guardrails (Shield enforcement: allow/deny/interrupt)
  //   - RunHooks EventEmitter (Watch observability)
  // See `./openai-agents-js.js` and `docs/adapters/openai-agents-js.md`.
  OPENAI_AGENTS: 'openai-agents',
  // Coming next:
  // AWS_BEDROCK_AGENTCORE: 'aws-bedrock-agentcore',
  // CLAUDE_CODE: 'claude-code',
  // LANGGRAPH: 'langgraph',
  // CREWAI: 'crewai',
});

// ── WMAAction canonical shape ───────────────────────────────────────────
//
// /**
//  * @typedef {object} WMAAction
//  *
//  * REQUIRED — every Source MUST populate these:
//  * @property {string} id              Stable, dedup-friendly event id
//  * @property {string} provider        From PROVIDERS (e.g. 'anthropic-managed')
//  * @property {string} agent_id        Native agent identifier
//  * @property {string} session_id      Native session/thread/run identifier
//  * @property {string} action_type     From ACTION_TYPES
//  * @property {string} timestamp       ISO-8601
//  * @property {'ok'|'error'|'blocked'} status
//  *
//  * OPTIONAL — present when applicable:
//  * @property {string|null} tool_name              For tool_use family
//  * @property {string|null} model                  For llm_call
//  * @property {number|null} duration_ms            Latency (start→end pair)
//  * @property {number|null} tokens_used            For llm_call (input+output+cache)
//  * @property {number|null} input_tokens
//  * @property {number|null} output_tokens
//  * @property {number|null} cache_read_tokens
//  * @property {number|null} cache_creation_tokens
//  * @property {string|null} error                  Truncated error message (≤500ch)
//  * @property {object|null} input                  Raw input payload — STAYS LOCAL
//  * @property {object|null} output                 Raw output payload — STAYS LOCAL
//  *
//  * SUB-AGENT FIELDS (PR-C — see WMAAction.parent_agent_id):
//  * @property {string|null} parent_agent_id        Null for root agents
//  * @property {string|null} composition_pattern    From COMPOSITION_PATTERNS
//  *
//  * MULTI-AGENT DISCRIMINATORS (v1.0.2 F-6a — preserved LOCALLY only,
//  * never sent raw to Fortress; the SignalsAggregator derives the
//  * aggregated session_ids list from them at finalize time):
//  * @property {string|null} session_thread_id      The thread the event happened in.
//  *                                                For frameworks where one session can
//  *                                                host multiple threads/sub-agents
//  *                                                (Anthropic Task tool, future similar
//  *                                                designs), this is how the vendor
//  *                                                itself discriminates "parent vs sub".
//  * @property {string|null} agent_name             The human-named emitter of this event
//  *                                                (the parent agent OR a sub-agent
//  *                                                running inside the parent's session).
//  *
//  * TEAM CORRELATION (v1.3.0 — Phase 2.A OpenAI Agents SDK + future
//  * Claude Code dynamic workflows):
//  * @property {string|null} team_id                Stable identifier shared by every
//  *                                                event in a logical group of
//  *                                                cooperating agents. Sources:
//  *                                                  (a) customer override via
//  *                                                      WMA_TEAM_ID env var or
//  *                                                      programmatic setter,
//  *                                                  (b) auto-detected from the
//  *                                                      OpenAI Agents SDK
//  *                                                      `agent_handoff` event —
//  *                                                      all agents in the handoff
//  *                                                      chain share the same
//  *                                                      team_id,
//  *                                                  (c) future: Claude Code dynamic
//  *                                                      workflow `runId`.
//  *                                                Drives the Legions UI "Team view"
//  *                                                drill-down. Null when unknown.
//  *
//  * RUNTIME-COMPUTED CONTEXT (v1.2.0 — see src/shield/context.js):
//  *  ctx attributes (hour_of_day_utc, recent_error_rate, etc.) are NOT stored
//  *  on WMAAction — they're computed at policy eval time and live in the
//  *  ContextTracker only.
//  */

const REQUIRED_FIELDS = ['id', 'provider', 'agent_id', 'session_id', 'action_type', 'timestamp', 'status'];

/**
 * Validate a WMAAction at runtime. Returns `{ valid, errors }`.
 * Cheap enough to run on every yield in dev (process.env.WMA_DEV_VALIDATE=1).
 *
 * Adapters should call this BEFORE yielding in their test suite, and the
 * SDK can opt into runtime validation via the env flag.
 */
export function validateWMAAction(obj) {
  const errors = [];
  if (!obj || typeof obj !== 'object') {
    return { valid: false, errors: ['not an object'] };
  }
  for (const f of REQUIRED_FIELDS) {
    if (obj[f] == null) errors.push(`missing required field: ${f}`);
  }
  if (obj.action_type && !Object.values(ACTION_TYPES).includes(obj.action_type)) {
    errors.push(`unknown action_type "${obj.action_type}" — add to ACTION_TYPES in contract.js`);
  }
  if (obj.status && !Object.values(STATUS_VALUES).includes(obj.status)) {
    errors.push(`unknown status "${obj.status}" — must be one of ${Object.values(STATUS_VALUES).join(', ')}`);
  }
  if (obj.composition_pattern != null
      && !Object.values(COMPOSITION_PATTERNS).includes(obj.composition_pattern)) {
    errors.push(`unknown composition_pattern "${obj.composition_pattern}"`);
  }
  if (obj.timestamp && Number.isNaN(Date.parse(obj.timestamp))) {
    errors.push(`timestamp not parseable: ${obj.timestamp}`);
  }
  return { valid: errors.length === 0, errors };
}

// ── Source abstract base class ──────────────────────────────────────────

/**
 * Every framework adapter MUST extend this class and override the abstract
 * methods. The Source is the boundary between "the customer's agent
 * runtime" and "the rest of WMA" — the only place where vendor-specific
 * code lives. Once a Source yields WMAAction objects, the pipe is
 * provider-agnostic.
 *
 * Static contract:
 *   providerName            — value from PROVIDERS
 *   enforcementCapability   — value from ENFORCEMENT_MODES; the MAX the
 *                             provider can do. The EFFECTIVE per-agent
 *                             mode may be weaker (resolved at runtime
 *                             via the provider's effectiveEnforcementMode
 *                             helper; see AnthropicManagedSource for the
 *                             reference impl).
 *
 *   ⚠️  Renamed from `enforcementMode` in v1.1.3 because the previous
 *       name was misleading (a static field is the capability ceiling,
 *       not the runtime mode). `enforcementMode` is kept as a backward-
 *       compat alias for v1.x consumers; it returns the same value.
 *
 * Instance contract:
 *   listAgents()       — return all agents accessible with the client creds
 *   streamEvents(id)   — async generator yielding WMAAction objects
 *   enforce(action, d) — only required if enforcementCapability != detect_only
 *
 * See `docs/SOURCE-ADAPTER-CONTRACT.md` for the full author guide.
 */
export class Source {
  static providerName = null;
  static enforcementCapability = null;
  // v1.1.3 backwards-compat alias for the renamed static field. Subclasses
  // that set `enforcementMode` directly still work; new subclasses should
  // set `enforcementCapability` instead. Resolved as a getter at read
  // time so the rename can land without breaking consumers like
  // assertImplementsSource() that read it from the class.
  static get enforcementMode() { return this.enforcementCapability; }

  constructor(config = {}) {
    if (new.target === Source) {
      throw new Error('Source is abstract — extend it in a subclass (e.g., AnthropicManagedSource).');
    }
    this.config = config;
  }

  /**
   * Discover all agents under the client's credentials.
   * @returns {Promise<Array<{id: string, name?: string, native?: object}>>}
   */
  async listAgents() {
    throw new Error(`${this.constructor.name}.listAgents() not implemented`);
  }

  /**
   * Stream WMAAction objects for the given agent. The implementation may
   * page, retry, dedup, or restart internally — consumers see a single
   * ordered stream.
   * @param {string} agentId
   * @param {object} [opts]
   * @yields {WMAAction}
   */
  async *streamEvents(agentId, opts) { // eslint-disable-line no-unused-vars
    throw new Error(`${this.constructor.name}.streamEvents() not implemented`);
    yield; // make this a generator
  }

  /**
   * Enforce a policy decision against a pending action. Only called when
   * the Source's static `enforcementMode` is not `detect_only`. The
   * subclass is responsible for translating WMA's canonical decision
   * (`allow`|`deny`) into the provider's native confirm/interrupt call.
   * @param {WMAAction} action
   * @param {{decision: 'allow'|'deny', reason?: string}} decision
   * @returns {Promise<{enforced: boolean, native_response?: object}>}
   */
  async enforce(action, decision) { // eslint-disable-line no-unused-vars
    if (this.constructor.enforcementCapability === ENFORCEMENT_MODES.DETECT_ONLY) {
      throw new Error(`${this.constructor.name} is detect_only — enforce() must not be called`);
    }
    throw new Error(`${this.constructor.name}.enforce() not implemented`);
  }
}

/**
 * Assertion helper for tests: verify a Source subclass declares the
 * required static fields and overrides the abstract methods.
 * Throws on any contract violation.
 */
export function assertImplementsSource(SourceClass) {
  if (!(SourceClass.prototype instanceof Source)) {
    throw new Error(`${SourceClass?.name || SourceClass} does not extend Source`);
  }
  if (!Object.values(PROVIDERS).includes(SourceClass.providerName)) {
    throw new Error(`${SourceClass.name}.providerName="${SourceClass.providerName}" not in PROVIDERS`);
  }
  // v1.1.3: read enforcementCapability (the new canonical name) but fall
  // back to enforcementMode for legacy subclasses that haven't migrated.
  const capability = SourceClass.enforcementCapability ?? SourceClass.enforcementMode;
  if (!Object.values(ENFORCEMENT_MODES).includes(capability)) {
    throw new Error(`${SourceClass.name}.enforcementCapability="${capability}" not in ENFORCEMENT_MODES`);
  }
  // The base class throws "not implemented" — a real subclass must override.
  for (const m of ['listAgents', 'streamEvents']) {
    if (SourceClass.prototype[m] === Source.prototype[m]) {
      throw new Error(`${SourceClass.name}.${m}() must be overridden`);
    }
  }
  if (capability !== ENFORCEMENT_MODES.DETECT_ONLY
      && SourceClass.prototype.enforce === Source.prototype.enforce) {
    throw new Error(`${SourceClass.name}.enforce() must be overridden (enforcementCapability=${capability})`);
  }
}
