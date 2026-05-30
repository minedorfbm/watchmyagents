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
export const ACTION_TYPES = Object.freeze({
  LLM_CALL: 'llm_call',
  TOOL_USE: 'tool_use',
  MCP_TOOL_USE: 'mcp_tool_use',
  CUSTOM_TOOL_USE: 'custom_tool_use',
  CUSTOM_TOOL_RESULT: 'custom_tool_result',
  TOOL_CONFIRMATION: 'tool_confirmation',
  USER_MESSAGE: 'user_message',
  USER_INTERRUPT: 'user_interrupt',
  MESSAGE: 'message',
  THINKING: 'thinking',
  CONTEXT_COMPACTED: 'context_compacted',
  THREAD_CREATED: 'thread_created',
  THREAD_MESSAGE_SENT: 'thread_message_sent',
  THREAD_MESSAGE_RECEIVED: 'thread_message_received',
  CONFIG_CHANGE: 'config_change',
  STATE_TRANSITION: 'state_transition',
  SESSION_ERROR: 'session_error',
  // Shield-only — emitted when WMA itself blocks an action:
  SHIELD_DECISION: 'shield_decision',
});

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
  // Coming next:
  // OPENAI_AGENTS: 'openai-agents',
  // AWS_BEDROCK_AGENTCORE: 'aws-bedrock-agentcore',
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
 *   providerName        — value from PROVIDERS
 *   enforcementMode     — value from ENFORCEMENT_MODES
 *
 * Instance contract:
 *   listAgents()        — return all agents accessible with the client creds
 *   streamEvents(id)    — async generator yielding WMAAction objects
 *   enforce(action, d)  — only required if enforcementMode != detect_only
 *
 * See `docs/SOURCE-ADAPTER-CONTRACT.md` for the full author guide.
 */
export class Source {
  static providerName = null;
  static enforcementMode = null;

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
    if (this.constructor.enforcementMode === ENFORCEMENT_MODES.DETECT_ONLY) {
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
  if (!Object.values(ENFORCEMENT_MODES).includes(SourceClass.enforcementMode)) {
    throw new Error(`${SourceClass.name}.enforcementMode="${SourceClass.enforcementMode}" not in ENFORCEMENT_MODES`);
  }
  // The base class throws "not implemented" — a real subclass must override.
  for (const m of ['listAgents', 'streamEvents']) {
    if (SourceClass.prototype[m] === Source.prototype[m]) {
      throw new Error(`${SourceClass.name}.${m}() must be overridden`);
    }
  }
  if (SourceClass.enforcementMode !== ENFORCEMENT_MODES.DETECT_ONLY
      && SourceClass.prototype.enforce === Source.prototype.enforce) {
    throw new Error(`${SourceClass.name}.enforce() must be overridden (enforcementMode=${SourceClass.enforcementMode})`);
  }
}
