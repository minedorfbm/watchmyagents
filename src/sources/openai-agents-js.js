// OpenAI Agents SDK adapter — v1.3.0 (Phase 2.A).
//
// Adapter type: customer-instrumented, push-model. NOT auto-discovery.
//
// Why customer-instrumented:
//   OpenAI's Agents SDK runs IN-PROCESS on the customer's machine — not
//   on OpenAI's servers. There is no `listAgents` / `listConversations`
//   equivalent that lets WMA pull events from outside. To observe an
//   OpenAI agent, WMA code MUST run inside the customer's process,
//   alongside the agent. This is fundamentally different from Anthropic
//   Managed Agents (REST poll) and from AgentCore (REST poll). It is
//   the same model Datadog APM, Sentry, Langfuse, and OpenLLMetry use
//   for OpenAI observability. The customer wires two lines of code; the
//   rest is automatic.
//
// Two extension points used (both OFFICIAL APIs of @openai/agents):
//   1. Tool Input Guardrails (Shield enforcement).
//      `wmaToolInputGuardrail()` returns a shape-compatible
//      `{ type: 'tool_input', name, run }` object that slots into the
//      Agent's `toolInputGuardrails` array. When a tool is about to fire,
//      the SDK awaits our `run()` and respects its `behavior`:
//        - { type: 'allow' }                       → tool proceeds normally
//        - { type: 'rejectContent', message }      → tool is BLOCKED,
//                                                    message returned in
//                                                    place of result
//        - { type: 'throwException' }              → run aborts with an
//                                                    exception (kills the
//                                                    agent loop)
//   2. RunHooks EventEmitter (Watch observability).
//      `attachWmaWatch(runner)` registers listeners on the Runner's
//      EventEmitter for: agent_start, agent_end, agent_handoff,
//      agent_tool_start, agent_tool_end. Each event is normalized to
//      the WMA contract NDJSON shape and written via the Logger.
//
// Zero runtime dependency invariant:
//   We do NOT import from '@openai/agents'. Instead we return shape-
//   compatible plain objects. This keeps the SDK's zero-deps guarantee
//   intact AND avoids the dynamic-import dance. The downside: any
//   schema drift on the OpenAI side is caught only at runtime, not
//   compile-time. We mitigate via fixture-based tests + a TypeScript
//   .d.ts that pins the public surface.
//
// Containment invariant:
//   Tool args + results may carry sensitive customer data. They are
//   captured into the WMAAction's `input` / `output` fields and written
//   to LOCAL NDJSON only. The anonymizer is the single egress gate to
//   Fortress. Identical to Anthropic Managed adapter discipline.

import { randomUUID, createHash } from 'node:crypto';
import {
  PROVIDERS, ACTION_TYPES, STATUS_VALUES,
  COMPOSITION_PATTERNS, ENFORCEMENT_MODES,
} from './contract.js';
import { evaluate, loadPolicies } from '../shield/policy.js';
import { createContextTracker } from '../shield/context.js';
import { DecisionLogger } from '../shield/decisions.js';
import { Logger } from '../logger.js';
import { normalizeToolInput } from '../anonymizer.js';

// ── Constants ──────────────────────────────────────────────────────────

const PROVIDER = PROVIDERS.OPENAI_AGENTS;

// We default fail-CLOSED on Shield evaluation errors. Customer can flip
// to fail-OPEN via options.failOpen — but that's a security regression
// the customer must opt into explicitly, with all the implications.
const DEFAULT_FAIL_OPEN = false;

// v1.4 F-32 (P2 Codex audit on v1.3.0): bound the bytes we accept on
// the hot path. A misbehaving tool, a model hallucinating a huge
// response, or a malicious customer-controlled fixture can otherwise
// pin CPU on JSON.parse, blow up the NDJSON line, or fill the disk.
// 256 KB is generous for legitimate tool inputs/outputs (real-world
// captures from the Guardian agent peak at < 2 KB) and well under what
// would degrade Watch / Shield. Customers with outlier traffic can
// override per-guardrail via options.maxArgBytes / options.maxResultBytes.
const DEFAULT_MAX_ARG_BYTES = 256 * 1024;
const DEFAULT_MAX_RESULT_BYTES = 256 * 1024;
const TRUNCATION_SENTINEL = '…[truncated by WMA Shield]';

// Mirror of '@openai/agents' value object factory. Replicated here so we
// don't take a runtime dep. If '@openai/agents' ever changes the shape
// (extreme low probability), fixture tests will catch it.
const ToolGuardrailFunctionOutputFactory = Object.freeze({
  allow(outputInfo) {
    return { behavior: { type: 'allow' }, outputInfo };
  },
  rejectContent(message, outputInfo) {
    return { behavior: { type: 'rejectContent', message }, outputInfo };
  },
  throwException(outputInfo) {
    return { behavior: { type: 'throwException' }, outputInfo };
  },
});

// ── Helpers ────────────────────────────────────────────────────────────

function nowIso() {
  return new Date().toISOString();
}

function readEnv(key, fallback) {
  const v = process.env[key];
  return v && v.length > 0 ? v : fallback;
}

// Parse `toolCall.arguments` defensively. The OpenAI SDK serializes them
// as a JSON string; some custom tool implementations pass them through
// already-parsed. Fail-closed: if we can't parse, return null and let
// the policy match against {} (which fails any specific clause).
//
// v1.4 F-32 — cap the input bytes before JSON.parse. Beyond the cap
// the input is truncated with a sentinel and a parsed shape that
// preserves the field structure as much as possible (try-parse the
// truncated text, fall back to `{ _wmaTruncated: true, original_bytes }`).
// Policies that match on tool_name still work; policies that match on
// argument values silently miss the truncated suffix — which is the
// correct fail-closed behavior for an oversize input.
function safeParseToolArgs(rawArgs, maxBytes = DEFAULT_MAX_ARG_BYTES) {
  if (rawArgs == null) return null;
  if (typeof rawArgs === 'object') {
    // Already parsed by the SDK or the customer. We don't deep-walk
    // and truncate — that would silently change policy match semantics
    // on nested fields. Defer the decision to the caller; the size cap
    // applies at the string-parse boundary, which is the realistic
    // SDK entry point.
    return rawArgs;
  }
  if (typeof rawArgs !== 'string') return null;
  // Byte cap: Buffer.byteLength is the safe length on the wire.
  const byteLen = Buffer.byteLength(rawArgs, 'utf8');
  if (byteLen > maxBytes) {
    // Truncate to maxBytes worth of bytes (substring is char-bounded;
    // good enough — exact byte truncation isn't required since we mark
    // the result as truncated and never feed it back to a real tool).
    const head = rawArgs.slice(0, maxBytes);
    try {
      const parsed = JSON.parse(head);
      // If by luck the head is valid JSON, return it plus the marker.
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return { ...parsed, _wmaTruncated: true, _wmaOriginalBytes: byteLen };
      }
      return { _wmaTruncated: true, _wmaOriginalBytes: byteLen, head: parsed };
    } catch {
      // Common path: truncated JSON is invalid mid-tree.
      return { _wmaTruncated: true, _wmaOriginalBytes: byteLen };
    }
  }
  try { return JSON.parse(rawArgs); }
  catch { return null; }
}

// Stable session id per run. The OpenAI SDK doesn't give us a top-level
// run identifier we can rely on across all event types (run-state-machine
// internals), so we mint our own UUID at first event and keep it.
function makeSessionId() {
  return `oai-${randomUUID()}`;
}

// v1.4 F-31 — short reference code minted per Shield internal error.
// Returned to the model as `Ref: WMA-SHL-<8hex>` and logged to stderr
// alongside the full err.message so an operator can correlate the
// generic model-facing message to the local detailed log without
// leaking the raw error to the model.
function makeErrorRef() {
  // 8 hex chars from a fresh UUID — wide enough to deconflict within
  // a session, short enough to be readable in a tool result.
  return `WMA-SHL-${randomUUID().replace(/-/g, '').slice(0, 8)}`;
}

// Derive a stable, monotonic event id from the SDK's tool_call id when
// present (so deduplication after restart works), else mint a UUID.
function makeEventId(toolCall) {
  if (toolCall && typeof toolCall === 'object') {
    const id = toolCall.callId || toolCall.id;
    if (typeof id === 'string' && id.length > 0) return `oai-${id}`;
  }
  return `oai-evt-${randomUUID()}`;
}

// Hash a customer-provided tool name for use as a stable agent_id when
// the SDK's `agent.name` field is missing or empty. Salt is intentionally
// fixed (no anti-collision goal — this is just a stable derivation).
function fallbackAgentId(toolName) {
  const h = createHash('sha256').update(String(toolName || 'unknown')).digest('hex');
  return `oai-agent-${h.slice(0, 16)}`;
}

// ── Team correlation ───────────────────────────────────────────────────
//
// A "team" is a stable id shared by every event in a related group of
// cooperating agents. Three resolution channels, highest precedence first:
//   1. Customer override: WMA_TEAM_ID env var.
//   2. Auto-detected: when the SDK emits `agent_handoff(from, to)`, the
//      from-agent's existing team_id propagates to the to-agent. The
//      first agent in a run gets a freshly-minted team_id (run-scoped).
//   3. Null: customer didn't opt into team correlation, no handoff
//      observed — events are tagged team_id=null. Legions UI shows them
//      under the "Untagged" bucket.

function teamIdFromEnv() {
  const v = readEnv('WMA_TEAM_ID', null);
  return v && v.length > 0 ? v : null;
}

// Per-run team tracker. Keyed by sessionId so multiple concurrent runs
// don't cross-pollinate.
function createTeamTracker(envTeamId) {
  // Map<sessionId, teamId>
  const teams = new Map();
  return {
    // Resolve the team_id for this event. If the customer set
    // WMA_TEAM_ID, that always wins. Otherwise we look up the
    // sessionId-keyed map (populated by recordHandoff() + first-event
    // bootstrap). Returns null if no info available.
    resolve(sessionId) {
      if (envTeamId) return envTeamId;
      return teams.get(sessionId) || null;
    },
    // First event in a run — establish a team_id. Subsequent events in
    // the same session inherit it.
    bootstrap(sessionId) {
      if (envTeamId) return envTeamId;
      let t = teams.get(sessionId);
      if (!t) {
        t = `oai-team-${randomUUID()}`;
        teams.set(sessionId, t);
      }
      return t;
    },
    // SDK emitted agent_handoff(from, to) — propagate the from-agent's
    // team to the to-agent. In Agents SDK both agents are within the
    // same run / sessionId, so this is mostly a no-op in our model.
    // We keep the hook for future fan-out scenarios.
    recordHandoff(_fromAgent, _toAgent, sessionId) {
      if (envTeamId) return envTeamId;
      return teams.get(sessionId) || null;
    },
  };
}

// ── Event normalization ────────────────────────────────────────────────
//
// Five event types from @openai/agents map to WMA contract action_types:
//
//   agent_start       → MESSAGE (with action_type override = 'agent_start')
//   agent_end         → MESSAGE (with action_type override = 'agent_end')
//   agent_handoff     → HANDOFF
//   agent_tool_start  → CUSTOM_TOOL_USE  (the tool fires NEXT — capture
//                                         input, no output yet)
//   agent_tool_end    → CUSTOM_TOOL_RESULT (capture output, link by
//                                           tool_call_id to the start)
//
// Notes:
//   - We pick CUSTOM_TOOL_USE over plain TOOL_USE: OpenAI Agents SDK
//     tools are ALWAYS customer-defined (no provider-built-in shell
//     equivalent at this surface). TOOL_USE stays reserved for provider-
//     built-ins (Anthropic web_search, AgentCore Browser Tool, etc.).
//   - agent_start / agent_end aren't in ACTION_TYPES today. We map them
//     to MESSAGE so the contract validator stays green. The action_type
//     override goes in the `output` envelope so consumers can still
//     filter. A first-class agent lifecycle action_type may be proposed
//     in v1.4.x.

export function normalizeAgentStart({ agent, turnInput, sessionId, teamId }) {
  return Object.freeze({
    id: `oai-evt-${randomUUID()}`,
    provider: PROVIDER,
    agent_id: agent?.name || fallbackAgentId('start'),
    agent_name: agent?.name || null,
    session_id: sessionId,
    session_thread_id: sessionId,
    action_type: ACTION_TYPES.MESSAGE,
    timestamp: nowIso(),
    status: STATUS_VALUES.OK,
    tool_name: null,
    model: agent?.model || null,
    duration_ms: null,
    parent_agent_id: null,
    composition_pattern: COMPOSITION_PATTERNS.SOLO,
    team_id: teamId,
    input: turnInput ? { turn_input: turnInput } : null,
    output: { kind: 'agent_start' },
  });
}

export function normalizeAgentEnd({ agent, output, sessionId, teamId }) {
  return Object.freeze({
    id: `oai-evt-${randomUUID()}`,
    provider: PROVIDER,
    agent_id: agent?.name || fallbackAgentId('end'),
    agent_name: agent?.name || null,
    session_id: sessionId,
    session_thread_id: sessionId,
    action_type: ACTION_TYPES.MESSAGE,
    timestamp: nowIso(),
    status: STATUS_VALUES.OK,
    tool_name: null,
    model: agent?.model || null,
    duration_ms: null,
    parent_agent_id: null,
    composition_pattern: COMPOSITION_PATTERNS.SOLO,
    team_id: teamId,
    input: null,
    output: { kind: 'agent_end', text: typeof output === 'string' ? output : null },
  });
}

export function normalizeAgentHandoff({ fromAgent, toAgent, sessionId, teamId }) {
  return Object.freeze({
    id: `oai-evt-${randomUUID()}`,
    provider: PROVIDER,
    agent_id: toAgent?.name || fallbackAgentId('handoff'),
    agent_name: toAgent?.name || null,
    session_id: sessionId,
    session_thread_id: sessionId,
    action_type: ACTION_TYPES.HANDOFF,
    timestamp: nowIso(),
    status: STATUS_VALUES.OK,
    tool_name: null,
    model: toAgent?.model || null,
    duration_ms: null,
    parent_agent_id: fromAgent?.name || null,
    composition_pattern: COMPOSITION_PATTERNS.HIERARCHY,
    team_id: teamId,
    input: null,
    output: {
      kind: 'agent_handoff',
      from: fromAgent?.name || null,
      to: toAgent?.name || null,
    },
  });
}

export function normalizeToolStart({ agent, tool, toolCall, sessionId, teamId, toolInputs }) {
  const parsedArgs = safeParseToolArgs(toolCall?.arguments);
  // v1.4 Codex #4 — per-tool argument aliases. If `toolInputs` is
  // provided AND has an entry for this tool's name, apply the alias
  // map via normalizeToolInput() from the anonymizer. The result
  // populates canonical names (`url`, `query`, `command`, `path`,
  // `file_path`) so the SignalsAggregator hashes them EXACTLY, not
  // via the F-30 suffix heuristic (which is the opt-out safety net,
  // not the precision path). Both layers coexist: explicit aliases
  // win on declared fields; heuristic catches the long tail.
  const aliases = toolInputs && tool?.name ? toolInputs[tool.name] : null;
  const finalInput = aliases ? normalizeToolInput(parsedArgs, aliases) : parsedArgs;
  return Object.freeze({
    id: makeEventId(toolCall),
    provider: PROVIDER,
    agent_id: agent?.name || fallbackAgentId(tool?.name),
    agent_name: agent?.name || null,
    session_id: sessionId,
    session_thread_id: sessionId,
    action_type: ACTION_TYPES.CUSTOM_TOOL_USE,
    timestamp: nowIso(),
    status: STATUS_VALUES.OK,
    tool_name: tool?.name || null,
    model: agent?.model || null,
    duration_ms: null,
    parent_agent_id: null,
    composition_pattern: COMPOSITION_PATTERNS.SOLO,
    team_id: teamId,
    input: finalInput,
    output: null,
  });
}

// v1.4 F-32 — cap result bytes before writing NDJSON. Verbose tools
// (HTML scrapers, web_fetch with full-page payloads, computer use
// screenshots base64'd) can return arbitrary megabytes. Without a cap
// we'd write a single ~MB-sized JSON line per call into the rotation
// file, fill the disk, and slow every subsequent NDJSON read.
function truncateResult(result, maxBytes = DEFAULT_MAX_RESULT_BYTES) {
  if (typeof result === 'string') {
    const byteLen = Buffer.byteLength(result, 'utf8');
    if (byteLen > maxBytes) {
      return {
        text: result.slice(0, maxBytes) + TRUNCATION_SENTINEL,
        _wmaTruncated: true,
        _wmaOriginalBytes: byteLen,
      };
    }
    return { text: result };
  }
  if (result == null) return { value: null };
  // Object / array result: serialize, check size, truncate if needed.
  try {
    const serialized = JSON.stringify(result);
    const byteLen = Buffer.byteLength(serialized, 'utf8');
    if (byteLen > maxBytes) {
      return {
        value: { _wmaTruncated: true, _wmaOriginalBytes: byteLen },
      };
    }
    return { value: result };
  } catch {
    return { value: { _wmaTruncated: true, _wmaUnserializable: true } };
  }
}

export function normalizeToolEnd({ agent, tool, result, toolCall, sessionId, teamId }) {
  return Object.freeze({
    id: `${makeEventId(toolCall)}-end`,
    provider: PROVIDER,
    agent_id: agent?.name || fallbackAgentId(tool?.name),
    agent_name: agent?.name || null,
    session_id: sessionId,
    session_thread_id: sessionId,
    action_type: ACTION_TYPES.CUSTOM_TOOL_RESULT,
    timestamp: nowIso(),
    status: STATUS_VALUES.OK,
    tool_name: tool?.name || null,
    model: agent?.model || null,
    duration_ms: null,
    parent_agent_id: null,
    composition_pattern: COMPOSITION_PATTERNS.SOLO,
    team_id: teamId,
    input: null,
    output: truncateResult(result),
  });
}

// ── Public API: Shield (Tool Input Guardrail) ──────────────────────────
//
// Returns a guardrail object SHAPE-COMPATIBLE with the @openai/agents
// `defineToolInputGuardrail()` output. Customer drops it into an Agent's
// `toolInputGuardrails: [...]` and the SDK runs it before every tool
// call.
//
// Options:
//   policiesPath:    string  — local JSON policy file path
//   ruleset:         object  — in-memory policy ruleset (overrides path)
//   logDir:          string  — NDJSON log dir (default: WMA_LOG_DIR or
//                              ./watchmyagents-logs)
//   sessionId:       string  — override session id (default: auto-minted)
//   recentWindowSize:number — context tracker window (default: 20)
//   failOpen:        boolean — on Shield internal error, allow vs deny
//                              (default: false = fail-CLOSED)
//   getTeamId:       fn()→string|null — custom team resolver
//   logger:          Logger  — inject an existing Logger (testing)
//   decisionLogger:  DecisionLogger — inject existing (testing)
//   tracker:         ContextTracker — inject existing (testing)
//
// All options are optional; defaults read from env. Lazy loading of the
// policy ruleset on first invocation if `policiesPath` is set.

export function wmaToolInputGuardrail(options = {}) {
  const failOpen = options.failOpen === true ? true : DEFAULT_FAIL_OPEN;
  const sessionId = options.sessionId || makeSessionId();
  const logDir = options.logDir
    || readEnv('WMA_LOG_DIR', './watchmyagents-logs');

  // Set up the shared shield state. Re-used across all tool calls
  // through this guardrail instance.
  let ruleset = options.ruleset || null;
  const tracker = options.tracker
    || createContextTracker({ recentWindowSize: options.recentWindowSize ?? 20 });
  // v1.3.1 F-29 (P1 Codex audit): provider must be passed explicitly so
  // shield_decision NDJSON rows carry 'openai-agents' instead of being
  // mis-attributed to 'anthropic-managed' (DecisionLogger's pre-v1.3.1
  // hardcoded default). Fortress / Guardian forensic surfaces depend on
  // this for correct multi-provider attribution.
  const decisionLogger = options.decisionLogger
    || new DecisionLogger({ logDir, agentId: 'openai-agents', sessionId, provider: PROVIDER });
  const logger = options.logger
    || new Logger({ logDir, agentId: 'openai-agents', sessionId, silent: true, bestEffort: false });

  // Team tracker — re-used for the entire run of this guardrail.
  const envTeamId = teamIdFromEnv();
  const teamTracker = createTeamTracker(envTeamId);

  const getTeamId = typeof options.getTeamId === 'function'
    ? options.getTeamId
    : () => teamTracker.bootstrap(sessionId);

  // Lazily load the ruleset on first invocation if a path was given.
  async function ensureRuleset() {
    if (ruleset != null) return ruleset;
    if (options.policiesPath) {
      ruleset = await loadPolicies(options.policiesPath);
      return ruleset;
    }
    // No ruleset, no path → default to "always allow". The customer
    // probably means to use Fortress; we don't ship that wiring in
    // v1.3.0 from this entry point. Log a warning once.
    if (!ensureRuleset._warned) {
      ensureRuleset._warned = true;
      process.stderr.write(
        '[wma/openai-agents] no policy ruleset configured — guardrail will allow all. ' +
        'Pass { policiesPath } or { ruleset } to wmaToolInputGuardrail() to enforce.\n',
      );
    }
    ruleset = { policies: [], default: { action: 'allow' } };
    return ruleset;
  }

  return {
    type: 'tool_input',
    name: 'watchmyagents-shield',
    run: async (data) => {
      // Defensive: data may be { context, agent, toolCall }.
      const agent = data?.agent || null;
      const toolCall = data?.toolCall || null;

      try {
        const rs = await ensureRuleset();

        // 1. Normalize the about-to-fire tool_use event.
        const event = normalizeToolStart({
          agent,
          tool: { name: toolCall?.name },
          toolCall,
          sessionId,
          teamId: getTeamId(),
          // v1.4 Codex #4 — per-tool alias map (option `toolInputs`).
          // Threaded through so the anonymizer hashes by canonical name
          // for tools the customer explicitly mapped.
          toolInputs: options.toolInputs,
        });

        // 2. Compute policy context BEFORE evaluation so recent_error_rate
        //    and friends reflect prior history.
        const policyCtx = tracker.compute(event);

        // 3. Evaluate Shield.
        const t0 = Date.now();
        const result = evaluate(event, rs, policyCtx);
        const decidedInMs = Date.now() - t0;

        // 4. Audit-grade log (chain-signed).
        await decisionLogger.record({
          sourceEvent: { id: event.id, type: event.action_type, tool_name: event.tool_name, input: event.input },
          decision: result.decision,
          ruleId: result.rule_id,
          ruleName: result.rule_name,
          message: result.message,
          decidedInMs,
          mode: result.mode,
        });

        // 5. Watch log (the event itself, separate from the decision).
        await logger.write(event);

        // 6. Record outcome into the context tracker for the next event.
        //    On a Shield block, the tool won't run — that's NOT a tool
        //    error from the agent's perspective. Use the default
        //    heuristic which won't mark allow/deny as errors.
        tracker.record(event);

        // 7. Translate Shield decision into OpenAI guardrail behavior.
        //    Shadow mode never blocks — log + allow.
        if (result.mode === 'shadow') {
          return ToolGuardrailFunctionOutputFactory.allow({
            wma: { rule_id: result.rule_id, mode: 'shadow', shadow_decision: result.decision },
          });
        }
        if (result.decision === 'deny') {
          return ToolGuardrailFunctionOutputFactory.rejectContent(
            result.message || `Blocked by ${result.rule_name || 'WMA Shield'}`,
            { wma: { rule_id: result.rule_id, rule_name: result.rule_name } },
          );
        }
        if (result.decision === 'interrupt') {
          return ToolGuardrailFunctionOutputFactory.throwException({
            wma: { rule_id: result.rule_id, rule_name: result.rule_name, message: result.message },
          });
        }
        return ToolGuardrailFunctionOutputFactory.allow({
          wma: { rule_id: null, rule_name: '(default-allow)' },
        });
      } catch (err) {
        // Shield internal failure (policy file unreadable, disk full on
        // log write, etc.). Default fail-CLOSED unless customer opted
        // into fail-OPEN.
        //
        // v1.4 F-31 (P2 Codex audit on v1.3.0): the agent must NOT see
        // the raw err.message — it can carry local paths, policy file
        // names, disk-mount strings, permission codes, or even fragments
        // of the policy itself that should never reach a model context.
        // We mint a short reference code, log the full error locally to
        // stderr keyed by that code, and return a generic message that
        // operators can correlate against the local log without exposing
        // anything actionable to the model. The outputInfo (which is NOT
        // surfaced to the model — it stays in the application's run
        // metadata) keeps the err.message for SDK-side tracing.
        const errorRef = makeErrorRef();
        process.stderr.write(
          `[wma/openai-agents] [${errorRef}] guardrail error: ${err.message}\n`,
        );
        if (failOpen) {
          return ToolGuardrailFunctionOutputFactory.allow({
            wma: {
              errorRef,
              error: err.message,
              failOpenApplied: true,
            },
          });
        }
        return ToolGuardrailFunctionOutputFactory.rejectContent(
          `WMA Shield internal error (fail-closed). Ref: ${errorRef}`,
          {
            wma: {
              errorRef,
              error: err.message,
              failOpenApplied: false,
            },
          },
        );
      }
    },
  };
}

// ── Public API: Watch (RunHooks listener attach) ───────────────────────
//
// Attaches WMA listeners to a Runner (or any EventEmitter-shaped object
// with `.on(event, listener)`). Captures all 5 lifecycle events,
// normalizes each, and writes to local NDJSON. Returns an unsubscribe
// function the customer can call on cleanup.
//
// Why a separate function from the guardrail:
//   The guardrail is OPTIONAL (customer might want Watch-only — pure
//   observability with no enforcement). The Watch attach is the
//   complementary opt-in. Both are independent.

export function attachWmaWatch(runner, options = {}) {
  if (!runner || typeof runner.on !== 'function') {
    throw new TypeError(
      'attachWmaWatch: runner must expose an .on(event, listener) method ' +
      '(the @openai/agents Runner EventEmitter, or a compatible shim).',
    );
  }

  const sessionId = options.sessionId || makeSessionId();
  const logDir = options.logDir
    || readEnv('WMA_LOG_DIR', './watchmyagents-logs');
  const logger = options.logger
    || new Logger({ logDir, agentId: 'openai-agents', sessionId, silent: true, bestEffort: true });

  const envTeamId = teamIdFromEnv();
  const teamTracker = options.teamTracker || createTeamTracker(envTeamId);

  // Per-event handlers. Each one normalizes then writes. We wrap each in
  // try/catch — Watch must NEVER throw inside the customer's Runner
  // event loop. Watch is observation; observation must be best-effort.
  const handlers = {
    agent_start: async (context, agent, turnInput) => {
      try {
        const teamId = teamTracker.bootstrap(sessionId);
        const event = normalizeAgentStart({ agent, turnInput, sessionId, teamId });
        await logger.write(event);
      } catch (e) {
        process.stderr.write(`[wma/openai-agents] watch agent_start error: ${e.message}\n`);
      }
    },
    agent_end: async (context, agent, output) => {
      try {
        const teamId = teamTracker.resolve(sessionId);
        const event = normalizeAgentEnd({ agent, output, sessionId, teamId });
        await logger.write(event);
      } catch (e) {
        process.stderr.write(`[wma/openai-agents] watch agent_end error: ${e.message}\n`);
      }
    },
    agent_handoff: async (context, fromAgent, toAgent) => {
      try {
        const teamId = teamTracker.recordHandoff(fromAgent, toAgent, sessionId)
          || teamTracker.bootstrap(sessionId);
        const event = normalizeAgentHandoff({ fromAgent, toAgent, sessionId, teamId });
        await logger.write(event);
      } catch (e) {
        process.stderr.write(`[wma/openai-agents] watch agent_handoff error: ${e.message}\n`);
      }
    },
    agent_tool_start: async (context, agent, tool, details) => {
      try {
        const teamId = teamTracker.resolve(sessionId) || teamTracker.bootstrap(sessionId);
        const event = normalizeToolStart({
          agent, tool, toolCall: details?.toolCall, sessionId, teamId,
          toolInputs: options.toolInputs,  // v1.4 Codex #4
        });
        await logger.write(event);
      } catch (e) {
        process.stderr.write(`[wma/openai-agents] watch agent_tool_start error: ${e.message}\n`);
      }
    },
    agent_tool_end: async (context, agent, tool, result, details) => {
      try {
        const teamId = teamTracker.resolve(sessionId) || teamTracker.bootstrap(sessionId);
        const event = normalizeToolEnd({
          agent, tool, result, toolCall: details?.toolCall, sessionId, teamId,
        });
        await logger.write(event);
      } catch (e) {
        process.stderr.write(`[wma/openai-agents] watch agent_tool_end error: ${e.message}\n`);
      }
    },
  };

  for (const [evt, fn] of Object.entries(handlers)) {
    runner.on(evt, fn);
  }

  // Unsubscribe helper. If `runner.off` exists (standard EventEmitter),
  // detach. Otherwise no-op. Customer should call this on shutdown.
  return function detachWmaWatch() {
    if (typeof runner.off !== 'function') return;
    for (const [evt, fn] of Object.entries(handlers)) {
      try { runner.off(evt, fn); }
      catch { /* listener wasn't attached or off() not supported */ }
    }
  };
}

// ── Public API: Watch via AgentHooks (when customer uses run() helper) ─
//
// The @openai/agents SDK exposes TWO event-emitter surfaces:
//   - RunHooks  : `runner.on(event, listener)` — fires when customer
//                 explicitly creates a Runner via `new Runner()`.
//                 Listener args INCLUDE the agent.
//   - AgentHooks: `agent.on(event, listener)`  — fires when customer
//                 uses the convenience `run(agent, ...)` function
//                 (without an explicit Runner). The agent is implicit
//                 (it's the one we registered listeners on), so the
//                 listener args do NOT include it (except agent_start).
//
// Real-world capture (June 2026) shows AgentHooks signatures:
//   agent_start      [context, agent, turnInput?]
//   agent_end        [context, output]            ← no agent
//   agent_handoff    [context, toAgent]           ← only the "to" side
//   agent_tool_start [context, tool, details]    ← no agent
//   agent_tool_end   [context, tool, result, details] ← no agent
//
// `attachWmaWatchToAgent(agent, options)` mirrors `attachWmaWatch`
// for the AgentHooks pattern. The agent is captured via closure so
// our normalizers still receive an agent_id even for events that
// don't pass the agent in their args.
//
// Returns a `detach()` function symmetric to attachWmaWatch.

export function attachWmaWatchToAgent(agent, options = {}) {
  if (!agent || typeof agent.on !== 'function') {
    throw new TypeError(
      'attachWmaWatchToAgent: agent must expose an .on(event, listener) method ' +
      '(the @openai/agents Agent EventEmitter, or a compatible shim).',
    );
  }

  const sessionId = options.sessionId || makeSessionId();
  const logDir = options.logDir
    || readEnv('WMA_LOG_DIR', './watchmyagents-logs');
  const logger = options.logger
    || new Logger({ logDir, agentId: 'openai-agents', sessionId, silent: true, bestEffort: true });

  const envTeamId = teamIdFromEnv();
  const teamTracker = options.teamTracker || createTeamTracker(envTeamId);

  // Same try/catch wrapping discipline as attachWmaWatch: Watch must
  // NEVER throw inside the customer's agent loop. Handlers below absorb
  // exceptions and write them to stderr instead of propagating.
  const handlers = {
    agent_start: async (context, eventAgent, turnInput) => {
      try {
        const teamId = teamTracker.bootstrap(sessionId);
        const event = normalizeAgentStart({
          agent: eventAgent || agent,
          turnInput, sessionId, teamId,
        });
        await logger.write(event);
      } catch (e) {
        process.stderr.write(`[wma/openai-agents] watch agent_start error: ${e.message}\n`);
      }
    },
    // AgentHooks agent_end does NOT pass the agent — captured via closure.
    agent_end: async (context, output) => {
      try {
        const teamId = teamTracker.resolve(sessionId);
        const event = normalizeAgentEnd({ agent, output, sessionId, teamId });
        await logger.write(event);
      } catch (e) {
        process.stderr.write(`[wma/openai-agents] watch agent_end error: ${e.message}\n`);
      }
    },
    // AgentHooks agent_handoff passes only the "to" agent. The "from"
    // is the agent we registered on (this listener is fired right
    // before control passes away from it).
    agent_handoff: async (context, toAgent) => {
      try {
        const teamId = teamTracker.recordHandoff(agent, toAgent, sessionId)
          || teamTracker.bootstrap(sessionId);
        const event = normalizeAgentHandoff({
          fromAgent: agent, toAgent, sessionId, teamId,
        });
        await logger.write(event);
      } catch (e) {
        process.stderr.write(`[wma/openai-agents] watch agent_handoff error: ${e.message}\n`);
      }
    },
    // AgentHooks tool events do NOT pass the agent — captured via closure.
    agent_tool_start: async (context, tool, details) => {
      try {
        const teamId = teamTracker.resolve(sessionId) || teamTracker.bootstrap(sessionId);
        const event = normalizeToolStart({
          agent, tool, toolCall: details?.toolCall, sessionId, teamId,
          toolInputs: options.toolInputs,  // v1.4 Codex #4
        });
        await logger.write(event);
      } catch (e) {
        process.stderr.write(`[wma/openai-agents] watch agent_tool_start error: ${e.message}\n`);
      }
    },
    agent_tool_end: async (context, tool, result, details) => {
      try {
        const teamId = teamTracker.resolve(sessionId) || teamTracker.bootstrap(sessionId);
        const event = normalizeToolEnd({
          agent, tool, result, toolCall: details?.toolCall, sessionId, teamId,
        });
        await logger.write(event);
      } catch (e) {
        process.stderr.write(`[wma/openai-agents] watch agent_tool_end error: ${e.message}\n`);
      }
    },
  };

  for (const [evt, fn] of Object.entries(handlers)) {
    agent.on(evt, fn);
  }

  return function detachWmaWatchFromAgent() {
    if (typeof agent.off !== 'function') return;
    for (const [evt, fn] of Object.entries(handlers)) {
      try { agent.off(evt, fn); }
      catch { /* listener wasn't attached or off() not supported */ }
    }
  };
}

// ── Enforcement metadata (for adapter registry / introspection) ───────

export const adapterMeta = Object.freeze({
  provider: PROVIDER,
  displayName: 'OpenAI Agents SDK',
  enforcement: ENFORCEMENT_MODES.SYNC_CONFIRM,
  compositionDefault: COMPOSITION_PATTERNS.SOLO,
  customerInstrumented: true,                // not auto-discovery
  peerPackage: '@openai/agents',
  // v1.4 F-33 — aligned with package.json#peerDependencies range
  // `^0.2.0`. Real fixtures captured against 0.2.x verified the
  // lifecycle event signatures in v1.3.0; minPeerVersion below that is
  // unsupported and may show drift in args layout (the AgentHooks vs
  // RunHooks gap that motivated the v1.3.0 finalize commit).
  minPeerVersion: '0.2.0',
  capabilities: Object.freeze({
    watch: true,
    shield: true,
    preToolDeny: true,                        // via ToolInputGuardrail
    postToolFilter: false,                    // ToolOutputGuardrail later
    teamIdAutoDetect: true,                   // via agent_handoff
    streamingSupported: 'verify-day-2',       // verify in smoke test
  }),
});

// Internal-only — exported for tests. The factory mirrors @openai/agents'
// public symbol; tests can assert against it.
export const __testing__ = Object.freeze({
  ToolGuardrailFunctionOutputFactory,
  safeParseToolArgs,
  makeSessionId,
  makeEventId,
  fallbackAgentId,
  createTeamTracker,
});
