// TypeScript types for the OpenAI Agents SDK adapter — v1.3.0.
//
// These types pin the PUBLIC surface customers consume. The runtime
// (openai-agents-js.js) is plain JS to preserve the zero-runtime-deps
// invariant; this .d.ts is consumed by tsc only and never executed.
//
// The guardrail return shape and the EventEmitter event signatures
// mirror @openai/agents v0.x — we don't import from it (also to avoid
// dragging it as a runtime dep here), we re-declare the minimal subset
// we need.

// ── @openai/agents shapes we reference (minimal re-declaration) ────────

/** Mirrors @openai/agents `ToolGuardrailBehavior`. */
export type WMAToolGuardrailBehavior =
  | { type: 'allow' }
  | { type: 'rejectContent'; message: string }
  | { type: 'throwException' };

/** Mirrors @openai/agents `ToolGuardrailFunctionOutput`. */
export interface WMAToolGuardrailFunctionOutput {
  behavior: WMAToolGuardrailBehavior;
  outputInfo?: unknown;
}

/** Mirrors @openai/agents `ToolInputGuardrailData`. */
export interface WMAToolInputGuardrailData {
  context?: unknown;
  agent?: { name?: string; model?: string; instructions?: string };
  toolCall?: {
    id?: string;
    callId?: string;
    name?: string;
    arguments?: string | object;
  };
}

/**
 * Return value of {@link wmaToolInputGuardrail}. Shape-compatible with
 * @openai/agents `ToolInputGuardrailDefinition`. Drop into an Agent's
 * `toolInputGuardrails: [...]` array.
 */
export interface WMAToolInputGuardrail {
  readonly type: 'tool_input';
  readonly name: string;
  run: (data: WMAToolInputGuardrailData) => Promise<WMAToolGuardrailFunctionOutput>;
}

// ── Adapter-specific types ─────────────────────────────────────────────

/** Minimal Logger surface — for advanced injection in tests. */
export interface WMALogger {
  write(event: unknown): Promise<unknown>;
}

/** Minimal DecisionLogger surface. */
export interface WMADecisionLogger {
  record(args: {
    sourceEvent: unknown;
    decision: string;
    ruleId: string | null;
    ruleName: string | null;
    message: string | null;
    decidedInMs: number | null;
    mode: 'enforce' | 'shadow';
  }): Promise<unknown>;
}

/** Minimal ContextTracker surface. */
export interface WMAContextTracker {
  compute(event: unknown, at?: number): {
    hour_of_day_utc: number;
    day_of_week_utc: number;
    agent_age_minutes: number;
    session_duration_ms: number;
    recent_error_rate: number;
    event_count_recent: number;
    event_count_total: number;
  };
  record(event: unknown, opts?: { isError?: boolean }): void;
  reset(): void;
}

/** Minimal team tracker for handoff propagation. */
export interface WMATeamTracker {
  resolve(sessionId: string): string | null;
  bootstrap(sessionId: string): string;
  recordHandoff(fromAgent: unknown, toAgent: unknown, sessionId: string): string | null;
}

/** Options for {@link wmaToolInputGuardrail}. */
export interface WMAGuardrailOptions {
  /** Path to a local JSON policy file. Loaded lazily on first invocation. */
  policiesPath?: string;
  /** In-memory ruleset (overrides policiesPath). Useful for tests. */
  ruleset?: { policies: unknown[]; default?: { action: string } };
  /** Directory for NDJSON logs. Defaults to env WMA_LOG_DIR or ./watchmyagents-logs. */
  logDir?: string;
  /** Override the session id. Defaults to an auto-minted UUID. */
  sessionId?: string;
  /** Trailing window for `ctx.recent_error_rate` etc. Default: 20. */
  recentWindowSize?: number;
  /** On Shield internal error, allow vs deny. Default: false (fail-CLOSED). */
  failOpen?: boolean;
  /** Custom team id resolver — overrides env + handoff propagation. */
  getTeamId?: () => string | null;
  /** Inject an existing Logger (testing). */
  logger?: WMALogger;
  /** Inject an existing DecisionLogger (testing). */
  decisionLogger?: WMADecisionLogger;
  /** Inject an existing ContextTracker (testing). */
  tracker?: WMAContextTracker;
  /** v1.4.6 — agent id used for the NDJSON path segment + native_agent_id.
   *  Defaults to 'openai-agents' when un-named. */
  agentId?: string;
  /** v1.4.6 — a live policy source (e.g. FortressPolicySource). The guardrail
   *  single-flight-starts it then reads current() on every call. */
  fortressPolicySource?: {
    start(): Promise<void>;
    current(): { policies: unknown[]; default?: { action: string } };
  };
  /** v1.4.7 — best-effort sink the guardrail fires each decision to
   *  (fire-and-forget). Built by openaiAgents() from policies.source='fortress'. */
  fortressDecisionSink?: (payload: object) => unknown | Promise<unknown>;
  /** v1.4.7 — salt for hashing session/input in the Fortress decision payload
   *  (defaults to WMA_SIGNALS_SALT). Without it, those hashes are null. */
  signalsSalt?: string;
  /** v1.4.7 — cap on concurrent in-flight decision uploads; excess are dropped
   *  best-effort (NDJSON stays durable). Default: 32. */
  maxDecisionUploadsInFlight?: number;
  /** v1.4 Codex #4 — per-tool argument aliases ({ tool: { nativeField: canonical } }). */
  toolInputs?: Record<string, Record<string, string>>;
  /** v1.4 F-32 — byte caps on captured tool args / results. Default 256 KB. */
  maxArgBytes?: number;
  maxResultBytes?: number;
  /** v1.4.1 F-35 — explicit escape hatch to allow ALL tool calls when no policy
   *  source is configured (demos/smoke tests only). */
  allowAllWhenUnconfigured?: boolean;
}

/**
 * Build the WMA Shield as an @openai/agents Tool Input Guardrail.
 *
 * Usage:
 * ```typescript
 * import { Agent } from '@openai/agents';
 * import { wmaToolInputGuardrail } from 'watchmyagents';
 *
 * const wmaShield = wmaToolInputGuardrail({
 *   policiesPath: './policies/mitre-starter.json',
 * });
 *
 * const agent = new Agent({
 *   name: 'Support bot',
 *   instructions: '...',
 *   tools: [...],
 *   toolInputGuardrails: [wmaShield],
 * });
 * ```
 */
export function wmaToolInputGuardrail(options?: WMAGuardrailOptions): WMAToolInputGuardrail;

// ── Watch ──────────────────────────────────────────────────────────────

/** Minimal Runner surface (the part of @openai/agents we touch). */
export interface WMARunnerLike {
  on(event: string, listener: (...args: any[]) => void): unknown;
  off?(event: string, listener: (...args: any[]) => void): unknown;
}

/** Minimal Agent surface — same shape as Runner from an EventEmitter
 * perspective. The methods are identical; the difference is the listener
 * signatures (see attachWmaWatchToAgent). */
export interface WMAAgentLike {
  on(event: string, listener: (...args: any[]) => void): unknown;
  off?(event: string, listener: (...args: any[]) => void): unknown;
}

/** Options for {@link attachWmaWatch}. */
export interface WMAWatchOptions {
  logDir?: string;
  sessionId?: string;
  logger?: WMALogger;
  teamTracker?: WMATeamTracker;
}

/**
 * Attach WMA Watch listeners to an @openai/agents Runner. Returns a
 * detach function the customer can call on shutdown.
 *
 * USE THIS when the customer creates a Runner explicitly:
 * ```typescript
 * import { Runner } from '@openai/agents';
 * import { attachWmaWatch } from 'watchmyagents';
 *
 * const runner = new Runner();
 * const detach = attachWmaWatch(runner);
 *
 * await runner.run(agent, input);
 *
 * detach();  // optional, on process shutdown
 * ```
 *
 * If the customer uses the convenience `run(agent, ...)` function
 * (no explicit Runner), use {@link attachWmaWatchToAgent} instead.
 */
export function attachWmaWatch(
  runner: WMARunnerLike,
  options?: WMAWatchOptions,
): () => void;

/**
 * Attach WMA Watch listeners to an @openai/agents Agent (AgentHooks
 * pattern). Use this when the customer uses the convenience
 * `run(agent, ...)` function rather than creating an explicit Runner.
 *
 * The AgentHooks event signatures differ slightly from RunHooks:
 * agent_end, agent_handoff, agent_tool_start, agent_tool_end do NOT
 * pass the agent in their args — it's captured via closure here.
 *
 * Usage:
 * ```typescript
 * import { Agent, run } from '@openai/agents';
 * import { attachWmaWatchToAgent } from 'watchmyagents';
 *
 * const myAgent = new Agent({ name: 'support_bot', tools: [...] });
 * const detach = attachWmaWatchToAgent(myAgent);
 *
 * await run(myAgent, 'help me reset my password');
 *
 * detach();  // optional, on process shutdown
 * ```
 */
export function attachWmaWatchToAgent(
  agent: WMAAgentLike,
  options?: WMAWatchOptions,
): () => void;

// ── Normalizers (exported for advanced users / tests) ──────────────────

/** Mirrors the WMA contract `WMAAction` shape. */
export interface WMAAction {
  id: string;
  provider: string;
  agent_id: string;
  agent_name: string | null;
  session_id: string;
  session_thread_id: string | null;
  action_type: string;
  timestamp: string;
  status: 'ok' | 'error' | 'blocked';
  tool_name: string | null;
  model: string | null;
  duration_ms: number | null;
  parent_agent_id: string | null;
  composition_pattern: 'solo' | 'hierarchy' | 'graph' | 'peer';
  team_id: string | null;
  input: object | null;
  output: object | null;
}

export interface NormalizeArgs<T extends string> {
  sessionId: string;
  teamId: string | null;
  agent?: { name?: string; model?: string };
}

export function normalizeAgentStart(args: NormalizeArgs<'agent_start'> & { turnInput?: unknown[] }): Readonly<WMAAction>;
export function normalizeAgentEnd(args: NormalizeArgs<'agent_end'> & { output?: string }): Readonly<WMAAction>;
export function normalizeAgentHandoff(args: NormalizeArgs<'agent_handoff'> & {
  fromAgent?: { name?: string; model?: string };
  toAgent?: { name?: string; model?: string };
}): Readonly<WMAAction>;
export function normalizeToolStart(args: NormalizeArgs<'tool_start'> & {
  tool?: { name?: string };
  toolCall?: { id?: string; callId?: string; name?: string; arguments?: string | object };
}): Readonly<WMAAction>;
export function normalizeToolEnd(args: NormalizeArgs<'tool_end'> & {
  tool?: { name?: string };
  toolCall?: { id?: string; callId?: string; name?: string; arguments?: string | object };
  result?: unknown;
}): Readonly<WMAAction>;

// ── Adapter metadata ───────────────────────────────────────────────────

export interface WMAAdapterMeta {
  readonly provider: 'openai-agents';
  readonly displayName: string;
  readonly enforcement: 'sync_confirm' | 'sync_interrupt' | 'detect_only';
  readonly compositionDefault: 'solo' | 'hierarchy' | 'graph' | 'peer';
  readonly customerInstrumented: true;
  readonly peerPackage: '@openai/agents';
  readonly minPeerVersion: string;
  readonly capabilities: Readonly<{
    watch: boolean;
    shield: boolean;
    preToolDeny: boolean;
    postToolFilter: boolean;
    teamIdAutoDetect: boolean;
    streamingSupported: boolean | string;
  }>;
}

export const adapterMeta: WMAAdapterMeta;
