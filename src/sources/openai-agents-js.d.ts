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
 * Usage:
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
 */
export function attachWmaWatch(
  runner: WMARunnerLike,
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
