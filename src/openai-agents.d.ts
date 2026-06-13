// Type declarations for the stable entry point `watchmyagents/openai-agents`.
//
// The runtime is src/openai-agents.js (the openaiAgents() factory + the
// re-exported low-level escape hatches). v1.4.8 (P2 quality): these types were
// previously pointed at the low-level module's .d.ts, which never declared
// openaiAgents() nor the v1.4.6/1.4.7 options (agentId, policies.source,
// uploadDecisions, signalsSalt) — TS users got a broken/incomplete typed API.

import type {
  WMAToolInputGuardrail,
  WMAGuardrailOptions,
  WMAAdapterMeta,
  WMARunnerLike,
  WMAAgentLike,
  WMAWatchOptions,
} from './sources/openai-agents-js';

// Re-export the low-level types + escape-hatch functions so TS users importing
// from 'watchmyagents/openai-agents' see the full surface the runtime exports.
export * from './sources/openai-agents-js';

/** Live policy source config. Today only Fortress is supported. */
export interface OpenaiAgentsPoliciesConfig {
  /** Pull the ruleset from Fortress (the same control plane wma-shield uses). */
  source: 'fortress';
  /** Fortress functions base URL. Defaults to WMA_FORTRESS_BASE_URL. */
  baseUrl?: string;
  /** WMA API key. Defaults to WMA_API_KEY. */
  apiKey?: string;
  /** Require Ed25519-signed policies (strict mode). */
  requireSignedPolicies?: boolean;
  /** Fail mode when a refresh yields no valid policies ('open' | 'closed'). */
  failMode?: 'open' | 'closed';
  /** Ship Shield decisions to the same Fortress's ingest-decisions.
   *  Default: true. Set false to keep decisions local-only (NDJSON). */
  uploadDecisions?: boolean;
}

/** Options for {@link openaiAgents}. */
export interface OpenaiAgentsOptions {
  /** 'enforce' (default) requires a policy source; 'observe' attaches Watch
   *  only and makes .shield() throw. */
  mode?: 'observe' | 'enforce';
  /** Agent id registered in Fortress — NDJSON path + native_agent_id, and
   *  scopes the Fortress policy pull. Required with policies.source='fortress'. */
  agentId?: string;
  /** Live policy source (Fortress). Mutually complete with policiesPath/ruleset. */
  policies?: OpenaiAgentsPoliciesConfig;
  /** Local JSON policy file. */
  policiesPath?: string;
  /** In-memory ruleset (overrides policiesPath). */
  ruleset?: { policies: unknown[]; default?: { action: string } };
  /** NDJSON log dir. Defaults to WMA_LOG_DIR or ./watchmyagents-logs. */
  logDir?: string;
  /** Override the session id (default: auto-minted). */
  sessionId?: string;
  /** Salt for hashing session/input in the Fortress decision payload.
   *  Defaults to WMA_SIGNALS_SALT. */
  signalsSalt?: string;
  /** On Shield internal error, allow vs deny. Default: false (fail-CLOSED). */
  failOpen?: boolean;
  /** Trailing window for ctx.recent_error_rate etc. Default: 20. */
  recentWindowSize?: number;
  /** Custom team id resolver. */
  getTeamId?: () => string | null;
  /** Per-tool argument aliases ({ tool: { nativeField: canonical } }). */
  toolInputs?: Record<string, Record<string, string>>;
  /** Byte caps on captured tool args / results. Default 256 KB. */
  maxArgBytes?: number;
  maxResultBytes?: number;
  /** Cap on concurrent in-flight decision uploads (excess dropped best-effort,
   *  NDJSON stays durable). Default: 32. */
  maxDecisionUploadsInFlight?: number;
  /** Inject for testing. */
  tracker?: unknown;
  logger?: unknown;
  decisionLogger?: unknown;
}

/** The object returned by {@link openaiAgents}. */
export interface OpenaiAgentsHandle {
  /** The @openai/agents Tool Input Guardrail (Shield). Throws in observe mode. */
  shield(): WMAToolInputGuardrail;
  /** Attach Watch — auto-detects Runner vs Agent. Returns a detach function. */
  watch(target: WMARunnerLike | WMAAgentLike): () => void;
  /** Adapter metadata. */
  readonly meta: WMAAdapterMeta;
  /** The configured mode. */
  readonly mode: 'observe' | 'enforce';
}

/**
 * Build the WMA OpenAI Agents SDK adapter from one shared config.
 *
 * ```typescript
 * import { openaiAgents } from 'watchmyagents/openai-agents';
 * import { Agent, run } from '@openai/agents';
 *
 * const wma = openaiAgents({
 *   mode: 'enforce',
 *   agentId: 'support_bot',
 *   policies: { source: 'fortress' },   // WMA_API_KEY + WMA_FORTRESS_BASE_URL from env
 * });
 *
 * const agent = new Agent({ name: 'support_bot', tools, toolInputGuardrails: [wma.shield()] });
 * wma.watch(agent);
 * await run(agent, 'help me');
 * ```
 */
export function openaiAgents(options?: OpenaiAgentsOptions): OpenaiAgentsHandle;
