// Public entry point for the OpenAI Agents SDK adapter (v1.4 Codex #1).
//
// Customers import the SDK like this:
//
//   import { openaiAgents } from 'watchmyagents/openai-agents';
//
//   const wma = openaiAgents({
//     policiesPath: './policies.json',
//     logDir: './watchmyagents-logs',
//     mode: 'enforce',  // 'observe' | 'enforce' (default 'enforce')
//     toolInputs: {
//       fetch_url: { endpoint_url: 'url' },     // per-tool aliases
//       shell:     { shell_cmd: 'command' },
//     },
//   });
//
//   const agent = new Agent({
//     name: 'support_bot',
//     tools,
//     toolInputGuardrails: [wma.shield()],   // ← Shield
//   });
//
//   wma.watch(agent);   // ← Watch (auto-detects Agent vs Runner)
//   // or:
//   wma.watch(runner);
//
//   await run(agent, 'help me');
//
// Why a factory: it lets the customer configure once (policy path,
// log dir, mode, tool input aliases) and get back a small object with
// `shield()` and `watch()` methods that share that config. The pre-v1.4
// pattern asked customers to import deep paths (
// `watchmyagents/src/sources/openai-agents-js.js`) and pass options to
// each call — fragile and verbose. This entry point is the stable
// surface; the internal module stays free to refactor.

import {
  wmaToolInputGuardrail,
  attachWmaWatch,
  attachWmaWatchToAgent,
  adapterMeta,
} from './sources/openai-agents-js.js';
import { FortressPolicySource, postDecision } from './shield/sources/fortress.js';
import { resolveFortressBase } from './fortress/url.js';

/**
 * Build the WMA OpenAI Agents SDK adapter from a single shared config.
 *
 * @param {object} [options]
 * @param {string} [options.agentId]           v1.4.6 — the agent id registered
 *                                             in Fortress. Used as the NDJSON
 *                                             path segment + native_agent_id,
 *                                             and to scope the Fortress policy
 *                                             pull. Required with
 *                                             policies.source='fortress'.
 * @param {object} [options.policies]          v1.4.6 — live policy source.
 *   `{ source: 'fortress', baseUrl?, apiKey?, requireSignedPolicies?, failMode? }`
 *   pulls the ruleset from Fortress (apiKey defaults to WMA_API_KEY, baseUrl to
 *   WMA_FORTRESS_BASE_URL) and refreshes it in the background — the same control
 *   plane wma-shield uses for Anthropic.
 * @param {string} [options.policiesPath]      Local JSON policy file.
 * @param {object} [options.ruleset]           In-memory ruleset.
 * @param {string} [options.logDir]            NDJSON log dir.
 * @param {'observe'|'enforce'} [options.mode] v1.4 Codex #2 — explicit
 *                                             mode. `enforce` requires
 *                                             a policy source; `observe`
 *                                             attaches Watch only and
 *                                             refuses to issue a Shield
 *                                             (calling `.shield()` throws
 *                                             so it's impossible to ship
 *                                             a build that looks armed
 *                                             but isn't).
 * @param {object<string, object>} [options.toolInputs]
 *   v1.4 Codex #4 — per-tool argument aliases. Maps tool_name →
 *   { nativeFieldName: canonicalFieldName }. Applied alongside the
 *   F-30 heuristic so customers with off-canonical arg names get
 *   exact hashing without relying on the suffix heuristic.
 * @param {boolean} [options.failOpen]         Default false (closed).
 * @param {number} [options.maxArgBytes]       Default 256 KB.
 * @param {number} [options.maxResultBytes]    Default 256 KB.
 * @param {object} [options.tracker]           Inject ContextTracker.
 * @param {object} [options.logger]            Inject Logger.
 * @param {object} [options.decisionLogger]    Inject DecisionLogger.
 * @returns {{
 *   shield: () => object,
 *   watch:  (target: object) => () => void,
 *   meta:   typeof adapterMeta,
 * }}
 */
export function openaiAgents(options = {}) {
  const mode = options.mode || 'enforce';
  if (mode !== 'observe' && mode !== 'enforce') {
    throw new TypeError(
      `openaiAgents: options.mode must be 'observe' or 'enforce', got '${mode}'`,
    );
  }

  // v1.4.6 — Fortress live policy source (the OpenAI register flow). When
  // `policies: { source: 'fortress' }` is set, build a FortressPolicySource
  // that the guardrail pulls from (+ background refresh), mirroring how
  // wma-shield gets its ruleset for Anthropic. Requires an agentId to scope
  // the pull, a base URL (option or WMA_FORTRESS_BASE_URL), and WMA_API_KEY.
  let fortressPolicySource = null;
  let fortressDecisionSink = null;
  if (options.policies && options.policies.source === 'fortress') {
    if (!options.agentId) {
      throw new Error(
        "openaiAgents({ policies: { source: 'fortress' } }) requires `agentId` " +
        "(the agent id you registered in Fortress) to scope the policy pull.",
      );
    }
    const apiKey = options.policies.apiKey || process.env.WMA_API_KEY;
    if (!apiKey) {
      throw new Error(
        "openaiAgents fortress policies: WMA_API_KEY is required (env or " +
        "policies.apiKey) to authenticate the policy pull.",
      );
    }
    const base = resolveFortressBase({
      explicitBase: options.policies.baseUrl,
      env: process.env,
    });
    if (!base) {
      throw new Error(
        "openaiAgents fortress policies: no base URL — set policies.baseUrl or " +
        "WMA_FORTRESS_BASE_URL (e.g. https://<project>.supabase.co/functions/v1).",
      );
    }
    fortressPolicySource = new FortressPolicySource({
      apiKey,
      base,
      anthropicAgentId: options.agentId,   // scopes get-policies by native agent id
      provider: adapterMeta.provider,      // v1.4.9: 'openai-agents' → Fortress scopes by (provider, native_agent_id)
      requireSignedPolicies: options.policies.requireSignedPolicies,
      failMode: options.policies.failMode,
    });

    // v1.4.7 (#1): ship decisions to the SAME Fortress (the control plane you
    // pull policies from is where the decisions belong). Auto-on; opt out with
    // policies.uploadDecisions === false to keep decisions local-only. The
    // guardrail fires these best-effort, off its hot path.
    if (options.policies.uploadDecisions !== false) {
      fortressDecisionSink = (decision) => postDecision({ apiKey, base, decision });
    }
  }

  // v1.4 Codex #2 — fail-loud refusal to start in enforce mode without
  // any policy source. Avoids the v1.3.0 footgun where missing policies
  // silently degraded to "allow all" with only a stderr warning. The
  // failure surfaces at config time (not on the first request) so it's
  // impossible to deploy a build that LOOKS armed but isn't.
  if (mode === 'enforce' && options.policiesPath == null && options.ruleset == null
      && fortressPolicySource == null) {
    throw new Error(
      "openaiAgents({ mode: 'enforce' }) requires policiesPath, ruleset, or " +
      "policies: { source: 'fortress' }. Either provide one, or switch to " +
      "{ mode: 'observe' } if you only want Watch (NDJSON capture) without Shield.",
    );
  }

  // Shared config we thread into both shield() and watch() so the
  // customer doesn't have to repeat it.
  const sharedOptions = {
    agentId:         options.agentId,            // v1.4.6: NDJSON path + native_agent_id
    fortressPolicySource,                        // v1.4.6: live Fortress ruleset (or null)
    fortressDecisionSink,                        // v1.4.7 #1: ship decisions (or null)
    maxDecisionUploadsInFlight: options.maxDecisionUploadsInFlight,  // v1.4.8: backpressure cap
    signalsSalt:     options.signalsSalt || process.env.WMA_SIGNALS_SALT,  // hash session/input
    policiesPath:    options.policiesPath,
    ruleset:         options.ruleset,
    logDir:          options.logDir,
    sessionId:       options.sessionId,
    failOpen:        options.failOpen,
    recentWindowSize: options.recentWindowSize,
    getTeamId:       options.getTeamId,
    tracker:         options.tracker,
    logger:          options.logger,
    decisionLogger:  options.decisionLogger,
    toolInputs:      options.toolInputs,
    maxArgBytes:     options.maxArgBytes,
    maxResultBytes:  options.maxResultBytes,
  };

  return Object.freeze({
    /** Returns the @openai/agents Tool Input Guardrail. In `observe`
     *  mode this throws — the customer asked for Watch-only and a
     *  guardrail would be misleading. */
    shield() {
      if (mode === 'observe') {
        throw new Error(
          "openaiAgents({ mode: 'observe' }).shield() is not allowed. " +
          "Observe mode does not produce Shield enforcement. " +
          "Switch to { mode: 'enforce', policiesPath: '...' } if you want to block.",
        );
      }
      return wmaToolInputGuardrail(sharedOptions);
    },

    /** Attaches Watch listeners. Auto-detects whether `target` is an
     *  Agent (AgentHooks) or a Runner (RunHooks) by checking method
     *  shape and known fields. Returns a detach function. */
    watch(target) {
      return autoAttachWatch(target, sharedOptions);
    },

    /** Adapter metadata — useful for tooling that wants to introspect
     *  what's available (capabilities, peer-dep min version, etc.). */
    meta: adapterMeta,

    /** The configured mode, exposed for runtime introspection. */
    mode,
  });
}

// v1.4 Codex #7 — auto-detect Runner vs Agent and dispatch to the
// matching attach function. The shape difference:
//   - @openai/agents Runner has `.run(agent, input)` AND emits the
//     RunHooks events with the agent as an explicit arg.
//   - @openai/agents Agent has `.name`/`.instructions`/`.tools` AND
//     emits AgentHooks events with the agent IMPLICIT (closure-
//     captured by attachWmaWatchToAgent).
//
// Both expose `.on()` from the EventEmitter base. We detect the
// runner by checking for `.run` (function) — it's the convenience the
// Runner class exposes that Agent doesn't. As a tiebreaker we look
// at the presence of `.tools` (Agent-only) and the absence of `.name`
// is fine as a hint but not load-bearing.
function autoAttachWatch(target, options) {
  if (!target || typeof target.on !== 'function') {
    throw new TypeError(
      'openaiAgents().watch(target): target must expose .on(event, listener). ' +
      'Pass an @openai/agents Runner or Agent instance.',
    );
  }
  // Independent signal checks — DO NOT make `looksLikeRunner` exclusive
  // of `looksLikeAgent`. The whole point of the ambiguity check below
  // is to catch targets that satisfy both shapes.
  const hasRunMethod = typeof target.run === 'function';
  const hasAgentShape = Array.isArray(target.tools) && typeof target.name === 'string';

  if (hasRunMethod && hasAgentShape) {
    throw new TypeError(
      'openaiAgents().watch(target): target looks like both Agent and Runner ' +
      '(has .tools[] AND .name AND .run() method). Disambiguate by calling ' +
      'attachWmaWatch(runner) or attachWmaWatchToAgent(agent) directly.',
    );
  }
  if (hasAgentShape) {
    return attachWmaWatchToAgent(target, options);
  }
  if (hasRunMethod) {
    return attachWmaWatch(target, options);
  }
  // Neither shape unambiguously identified — fall back to AgentHooks
  // since the convenience `run(agent, ...)` function dispatches
  // AgentHooks, which is the more common path for new customers
  // (validated against real fixtures captured 2026-06-10).
  return attachWmaWatchToAgent(target, options);
}

// Re-export the low-level functions so customers that need fine-grained
// control (e.g. test scaffolding, advanced multi-runner setups) can
// still reach them. The factory is the recommended entry point; these
// are the escape hatches.
export {
  wmaToolInputGuardrail,
  attachWmaWatch,
  attachWmaWatchToAgent,
  adapterMeta,
};
