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

/**
 * Build the WMA OpenAI Agents SDK adapter from a single shared config.
 *
 * @param {object} [options]
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

  // v1.4 Codex #2 — fail-loud refusal to start in enforce mode without
  // any policy source. Avoids the v1.3.0 footgun where missing policies
  // silently degraded to "allow all" with only a stderr warning. The
  // failure surfaces at config time (not on the first request) so it's
  // impossible to deploy a build that LOOKS armed but isn't.
  if (mode === 'enforce' && options.policiesPath == null && options.ruleset == null) {
    throw new Error(
      "openaiAgents({ mode: 'enforce' }) requires policiesPath or ruleset. " +
      "Either provide one, or switch to { mode: 'observe' } if you only " +
      "want Watch (NDJSON capture) without Shield enforcement.",
    );
  }

  // Shared config we thread into both shield() and watch() so the
  // customer doesn't have to repeat it.
  const sharedOptions = {
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
