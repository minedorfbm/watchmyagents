#!/usr/bin/env node
// wma-shield — real-time policy enforcement for Anthropic Managed Agents.
//
// Two modes:
//
//   AGENT-WIDE (production)  — wma-shield --agent-id agent_xxx
//     Attaches to ALL active sessions of the agent. Discovers new sessions
//     via periodic listSessions polling. Runs forever until SIGINT.
//
//   SINGLE-SESSION (testing) — wma-shield --agent-id agent_xxx --session-id sesn_xxx
//     Attaches to one specific session and exits when that session ends.
//
// Within each session, Shield uses one of two enforcement modes auto-detected
// at startup from the agent config:
//
//   tool_confirmation — when at least one tool has permission_policy:always_ask.
//                       Blocks tool calls BEFORE execution.
//   interrupt         — when no tool has always_ask. Reactive: terminates the
//                       session AFTER a violating tool ran. Zero setup required.
//
// Setup helper:
//   wma-shield --setup-guide --agent-id agent_xxx
//     → prints instructions to upgrade to tool_confirmation mode.
//
// ANTHROPIC_API_KEY env var is used if --api-key is omitted.

import { resolve } from 'node:path';
import { streamWithReconnect } from '../src/shield/stream.js';
import { loadPolicies, evaluate } from '../src/shield/policy.js';
import {
  confirmAllow, confirmDeny, interruptSession,
  getAgentConfig, detectAlwaysAsk,
} from '../src/shield/enforce.js';
import { DecisionLogger } from '../src/shield/decisions.js';
import { listSessions } from '../src/sources/anthropic-managed.js';

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const k = a.slice(2);
      const n = argv[i + 1];
      if (n == null || n.startsWith('--')) out[k] = true;
      else { out[k] = n; i++; }
    }
  }
  return out;
}

function die(msg, code = 1) { process.stderr.write(`${msg}\n`); process.exit(code); }
function info(msg) { process.stdout.write(`[shield] ${msg}\n`); }
function warn(msg) { process.stderr.write(`[shield] ⚠️  ${msg}\n`); }
function sinfo(sid, msg) { process.stdout.write(`[shield/${sid.slice(0, 12)}] ${msg}\n`); }
function swarn(sid, msg) { process.stderr.write(`[shield/${sid.slice(0, 12)}] ⚠️  ${msg}\n`); }

const CACHEABLE_TOOL_TYPES = new Set([
  'agent.tool_use', 'agent.mcp_tool_use', 'agent.custom_tool_use',
]);

// Session statuses that mean "still active, worth watching"
const ACTIVE_STATUSES = new Set(['running', 'idle', 'rescheduled']);

function normalizeForPolicy(rawEvent) {
  return {
    action_type: rawEvent.type === 'agent.tool_use' ? 'tool_use'
               : rawEvent.type === 'agent.mcp_tool_use' ? 'mcp_tool_use'
               : rawEvent.type === 'agent.custom_tool_use' ? 'custom_tool_use'
               : 'unknown',
    tool_name: rawEvent.name || 'unknown',
    input: rawEvent.input ?? null,
    _raw_type: rawEvent.type,
    _raw_id: rawEvent.id,
  };
}

function printSetupGuide(agentId) {
  process.stdout.write(`
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Shield setup guide — upgrade your agent to precise mode
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Without permission_policy: always_ask configured on your agent's
tools, Shield runs in DEGRADED mode (interrupts the session AFTER
a violating tool already executed).

For pre-execution blocking, your agent's "tools" array needs:

  {
    "type": "agent_toolset_20260401",
    "default_config": {
      "permission_policy": { "type": "always_ask" }
    }
  }

Anthropic's API does NOT support PATCH on /v1/agents, so options:

  Option A — Edit in the Anthropic Console (recommended):
    1. Visit https://console.anthropic.com/agents/${agentId}
    2. Edit the agent
    3. Set default_config.permission_policy to { "type": "always_ask" }
    4. Save. NEW sessions use the updated permission policy.

  Option B — Recreate the agent via API (returns a new agent_id):
    Use POST /v1/agents with your current config + the snippet above.

After either option, restart Shield — it auto-detects the new mode.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
`);
}

// ────────────────────────────────────────────────────────────────────────
// Per-session worker — runs one event loop, returns when session ends.
// ────────────────────────────────────────────────────────────────────────
async function runSessionWorker({ sessionId, ctx }) {
  const { apiKey, agentId, ruleset, mode, decisions, signal } = ctx;
  sinfo(sessionId, `attached (${mode} mode)`);

  let processed = 0, enforced = 0, sessionInterrupted = false;
  // Cache is only needed for tool_confirmation mode (lookup by event_id when
  // requires_action fires). Interrupt mode evaluates synchronously and never
  // reads the cache, so caching there would just leak memory on long sessions.
  const toolUseCache = new Map();

  try {
    for await (const rawEvent of streamWithReconnect({
      apiKey, sessionId, signal, maxAttempts: 3,
      onReconnect: ({ attempt, backoffMs, error }) => {
        sinfo(sessionId, `reconnect attempt ${attempt}/3 in ${backoffMs}ms (${error.message})`);
      },
    })) {
      processed++;

      // ── INTERRUPT MODE ──────────────────────────────────────────────
      if (mode === 'interrupt' && CACHEABLE_TOOL_TYPES.has(rawEvent.type)) {
        // No caching in interrupt mode — react synchronously, free memory.
        const normalized = normalizeForPolicy(rawEvent);
        const t0 = Date.now();
        const result = evaluate(normalized, ruleset);
        const decidedInMs = Date.now() - t0;

        sinfo(sessionId, `${rawEvent.type} tool=${normalized.tool_name} → ${result.decision}${result.rule_id ? ` (${result.rule_id})` : ''}`);

        await decisions(sessionId).record({
          sourceEvent: rawEvent, decision: result.decision,
          ruleId: result.rule_id, ruleName: result.rule_name,
          message: result.message, decidedInMs,
        });

        if ((result.decision === 'deny' || result.decision === 'interrupt') && !sessionInterrupted) {
          try {
            await interruptSession({
              apiKey, sessionId,
              followUpMessage: `Shield interrupted: ${result.message || result.rule_name || 'policy violation'}`,
            });
            sessionInterrupted = true;
            enforced++;
            swarn(sessionId, 'session interrupted — agent loop stopped');
          } catch (e) {
            process.stderr.write(`[shield/${sessionId.slice(0, 12)}] interrupt error: ${e.message}\n`);
          }
        }
        continue;
      }

      // ── TOOL_CONFIRMATION MODE ──────────────────────────────────────
      if (mode === 'tool_confirmation' && CACHEABLE_TOOL_TYPES.has(rawEvent.type)) {
        toolUseCache.set(rawEvent.id, rawEvent);
        continue;
      }

      if (mode === 'tool_confirmation'
          && rawEvent.type === 'session.status_idle'
          && rawEvent.stop_reason?.type === 'requires_action'
          && Array.isArray(rawEvent.stop_reason.event_ids)) {

        for (const eventId of rawEvent.stop_reason.event_ids) {
          const sourceEvent = toolUseCache.get(eventId);
          if (!sourceEvent) {
            swarn(sessionId, `requires_action for unknown event_id ${eventId} — denying defensively`);
            try {
              await confirmDeny({
                apiKey, sessionId, toolUseId: eventId,
                denyMessage: 'Shield never saw the original tool_use. Denying defensively.',
              });
            } catch (e) {
              process.stderr.write(`[shield/${sessionId.slice(0, 12)}] enforcement error: ${e.message}\n`);
            }
            continue;
          }

          const normalized = normalizeForPolicy(sourceEvent);
          const t0 = Date.now();
          const result = evaluate(normalized, ruleset);
          const decidedInMs = Date.now() - t0;

          sinfo(sessionId, `requires_action ${sourceEvent.type} tool=${normalized.tool_name} → ${result.decision}${result.rule_id ? ` (${result.rule_id})` : ''}`);

          await decisions(sessionId).record({
            sourceEvent, decision: result.decision,
            ruleId: result.rule_id, ruleName: result.rule_name,
            message: result.message, decidedInMs,
          });

          try {
            if (result.decision === 'allow') {
              await confirmAllow({ apiKey, sessionId, toolUseId: eventId });
              enforced++;
            } else if (result.decision === 'deny') {
              await confirmDeny({
                apiKey, sessionId, toolUseId: eventId,
                denyMessage: result.message || `Blocked by ${result.rule_name}`,
              });
              enforced++;
            } else if (result.decision === 'interrupt') {
              await interruptSession({
                apiKey, sessionId,
                followUpMessage: `Shield interrupted: ${result.message || result.rule_name}`,
              });
              sessionInterrupted = true;
              enforced++;
              break;
            }
          } catch (e) {
            process.stderr.write(`[shield/${sessionId.slice(0, 12)}] enforcement error on event ${eventId}: ${e.message}\n`);
          }

          toolUseCache.delete(eventId);
        }
        continue;
      }

      // Session ended → exit worker cleanly.
      if (rawEvent.type === 'session.status_terminated') {
        sinfo(sessionId, `session terminated: ${rawEvent.stop_reason?.type || 'unknown'}`);
        break;
      }
    }
  } catch (e) {
    if (!signal.aborted) {
      process.stderr.write(`[shield/${sessionId.slice(0, 12)}] worker error: ${e.message}\n`);
    }
  }

  sinfo(sessionId, `worker exit — observed ${processed}, enforced ${enforced}`);
  return { processed, enforced };
}

// ────────────────────────────────────────────────────────────────────────
// Agent-wide discovery — polls listSessions and spawns workers for new ones.
// ────────────────────────────────────────────────────────────────────────
async function runAgentWide(ctx) {
  const { apiKey, agentId, signal } = ctx;
  const workers = new Map();      // sessionId → AbortController (active workers)
  const cooldown = new Map();     // sessionId → unix-ms timestamp when re-attach is allowed

  const POLL_INTERVAL_MS = 10_000;
  // When a worker exits without seeing any events, the session's SSE stream
  // closed cleanly with no traffic — Anthropic does this for idle sessions.
  // Re-attaching every 10s spams the logs and the API for no benefit; cool down
  // for 60s before trying again. Any real activity invalidates the cooldown.
  const QUIET_COOLDOWN_MS = 60_000;

  async function discoverAndAttach() {
    let sessions;
    try {
      // Look at sessions from the last 24h (anything older that's still idle
      // is probably stale; the user can extend the window if needed).
      const since = new Date(Date.now() - 24 * 3600_000);
      sessions = await listSessions(apiKey, { agentId, since });
    } catch (e) {
      warn(`listSessions failed: ${e.message}`);
      return;
    }

    const now = Date.now();
    for (const s of sessions) {
      if (!s.id || workers.has(s.id)) continue;
      const status = s.status?.type || s.status; // tolerate either shape
      if (!ACTIVE_STATUSES.has(status)) continue;

      // Honor the cooldown for sessions that recently exited quietly.
      const retryAt = cooldown.get(s.id) || 0;
      if (now < retryAt) continue;

      // New active session — spawn a worker.
      const sessionAc = new AbortController();
      workers.set(s.id, sessionAc);
      const combined = AbortSignal.any([signal, sessionAc.signal]);

      runSessionWorker({
        sessionId: s.id,
        ctx: { ...ctx, signal: combined },
      }).then((stats) => {
        // Quiet exit → cooldown so we don't busy-loop reconnecting.
        // Productive exit (at least one event observed) → clear any cooldown.
        if (stats && stats.processed === 0) {
          cooldown.set(s.id, Date.now() + QUIET_COOLDOWN_MS);
        } else {
          cooldown.delete(s.id);
        }
      }).finally(() => {
        workers.delete(s.id);
      });
    }
  }

  info(`agent-wide mode — polling for sessions every ${POLL_INTERVAL_MS / 1000}s`);
  await discoverAndAttach();

  const ticker = setInterval(discoverAndAttach, POLL_INTERVAL_MS);

  // Block until SIGINT/SIGTERM.
  await new Promise(resolveOuter => {
    signal.addEventListener('abort', () => {
      clearInterval(ticker);
      for (const ac of workers.values()) ac.abort();
      resolveOuter();
    });
  });

  info(`shutdown — drained ${workers.size} remaining workers`);
}

// ────────────────────────────────────────────────────────────────────────
// Main
// ────────────────────────────────────────────────────────────────────────
async function main() {
  const args = parseArgs(process.argv.slice(2));
  const apiKey = args['api-key'] || process.env.ANTHROPIC_API_KEY;
  const agentId = args['agent-id'];

  if (args['setup-guide']) {
    if (!agentId) die('error: --setup-guide requires --agent-id <id>');
    printSetupGuide(agentId);
    process.exit(0);
  }

  const singleSessionId = args['session-id']; // optional now
  const policyPath = args.policy;
  const logDir = resolve(args['log-dir'] || './watchmyagents-logs');

  if (!apiKey) die('error: --api-key or ANTHROPIC_API_KEY required');
  if (!agentId) die('error: --agent-id required');
  if (!policyPath) die('error: --policy <path-to-policies.json> required');

  let ruleset;
  try {
    ruleset = await loadPolicies(resolve(policyPath));
  } catch (e) {
    die(`error loading policies: ${e.message}`);
  }

  let mode = 'interrupt';
  let agentMeta = null;
  try {
    agentMeta = await getAgentConfig(apiKey, agentId);
    if (detectAlwaysAsk(agentMeta)) mode = 'tool_confirmation';
  } catch (e) {
    warn(`could not fetch agent config (${e.message}). Defaulting to interrupt mode.`);
  }

  info(`armed — ${ruleset.policies.length} policies loaded from ${policyPath}`);
  info(`default action when no rule matches: ${ruleset.default.action}`);
  info(`agent: ${agentId}${agentMeta?.name ? ` "${agentMeta.name}"` : ''}`);
  info(`enforcement mode: ${mode}`);
  if (mode === 'interrupt') {
    warn('DEGRADED mode — Shield will interrupt AFTER a violating tool runs.');
    warn(`For pre-execution blocking, run: wma-shield --setup-guide --agent-id ${agentId}`);
  }

  // Per-session DecisionLogger factory (each session gets its own to keep
  // sequence numbers monotonic per session).
  const loggers = new Map();
  const decisions = (sessionId) => {
    if (!loggers.has(sessionId)) {
      loggers.set(sessionId, new DecisionLogger({ logDir, agentId, sessionId }));
    }
    return loggers.get(sessionId);
  };

  const ac = new AbortController();
  process.on('SIGINT',  () => { info('SIGINT received, shutting down…'); ac.abort(); });
  process.on('SIGTERM', () => { info('SIGTERM received, shutting down…'); ac.abort(); });

  const ctx = { apiKey, agentId, ruleset, mode, decisions, signal: ac.signal };

  if (singleSessionId) {
    info(`single-session mode — attached to ${singleSessionId}`);
    await runSessionWorker({ sessionId: singleSessionId, ctx });
  } else {
    await runAgentWide(ctx);
  }
}

main().catch(e => {
  process.stderr.write(`error: ${e.stack || e.message}\n`);
  process.exit(1);
});
