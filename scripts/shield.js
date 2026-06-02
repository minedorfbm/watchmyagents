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
import { maybePrintVersionAndExit } from '../src/version.js';
import { DecisionLogger } from '../src/shield/decisions.js';
import { listSessions, listAgents } from '../src/sources/anthropic-managed.js';
import { FortressPolicySource, postDecision } from '../src/shield/sources/fortress.js';
import { resolveFortressBase, fortressEndpoint } from '../src/fortress/url.js';
import { PolicyStream } from '../src/shield/policy-stream.js';
import { isValidAgentId, isValidSessionId } from '../src/validate.js';
// v1.1.4 F-19 (P1 Codex audit): all egress to Fortress now flows through
// buildFortressDecisionPayload, which normalizes tool_name via the
// anonymizer's allowlist + salted-hash scheme and drops anything it can't
// safely normalize. Keeps Shield's payload aligned with the README
// promise that decisions ship fingerprints, not raw values.
import { buildFortressDecisionPayload } from '../src/shield/upload.js';

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
const sleep = (ms, signal) => new Promise((res) => {
  const t = setTimeout(res, ms);
  if (signal) signal.addEventListener('abort', () => { clearTimeout(t); res(); }, { once: true });
});
function parseWindowMs(v, fallback) {
  const m = v && String(v).match(/^(\d+)\s*([smhd])$/);
  return m ? parseInt(m[1], 10) * { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }[m[2]] : fallback;
}

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
  const { apiKey, agentId, mode, decisions, signal, pushDecisionToFortress, signalsSalt } = ctx;
  // NOTE: ctx.ruleset is a getter — read it FRESH per evaluation so policy
  // refreshes from Fortress (every 5 min) take effect without restart.
  sinfo(sessionId, `attached (${mode} mode)`);

  // Helper: assemble + fire the decision push to Fortress (fire-and-forget).
  // v1.1.4 F-19 (P1 Codex audit): delegates payload construction to the
  // pure helper in src/shield/upload.js so the egress-side containment
  // logic (tool_name allowlist + salted hashing) is unit-tested in
  // isolation. The helper drops any field it cannot safely normalize
  // (custom tool without salt, missing salt for hashes) rather than
  // passing the raw value through.
  const fireToFortress = (rawEvent, normalized, result, decidedInMs) => {
    if (!pushDecisionToFortress) return;
    const payload = buildFortressDecisionPayload({
      agentId, sessionId, rawEvent, normalized, result, decidedInMs,
      signalsSalt,
    });
    pushDecisionToFortress(payload).catch(() => undefined);
  };

  let processed = 0, enforced = 0, sessionInterrupted = false;
  // Cache is only needed for tool_confirmation mode (lookup by event_id when
  // requires_action fires). Interrupt mode evaluates synchronously and never
  // reads the cache, so caching there would just leak memory on long sessions.
  //
  // Bounded cache: any tool_use whose policy is "always_allow" never appears
  // in requires_action, so without these limits the Map would grow forever
  // on long-running sessions. Two limits enforced:
  //   - Maximum 1000 entries (LRU eviction)
  //   - TTL 5 minutes (any entry not consumed by requires_action gets dropped)
  const TOOLUSE_CACHE_MAX = 1000;
  const TOOLUSE_CACHE_TTL_MS = 5 * 60 * 1000;
  const toolUseCache = new Map(); // event_id → { event, cachedAt }

  function cacheToolUse(event) {
    const now = Date.now();
    // TTL sweep: only walk if cache is non-trivial in size (cheap noop otherwise)
    if (toolUseCache.size > 16) {
      for (const [k, v] of toolUseCache) {
        if (now - v.cachedAt > TOOLUSE_CACHE_TTL_MS) toolUseCache.delete(k);
      }
    }
    // LRU cap: drop oldest insertion if over the size limit
    while (toolUseCache.size >= TOOLUSE_CACHE_MAX) {
      const oldest = toolUseCache.keys().next().value;
      toolUseCache.delete(oldest);
    }
    toolUseCache.set(event.id, { event, cachedAt: now });
  }

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
        const result = evaluate(normalized, ctx.ruleset);
        const decidedInMs = Date.now() - t0;

        // v1.1.3 Phase 1.D — mode badge in the log line for operator visibility.
        const modeTag = result.mode === 'shadow' ? ' [SHADOW]' : '';
        sinfo(sessionId, `${rawEvent.type} tool=${normalized.tool_name} → ${result.decision}${modeTag}${result.rule_id ? ` (${result.rule_id})` : ''}`);

        await decisions(sessionId).record({
          sourceEvent: rawEvent, decision: result.decision,
          ruleId: result.rule_id, ruleName: result.rule_name,
          message: result.message, decidedInMs,
          mode: result.mode,
        });
        fireToFortress(rawEvent, normalized, result, decidedInMs);

        // v1.1.3 Phase 1.D — in shadow mode, the decision is COMPUTED + LOGGED
        // but NOT enforced. The rule's "would_deny" / "would_interrupt"
        // outcome flows to Fortress for Platt-scaling calibration + diff-in-diff
        // efficacy measurement (Guardian Core hardening axes 1 + 4), but the
        // agent's session continues uninterrupted. Promote to enforce only
        // after calibration confidence + lifecycle gates (Guardian Core spec
        // observe → shadow → enforce → retired).
        if (result.mode === 'shadow') continue;

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
        cacheToolUse(rawEvent);
        continue;
      }

      if (mode === 'tool_confirmation'
          && rawEvent.type === 'session.status_idle'
          && rawEvent.stop_reason?.type === 'requires_action'
          && Array.isArray(rawEvent.stop_reason.event_ids)) {

        for (const eventId of rawEvent.stop_reason.event_ids) {
          const cached = toolUseCache.get(eventId);
          const sourceEvent = cached?.event;
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
          const result = evaluate(normalized, ctx.ruleset);
          const decidedInMs = Date.now() - t0;

          // v1.1.3 Phase 1.D — mode badge in the log line for operator visibility.
          const modeTag = result.mode === 'shadow' ? ' [SHADOW]' : '';
          sinfo(sessionId, `requires_action ${sourceEvent.type} tool=${normalized.tool_name} → ${result.decision}${modeTag}${result.rule_id ? ` (${result.rule_id})` : ''}`);

          await decisions(sessionId).record({
            sourceEvent, decision: result.decision,
            ruleId: result.rule_id, ruleName: result.rule_name,
            message: result.message, decidedInMs,
            mode: result.mode,
          });
          fireToFortress(sourceEvent, normalized, result, decidedInMs);

          // v1.1.3 Phase 1.D — shadow mode in tool_confirmation: we MUST
          // still send confirmAllow even when the rule said deny/interrupt,
          // otherwise the agent hangs waiting for our response. The
          // decision is logged with mode=shadow so calibration can compare
          // what the rule said vs what was enforced (which is "nothing"
          // here). For mode=enforce, the original branching below stands.
          if (result.mode === 'shadow') {
            try {
              await confirmAllow({ apiKey, sessionId, toolUseId: eventId });
              // No enforced++ — shadow doesn't enforce by definition.
            } catch (e) {
              process.stderr.write(`[shield/${sessionId.slice(0, 12)}] shadow confirmAllow error: ${e.message}\n`);
            }
            continue;
          }

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
  // Discovery window for sessions we haven't attached yet (default 7d). Already-
  // attached workers stream until the session terminates regardless of age, so a
  // long-running session never loses enforcement once attached.
  const discoveryWindowMs = ctx.discoveryWindowMs || 7 * 24 * 3600_000;
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
      const since = new Date(Date.now() - discoveryWindowMs);
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
  // v1.1.1 F-13: --version / -v short-circuit before any other parsing.
  maybePrintVersionAndExit(process.argv);
  const args = parseArgs(process.argv.slice(2));
  const apiKey = args['api-key'] || process.env.ANTHROPIC_API_KEY;
  const agentId = args['agent-id'];

  if (args['setup-guide']) {
    if (!agentId) die('error: --setup-guide requires --agent-id <id>');
    printSetupGuide(agentId);
    process.exit(0);
  }

  // Security: --api-key on the command line ends up in shell history and in
  // the process list. Strongly prefer the ANTHROPIC_API_KEY env var.
  if (args['api-key']) {
    process.stderr.write(
      '[shield] warning: --api-key on the command line is visible in shell history and\n' +
      '         in the process list. Prefer: export ANTHROPIC_API_KEY=...\n'
    );
  }

  const singleSessionId = args['session-id']; // optional now
  const policyPath = args.policy;
  const policiesSource = args['policies-source'] || (policyPath ? 'local' : null);
  const wmaApiKey = args['wma-api-key'] || process.env.WMA_API_KEY;
  const signalsSalt = args['salt'] || process.env.WMA_SIGNALS_SALT;
  const fortressBase = resolveFortressBase({
    explicitBase: args['fortress-base-url'],
    explicitUrl: args['fortress-url'],
  });
  const logDir = resolve(args['log-dir'] || './watchmyagents-logs');
  const allAgents = !!args['all-agents'];
  const discoveryWindowMs = parseWindowMs(args['discovery-since'], 7 * 24 * 3600_000);

  if (!apiKey) die('error: --api-key or ANTHROPIC_API_KEY required');
  if (!allAgents && !agentId) die('error: --agent-id required (or --all-agents for fleet mode)');
  if (allAgents && singleSessionId) die('error: --all-agents is incompatible with --session-id');
  if (allAgents && policiesSource !== 'fortress') {
    die('error: --all-agents requires --policies-source fortress (per-agent policies).');
  }
  if (agentId && !isValidAgentId(agentId)) {
    die(`error: --agent-id has invalid format (expected "agent_" + alphanumeric, got "${agentId}")`);
  }
  // --session-id ends up in the Anthropic SSE URL path (src/shield/stream.js).
  // Validate the same way wma-fetch does so a crafted value can't tamper the URL.
  if (singleSessionId && !isValidSessionId(singleSessionId)) {
    die(`error: --session-id has invalid format (expected "sesn_" + alphanumeric, got "${singleSessionId}")`);
  }

  // Validate the policy source config once (shared across the fleet). For local
  // mode the ruleset is loaded once and shared by every agent.
  let sharedLocalRuleset = null;
  if (policiesSource === 'fortress') {
    if (!wmaApiKey) die('error: --policies-source fortress requires --wma-api-key or WMA_API_KEY env');
    if (!fortressBase) die('error: --policies-source fortress requires --fortress-base-url or WMA_FORTRESS_BASE_URL env');
    if (!/^wma_[a-f0-9]{32}$/i.test(wmaApiKey)) warn(`WMA_API_KEY format looks unusual (expected wma_<32hex>).`);
  } else if (policiesSource === 'local') {
    if (!policyPath) die('error: --policies-source local requires --policy <path-to-policies.json>');
    try { sharedLocalRuleset = await loadPolicies(resolve(policyPath)); }
    catch (e) { die(`error loading policies: ${e.message}`); }
  } else {
    die('error: --policy <path> OR --policies-source fortress required');
  }

  // Resolve the agent list: whole fleet (--all-agents) or a single agent.
  let agentIds;
  if (allAgents) {
    info('discovering agents (fleet mode)…');
    const all = await listAgents(apiKey).catch((e) => die(`failed to list agents: ${e.message}`));
    agentIds = all.map((a) => a.id).filter((id) => id && isValidAgentId(id));
    if (agentIds.length === 0) die('error: no agents found under this API key');
    info(`fleet: ${agentIds.length} agent(s)`);
  } else {
    agentIds = [agentId];
  }
  const fleet = agentIds.length > 1;

  // Shared infra: one shutdown signal, one fortress-source registry, one pusher.
  const ac = new AbortController();
  const fortressSources = [];
  const fortressStreams = [];  // v1.1.0 Phase 2 PolicyStream instances
  const shutdown = (sig) => {
    info(`${sig} received, shutting down…`);
    for (const fp of fortressSources) fp.stop();
    for (const ps of fortressStreams) ps.close();
    ac.abort();
  };
  process.on('SIGINT',  () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));

  // Optional Fortress decision pusher (each ctx carries its own agent id, so a
  // single shared pusher tags decisions with the right agent).
  const canPushToFortress = !!(wmaApiKey && fortressBase);
  const pushDecisionToFortress = canPushToFortress
    ? async (decisionData) => {
        try { await postDecision({ apiKey: wmaApiKey, base: fortressBase, decision: decisionData }); }
        catch (e) { warn(`Fortress decision push failed: ${e.message}`); }
      }
    : null;

  // Per-agent SETUP (separate from the long-running phase so we can COUNT how
  // many actually armed). In fleet mode a per-agent startup failure is skipped
  // (warn) instead of killing the fleet. Returns the agent's ctx, or null if skipped.
  async function setupAgent(aid) {
    const tag = fleet ? `[${aid.slice(0, 16)}…] ` : '';
    let fortressPolicies = null;
    let ruleset = sharedLocalRuleset;
    if (policiesSource === 'fortress') {
      // v1.1.0 Phase 1 L3.5: policy refresh from Fortress every 60s
      // (was 5min). Combined with Phase 2 realtime subscription work,
      // this brings new-policy-deployed-to-Shield latency from 5min
      // worst-case down to ~60s, with the Phase 2 push model taking
      // it to sub-second later.
      fortressPolicies = new FortressPolicySource({
        apiKey: wmaApiKey, base: fortressBase, anthropicAgentId: aid, refreshIntervalMs: 60_000,
        onError: (e) => warn(`${tag}policy refresh failed (keeping cached): ${e.message}`),
        onRefresh: ({ policies, fetched_at, initial }) => info(`${tag}policies ${initial ? 'loaded' : 'refreshed'} from Fortress — ${policies.length} active (fetched_at: ${fetched_at})`),
      });
      try { await fortressPolicies.start(); }
      catch (e) {
        if (fleet) { warn(`${tag}skipped — policy fetch failed: ${e.message}`); return null; }
        die(`error fetching policies from Fortress: ${e.message}\n       Check WMA_FORTRESS_BASE_URL and WMA_API_KEY.`);
      }
      fortressSources.push(fortressPolicies);
      // v1.1.0 Phase 2: persistent SSE connection to Fortress for instant
      // policy updates (~100ms latency vs 60s poll). Falls back silently
      // when the /policies-stream endpoint isn't deployed yet (HTTP 404),
      // so the SDK ships safely even if the companion Lovable prompt
      // hasn't landed on a given Fortress instance.
      const streamUrl = fortressEndpoint(fortressBase, 'policies-stream');
      const policyStream = new PolicyStream({
        url: streamUrl,
        apiKey: wmaApiKey,
        anthropicAgentId: aid,
        onError: (e) => warn(`${tag}policy-stream: ${e.message}`),
        onInfo: (msg) => info(`${tag}${msg}`),
      });
      policyStream.on('policy_changed', () => {
        // Fortress pushed a policy change for this agent — trigger an
        // immediate refresh through the standard path so all the existing
        // compile/validation logic applies.
        fortressPolicies.refresh().catch((e) => warn(`${tag}stream-triggered refresh failed: ${e.message}`));
      });
      policyStream.start();
      fortressStreams.push(policyStream);
      ruleset = fortressPolicies.current();
    }

    let mode = 'interrupt';
    let agentMeta = null;
    try { agentMeta = await getAgentConfig(apiKey, aid); if (detectAlwaysAsk(agentMeta)) mode = 'tool_confirmation'; }
    catch (e) { warn(`${tag}could not fetch agent config (${e.message}). Defaulting to interrupt mode.`); }

    info(`${tag}armed — ${ruleset.policies.length} policies · default ${ruleset.default.action} · mode ${mode}${agentMeta?.name ? ` · "${agentMeta.name}"` : ''}`);
    if (mode === 'interrupt' && !fleet) {
      warn('DEGRADED mode — Shield will interrupt AFTER a violating tool runs.');
      warn(`For pre-execution blocking, run: wma-shield --setup-guide --agent-id ${aid}`);
    }

    const loggers = new Map();
    const decisions = (sessionId) => {
      if (!loggers.has(sessionId)) loggers.set(sessionId, new DecisionLogger({ logDir, agentId: aid, sessionId }));
      return loggers.get(sessionId);
    };
    return {
      apiKey, agentId: aid,
      get ruleset() { return fortressPolicies ? fortressPolicies.current() : ruleset; },
      mode, decisions, pushDecisionToFortress, signalsSalt, signal: ac.signal, discoveryWindowMs,
    };
  }

  if (!fleet) {
    // Single agent: arm + run (blocks until SIGINT/SIGTERM). die() on failure
    // already fires inside setupAgent for the non-fleet path.
    const ctx = await setupAgent(agentIds[0]);
    await (singleSessionId ? runSessionWorker({ sessionId: singleSessionId, ctx }) : runAgentWide(ctx));
    return;
  }

  // Fleet: arm all discovered agents, then RECONCILE periodically so an agent
  // created after startup gets armed + protected without a restart. A per-agent
  // arm failure is skipped and retried on the next reconcile.
  const armed = new Set();
  const running = [];
  const armNew = async (ids) => {
    for (const aid of ids) {
      if (armed.has(aid)) continue;
      const ctx = await setupAgent(aid);
      if (!ctx) continue;                 // skipped (policy fetch failed) → retry next reconcile
      armed.add(aid);
      running.push(runAgentWide(ctx));    // fire; blocks on the shared signal until shutdown
      info(`fleet: armed ${aid.slice(0, 16)}…`);
    }
  };
  await armNew(agentIds);
  if (armed.size === 0) {
    die(`error: no agents could be armed (${agentIds.length} discovered; all policy fetches failed). Check WMA_API_KEY / WMA_FORTRESS_BASE_URL.`);
  }
  // v1.1.0 Phase 1 L3: supervisor reconcile every 30s (was 60s) so a
  // freshly-created Anthropic agent gets armed sub-30s instead of sub-minute.
  info(`fleet: ${armed.size}/${agentIds.length} agent(s) armed; reconciling every 30s for new agents.`);
  while (!ac.signal.aborted) {
    await sleep(30_000, ac.signal);
    if (ac.signal.aborted) break;
    let all;
    try { all = await listAgents(apiKey); }
    catch (e) { warn(`fleet reconcile failed (keeping current): ${e.message}`); continue; }
    await armNew(all.map((a) => a.id).filter((id) => id && isValidAgentId(id)));
  }
  await Promise.all(running);
}

main().catch(e => {
  process.stderr.write(`error: ${e.stack || e.message}\n`);
  process.exit(1);
});
