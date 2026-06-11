// Anthropic Managed Agents — post-hoc fetcher
//
// Verified against docs.claude.com/managed-agents/events-and-streaming
// (managed-agents-2026-04-01 beta).
//
// Mapping policy:
//   span.model_request_end (model_usage)   → llm_call entry  (tokens + duration)
//   agent.tool_use + agent.tool_result     → tool_use entry  (duration + error)
//   agent.mcp_tool_use + agent.mcp_tool_result → mcp_tool_use entry
//   agent.custom_tool_use                  → custom_tool_use entry (no duration —
//                                            resolution comes from user side)
//   session.error                          → error entry
//   agent.message / agent.thinking         → skipped (token cost is on the
//                                            model_request_end span anyway,
//                                            content is the agent's output not
//                                            an "action" we observe)

import { request } from 'node:https';
import { URLSearchParams } from 'node:url';
import { Source, PROVIDERS, ENFORCEMENT_MODES, ACTION_TYPES, COMPOSITION_PATTERNS } from './contract.js';
import {
  getAgentConfig, detectAlwaysAsk,
  confirmAllow, confirmDeny, interruptSession,
} from '../shield/enforce.js';
import { safeNonNegInt } from '../tokens.js';

const API_HOST = 'api.anthropic.com';
const BETA = 'managed-agents-2026-04-01';
const VERSION = '2023-06-01';
// Hard cap on any single GET so a hung connection can't pin Watch/Shield
// forever. getWithRetry will retry on timeout (the error propagates here).
const REQUEST_TIMEOUT_MS = 30_000;
// v1.1.2 F-17 (P3 Codex audit): cap on a single Anthropic response body.
// Event history pages (/v1/sessions/{id}/events) can carry up to ~1000
// events × thousands of bytes each, so 16 MB is the headroom we leave
// before we conclude something is wrong. Above this we abort the
// request and getWithRetry will retry on the next attempt.
const MAX_ANTHROPIC_RESPONSE_BYTES = 16 * 1024 * 1024;

function httpGet(apiKey, path) {
  return new Promise((resolve, reject) => {
    const req = request({
      host: API_HOST, port: 443, path, method: 'GET',
      rejectUnauthorized: true,
      headers: {
        'x-api-key': apiKey,
        'anthropic-version': VERSION,
        'anthropic-beta': BETA,
        'accept': 'application/json',
      },
    }, res => {
      const chunks = [];
      let receivedBytes = 0;
      let aborted = false;
      res.on('data', c => {
        if (aborted) return;
        receivedBytes += c.length;
        if (receivedBytes > MAX_ANTHROPIC_RESPONSE_BYTES) {
          aborted = true;
          chunks.length = 0;
          try { req.destroy(); } catch { /* already destroyed */ }
          reject(new Error(`Anthropic response exceeded ${MAX_ANTHROPIC_RESPONSE_BYTES} bytes — aborting (${path})`));
          return;
        }
        chunks.push(c);
      });
      res.on('end', () => {
        if (aborted) return;
        const body = Buffer.concat(chunks).toString('utf8');
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try { resolve(JSON.parse(body)); } catch (e) { reject(e); }
        } else if (res.statusCode === 429) {
          const ra = parseInt(res.headers['retry-after'] || '5', 10);
          const err = new Error(`HTTP 429: ${body}`);
          err.retryAfter = ra; reject(err);
        } else {
          reject(new Error(`HTTP ${res.statusCode}: ${body.slice(0, 500)}`));
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(REQUEST_TIMEOUT_MS, () => {
      req.destroy(new Error(`Anthropic request timed out after ${REQUEST_TIMEOUT_MS}ms (${path})`));
    });
    req.end();
  });
}

async function getWithRetry(apiKey, path, attempts = 3) {
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try { return await httpGet(apiKey, path); }
    catch (e) {
      lastErr = e;
      const wait = e.retryAfter ? e.retryAfter * 1000 : 1000 * 2 ** i;
      if (i < attempts - 1) await new Promise(r => setTimeout(r, wait));
    }
  }
  throw lastErr;
}

export async function getAgent(apiKey, agentId) {
  return getWithRetry(apiKey, `/v1/agents/${agentId}`);
}

// List every Managed Agent under the API key (paginated). Used for fleet mode
// (watch/shield/service --all-agents) and agent discovery.
export async function listAgents(apiKey, { limit = 100 } = {}) {
  const agents = [];
  let after = null;
  while (true) {
    const qs = new URLSearchParams({ limit: String(limit) });
    if (after) qs.set('after_id', after);
    const data = await getWithRetry(apiKey, `/v1/agents?${qs}`);
    const page = data.data || [];
    for (const a of page) agents.push(a);
    if (!data.has_more || page.length === 0) break;
    after = page[page.length - 1]?.id;
    if (!after) break;
  }
  return agents;
}

// v1.4.2 F-45 (P1 audit): page through the FULL session list and filter by
// `since` per-row — do NOT early-break. The previous version stopped
// paginating at the first session older than `since`, assuming the API
// returns sessions newest-first by created_at. Nothing enforces that ordering
// (no `order=` param is sent), and the doc never promised it. If the API
// ordered by id / updated_at, a single out-of-window session aborted
// pagination while newer in-window sessions sat on later pages — they were
// NEVER enumerated, so that agent's activity went untraced (a security blind
// spot, the exact failure this tool exists to prevent). We now scan every
// page; a session older than `since` is skipped, not a stop signal. A null
// created_at is treated as in-window (we cannot prove it is old). `maxPages`
// is a pathological-loop backstop; hitting it warns loudly rather than
// silently truncating.
export async function listSessions(apiKey, { agentId, since, limit = 100, maxPages = 1000, _fetch } = {}) {
  // _fetch is an injectable page-fetcher seam for tests (path -> response
  // object with { data, has_more }). Production uses the real getWithRetry.
  const fetchPage = _fetch || ((path) => getWithRetry(apiKey, path));
  const sessions = [];
  let after = null;
  let pages = 0;
  while (pages < maxPages) {
    pages++;
    const qs = new URLSearchParams({ limit: String(limit) });
    if (agentId) qs.set('agent_id', agentId);
    if (after) qs.set('after_id', after);
    const data = await fetchPage(`/v1/sessions?${qs}`);
    const page = data.data || [];
    for (const s of page) {
      const created = s.created_at ? new Date(s.created_at) : null;
      if (since && created && created < since) continue;   // skip, do NOT stop
      sessions.push(s);
    }
    if (!data.has_more || page.length === 0) break;
    after = page[page.length - 1]?.id;
    if (!after) break;
  }
  if (pages >= maxPages) {
    process.stderr.write(
      `[wma] listSessions: hit maxPages=${maxPages} for agent ${agentId || '(all)'} — ` +
      'session enumeration may be INCOMPLETE. Raise maxPages or narrow the agent set.\n',
    );
  }
  return sessions;
}

// Yields raw events in chronological order. Accepts an optional types filter
// to reduce payload (server-side `types[]=...&types[]=...`).
export async function* fetchRawEvents(apiKey, sessionId, { types } = {}) {
  let after = null;
  while (true) {
    const qs = new URLSearchParams({ limit: '1000' });
    if (after) qs.set('after_id', after);
    if (types) for (const t of types) qs.append('types[]', t);
    const data = await getWithRetry(apiKey, `/v1/sessions/${sessionId}/events?${qs}`);
    const page = data.data || [];
    for (const ev of page) yield ev;
    if (!data.has_more || page.length === 0) break;
    after = page[page.length - 1]?.id;
    if (!after) break;
  }
}

const RELEVANT_TYPES = [
  'span.model_request_start', 'span.model_request_end',
  // User events (audit trail of human/orchestrator inputs)
  'user.message', 'user.interrupt',
  'user.tool_confirmation', 'user.custom_tool_result',
  // Agent events
  'agent.message', 'agent.thinking',
  'agent.tool_use', 'agent.tool_result',
  'agent.mcp_tool_use', 'agent.mcp_tool_result',
  'agent.custom_tool_use',
  'agent.thread_context_compacted',
  'agent.thread_message_sent', 'agent.thread_message_received',
  // Session lifecycle (security-critical: config changes, terminations)
  'session.error',
  'session.updated',
  'session.thread_created',
  'session.status_running', 'session.status_idle',
  'session.status_rescheduled', 'session.status_terminated',
  'session.thread_status_running', 'session.thread_status_idle',
  'session.thread_status_terminated',
];

const tsMs = ev => Date.parse(ev.processed_at || ev.created_at || '') || null;

// v1.1.3 Phase 1.B — `fetchSessionEntries` is now a 3-line wrapper around
// the pure async transformer below. The HTTP layer (fetchRawEvents) is
// the only thing that needs the network — the per-event normalization
// logic is a pure async generator that any test can drive with synthetic
// event arrays. Same external contract; new internal seam for testing.
export async function* fetchSessionEntries({ apiKey, agentId, sessionId, model }) {
  yield* transformRawEventsToWMAActions(
    fetchRawEvents(apiKey, sessionId),
    { agentId, sessionId, model },
  );
}

/**
 * Pure async transformer: raw Anthropic events → WMAAction objects.
 *
 * Takes any async iterable of raw Anthropic events (live HTTP stream OR
 * synthetic test fixture array) plus the routing metadata, yields one
 * WMAAction per relevant event. Maintains all the cross-event state
 * (pendingModelReq / pendingToolUse pairs, subThreadIds tracking, F-6a
 * discriminators, F-8 end-of-session flush of unresolved tool calls).
 *
 * Why a separate function: keeps `fetchSessionEntries` HTTP-only and
 * makes integration tests trivial — no network mocking required.
 */
export async function* transformRawEventsToWMAActions(rawEventsAsyncIterable, { agentId, sessionId, model }) {
  // Pair-tracking maps: event_id of the "start" → its timestamp + metadata
  const pendingModelReq = new Map();    // span.model_request_start.id → ts
  const pendingToolUse = new Map();     // agent.tool_use.id → { ts, name, isMcp, input }

  // v1.1.3 Phase 1.C — Anthropic sub-agent detection.
  // Anthropic Task tool: when a parent agent delegates, a NEW thread is
  // spawned within the parent's session (`session.thread_created` event).
  // Subsequent events with that session_thread_id belong to the sub-agent.
  // We track the set of "spawned" thread ids and, for each event, set
  // composition_pattern='hierarchy' if it happened inside a sub-thread.
  //
  // Important Anthropic-specific design note: the sub-agent does NOT have
  // a separate agent_id at the Anthropic API level — it runs inside the
  // parent's session and its actions are attributed to the parent's
  // agent_id. So `parent_agent_id` STAYS NULL for all events of this
  // session (the sub-agent shares identity with the parent). Operators
  // who want per-sub-agent visibility use the local NDJSON's
  // `session_thread_id` + `agent_name` discriminators (captured since
  // v1.0.2 F-6a) to differentiate. Other adapters (OpenAI handoffs,
  // CrewAI manager, Hermes spawn_subagent) where sub-agents DO have
  // distinct API-level IDs will populate parent_agent_id natively.
  const subThreadIds = new Set();

  // `provider` is the canonical field per src/sources/contract.js (no
  // other consumer ever read the previous `framework` field, so it was
  // dropped in PR-B with zero downstream impact).
  const base = {
    provider: PROVIDERS.ANTHROPIC_MANAGED,
    agent_id: agentId,
    session_id: sessionId,
  };

  // No server-side `types[]` filter: the API rejects unknown values, but the
  // exact filterable set is undocumented & evolves. We pull everything and
  // filter here, ensuring future event types are surfaced rather than dropped.
  const RELEVANT = new Set(RELEVANT_TYPES);
  for await (const ev of rawEventsAsyncIterable) {
    if (!RELEVANT.has(ev.type)) continue;
    const type = ev.type;
    const ts = ev.processed_at || ev.created_at || new Date().toISOString();
    // v1.0.2 F-6a: capture Anthropic's own discriminators on EVERY event,
    // not just thread_message_*. session_thread_id + agent_name are how
    // the vendor itself tells parent activity from sub-agent activity.
    // Preserved LOCALLY (NDJSON) only — never sent raw to Fortress.
    const session_thread_id = ev.session_thread_id ?? null;
    const agent_name = ev.agent_name ?? null;
    // v1.1.3 Phase 1.C: derive composition_pattern at event level.
    // Sub-thread events (session_thread_id registered in subThreadIds via
    // a prior session.thread_created) → hierarchy. Root-thread events
    // OR events without thread_id → solo. The aggregator in uploadSignals
    // upgrades the AGENT-level composition_pattern to "hierarchy" when
    // any event in the window is non-solo, so even pre-spawn root events
    // contribute correctly to the agent's overall classification.
    const inSubThread = session_thread_id != null && subThreadIds.has(session_thread_id);
    const composition_pattern = inSubThread ? COMPOSITION_PATTERNS.HIERARCHY : COMPOSITION_PATTERNS.SOLO;
    // parent_agent_id: see the design note at the top of fetchSessionEntries.
    // Anthropic Task tool sub-agents share the parent's agent_id at the API
    // level, so the field is null for ALL Anthropic events. Explicitly
    // null (not undefined) so consumers see a documented value per WMAAction
    // schema and downstream tests can assert it cleanly.
    const subAgentMeta = { session_thread_id, agent_name, composition_pattern, parent_agent_id: null };
    const tsMillis = tsMs(ev);

    if (type === 'span.model_request_start') {
      pendingModelReq.set(ev.id, tsMillis);
      continue;
    }
    if (type === 'span.model_request_end') {
      const startTs = pendingModelReq.get(ev.model_request_start_id);
      pendingModelReq.delete(ev.model_request_start_id);
      const u = ev.model_usage || {};
      // v1.4.2 F-49 (P2 audit): sanitize to non-negative integers. A
      // malformed/adversarial model_usage (NaN, negative, string) must not
      // zero-out or poison the token totals that drive cost/abuse detection.
      const i = safeNonNegInt(u.input_tokens);
      const o = safeNonNegInt(u.output_tokens);
      const cr = safeNonNegInt(u.cache_read_input_tokens);
      const cw = safeNonNegInt(u.cache_creation_input_tokens);
      yield {
        ...base,
        ...subAgentMeta,
        id: ev.id,
        action_type: 'llm_call',
        tool_name: null,
        model: model || null,
        timestamp: ts,
        duration_ms: (startTs && tsMillis) ? tsMillis - startTs : null,
        input_tokens: i || null,
        output_tokens: o || null,
        cache_read_tokens: cr || null,
        cache_creation_tokens: cw || null,
        tokens_used: (i + o + cr + cw) || null,
        status: ev.is_error ? 'error' : 'ok',
      };
      continue;
    }

    if (type === 'user.message') {
      yield {
        ...base,
        ...subAgentMeta,
        id: ev.id,
        action_type: 'user_message',
        tool_name: null,
        model: model || null,
        timestamp: ts,
        status: 'ok',
        input: { content: ev.content || [] },
      };
      continue;
    }

    if (type === 'user.interrupt') {
      yield {
        ...base,
        ...subAgentMeta,
        id: ev.id,
        action_type: 'user_interrupt',
        tool_name: null,
        model: model || null,
        timestamp: ts,
        status: 'ok',
      };
      continue;
    }

    // Audit trail: who approved/denied which tool, with optional deny_message
    if (type === 'user.tool_confirmation') {
      const denied = ev.result === 'deny';
      yield {
        ...base,
        ...subAgentMeta,
        id: ev.id,
        action_type: 'tool_confirmation',
        tool_name: null,
        model: model || null,
        timestamp: ts,
        status: denied ? 'error' : 'ok',
        input: { tool_use_id: ev.tool_use_id, result: ev.result },
        output: { deny_message: ev.deny_message ?? null },
        error: denied ? (ev.deny_message || 'denied').slice(0, 500) : null,
      };
      continue;
    }

    if (type === 'user.custom_tool_result') {
      yield {
        ...base,
        ...subAgentMeta,
        id: ev.id,
        action_type: 'custom_tool_result',
        tool_name: null,
        model: model || null,
        timestamp: ts,
        status: ev.is_error ? 'error' : 'ok',
        input: { custom_tool_use_id: ev.custom_tool_use_id },
        output: { content: ev.content ?? null },
      };
      continue;
    }

    if (type === 'agent.message') {
      yield {
        ...base,
        ...subAgentMeta,
        id: ev.id,
        action_type: 'message',
        tool_name: null,
        model: model || null,
        timestamp: ts,
        status: 'ok',
        output: { content: ev.content || [] },
      };
      continue;
    }

    if (type === 'agent.thinking') {
      yield {
        ...base,
        ...subAgentMeta,
        id: ev.id,
        action_type: 'thinking',
        tool_name: null,
        model: model || null,
        timestamp: ts,
        status: 'ok',
        output: { thinking: ev.thinking ?? ev.content ?? null, signature: ev.signature ?? null },
      };
      continue;
    }

    if (type === 'agent.tool_use' || type === 'agent.mcp_tool_use') {
      pendingToolUse.set(ev.id, {
        ts: tsMillis,
        // v1.4.2 F-41 (P1 audit): a missing tool name becomes null, NOT the
        // literal string 'unknown'. A 'unknown' fallback (a) let a tool_name
        // DENYLIST silently miss a real tool whose name field was absent
        // (the rule keys on e.g. "bash"; "unknown" !== "bash" → no match →
        // default-allow), and (b) collided two distinct unnamed tools into
        // one forensic bucket. null fails every specific tool_name clause
        // closed and is honestly absent. tool_name is `string|null` per the
        // WMAAction contract; normalizeToolName(null) returns null and the
        // aggregator skips null-named entries from per-tool counts.
        name: ev.name ?? null,
        isMcp: type === 'agent.mcp_tool_use',
        input: ev.input ?? null,
        mcpServer: ev.server_name ?? ev.mcp_server_name ?? null,
        // v1.1.1 F-8: capture sub-agent context at storage time so the
        // end-of-session flush yields entries with the right attribution.
        startTimestamp: ts,
        session_thread_id,
        agent_name,
      });
      continue;
    }
    if (type === 'agent.tool_result' || type === 'agent.mcp_tool_result') {
      const start = pendingToolUse.get(ev.tool_use_id);
      pendingToolUse.delete(ev.tool_use_id);
      const isError = ev.is_error === true;
      // v1.1.3 Phase 1.B fix: the yielded action represents the TOOL CALL
      // as a whole (input from start, output from result). Its discriminators
      // (session_thread_id, agent_name, composition_pattern) should reflect
      // the START's context — where the tool was INVOKED — not the result
      // event's, which may or may not carry these fields depending on
      // provider event-shape quirks. Falls back to the current event's
      // subAgentMeta if the start somehow didn't capture them (defensive).
      const pairedMeta = start ? {
        session_thread_id: start.session_thread_id ?? subAgentMeta.session_thread_id,
        agent_name: start.agent_name ?? subAgentMeta.agent_name,
        composition_pattern: (start.session_thread_id != null && subThreadIds.has(start.session_thread_id))
          ? COMPOSITION_PATTERNS.HIERARCHY
          : COMPOSITION_PATTERNS.SOLO,
        parent_agent_id: null,  // see subAgentMeta — Anthropic shares parent's agent_id
      } : subAgentMeta;
      yield {
        ...base,
        ...pairedMeta,
        id: ev.id,
        action_type: start?.isMcp ? 'mcp_tool_use' : 'tool_use',
        tool_name: start?.name ?? null,   // F-41: null, never literal 'unknown'
        timestamp: ts,
        duration_ms: (start?.ts && tsMillis) ? tsMillis - start.ts : null,
        status: isError ? 'error' : 'ok',
        error: isError ? extractText(ev.content).slice(0, 500) : null,
        input: start?.input ?? null,
        output: { content: ev.content ?? null, mcp_server: start?.mcpServer ?? undefined },
      };
      continue;
    }

    if (type === 'agent.custom_tool_use') {
      yield {
        ...base,
        ...subAgentMeta,
        id: ev.id,
        action_type: 'custom_tool_use',
        tool_name: ev.name ?? null,   // F-41: null, never literal 'unknown'
        timestamp: ts,
        status: 'ok',
        input: ev.input ?? null,
      };
      continue;
    }

    // Context window saturation — historic content may be lost
    if (type === 'agent.thread_context_compacted') {
      yield {
        ...base,
        ...subAgentMeta,
        id: ev.id,
        action_type: 'context_compacted',
        tool_name: null,
        model: model || null,
        timestamp: ts,
        status: 'ok',
        output: {
          session_thread_id: ev.session_thread_id ?? null,
          agent_name: ev.agent_name ?? null,
        },
      };
      continue;
    }

    // Multi-agent: orchestrator/sub-agent message passing
    if (type === 'agent.thread_message_sent' || type === 'agent.thread_message_received') {
      const direction = type.endsWith('_sent') ? 'sent' : 'received';
      yield {
        ...base,
        ...subAgentMeta,
        id: ev.id,
        action_type: `thread_message_${direction}`,
        tool_name: null,
        model: model || null,
        timestamp: ts,
        status: 'ok',
        output: {
          session_thread_id: ev.session_thread_id ?? null,
          agent_name: ev.agent_name ?? null,
          content: ev.content ?? null,
        },
      };
      continue;
    }

    // Security-critical: session configuration changed mid-flight.
    // Docs say "Includes only the fields that changed."
    if (type === 'session.updated') {
      const { id: _id, type: _type, processed_at: _pa, created_at: _ca, ...changes } = ev;
      yield {
        ...base,
        ...subAgentMeta,
        id: ev.id,
        action_type: 'config_change',
        tool_name: null,
        model: model || null,
        timestamp: ts,
        status: 'ok',
        output: { changes },
      };
      continue;
    }

    if (type === 'session.thread_created') {
      // v1.1.3 Phase 1.C: register the newly-spawned thread as a sub-thread
      // BEFORE yielding so subsequent events with this session_thread_id are
      // correctly marked composition_pattern='hierarchy'. The thread_created
      // event itself is yielded with the pattern computed before this line —
      // it's the PARENT's act of spawning, so 'solo' is correct here (the
      // parent did this act in its own context); only the events that
      // FOLLOW inside the new thread get 'hierarchy'.
      if (ev.session_thread_id) subThreadIds.add(ev.session_thread_id);
      yield {
        ...base,
        ...subAgentMeta,
        id: ev.id,
        action_type: 'thread_created',
        tool_name: null,
        model: model || null,
        timestamp: ts,
        status: 'ok',
        output: {
          session_thread_id: ev.session_thread_id ?? null,
          agent_name: ev.agent_name ?? null,
        },
      };
      continue;
    }

    if (type === 'session.error') {
      yield {
        ...base,
        ...subAgentMeta,
        id: ev.id,
        action_type: 'session_error',
        tool_name: null,
        timestamp: ts,
        status: 'error',
        error: (ev.error?.message || 'session error').slice(0, 500),
      };
      continue;
    }

    // session.status_{running,idle,rescheduled,terminated},
    // session.thread_status_{running,idle,terminated}
    // → state transitions, useful for security audit (e.g. inspecting
    //   stop_reason for refusals, errors, max_tokens; terminated = fatal)
    if (type.startsWith('session.status_') || type.startsWith('session.thread_status_')) {
      const isThread = type.startsWith('session.thread_status_');
      const prefix = isThread ? 'session.thread_status_' : 'session.status_';
      const state = type.slice(prefix.length); // 'running' | 'idle' | 'rescheduled' | 'terminated'
      const fatal = state === 'terminated';
      yield {
        ...base,
        ...subAgentMeta,
        id: ev.id,
        action_type: 'state_transition',
        tool_name: null,
        model: model || null,
        timestamp: ts,
        status: fatal ? 'error' : 'ok',
        output: {
          scope: isThread ? 'session_thread' : 'session',
          state,
          stop_reason: ev.stop_reason ?? null,
          agent_name: ev.agent_name ?? null,
          session_thread_id: ev.session_thread_id ?? null,
        },
        error: fatal ? (ev.stop_reason?.message || ev.stop_reason?.type || 'session terminated').slice(0, 500) : null,
      };
      continue;
    }
  }

  // v1.1.1 F-8 (P1 Codex audit): flush remaining pendingToolUse entries
  // as explicit "no_result_observed" tool_use events. These are tool
  // calls that started (we saw agent.tool_use) but never produced a
  // result (no agent.tool_result paired): most commonly because Shield
  // pre-blocked them, the operator denied via tool_confirmation, the
  // tool died mid-execution, or the session terminated before the
  // result event arrived. For a security audit product, these incomplete
  // calls are often the MOST useful signals — a blocked exfil attempt
  // shows up here, not in successful tool_results. Yielding them
  // explicitly with status='error' keeps the local NDJSON, anonymizer
  // signals (counts, IoC hashes, tool_counts), and Fortress decisions
  // honest about what actually happened.
  for (const [toolUseId, pending] of pendingToolUse) {
    yield {
      ...base,
      session_thread_id: pending.session_thread_id,
      agent_name: pending.agent_name,
      id: toolUseId,
      action_type: pending.isMcp ? 'mcp_tool_use' : 'tool_use',
      tool_name: pending.name,
      model: model || null,
      timestamp: pending.startTimestamp,
      duration_ms: null,
      status: 'error',
      error: 'no_result_observed',
      input: pending.input,
      output: { mcp_server: pending.mcpServer ?? undefined },
    };
  }
  pendingToolUse.clear();
}

// ────────────────────────────────────────────────────────────────────────
// effectiveEnforcementMode — F-2 of the Codex v1.0.1 audit
// ────────────────────────────────────────────────────────────────────────
// AnthropicManagedSource.enforcementMode is the PROVIDER'S MAX capability
// (sync_confirm). But the EFFECTIVE mode for a given agent depends on
// whether at least one of its tools/toolsets has permission_policy =
// always_ask. When none does, Shield can only interrupt AFTER a violating
// tool ran, not block before — that's sync_interrupt territory.
//
// This helper resolves the per-agent effective mode from the live agent
// config so the value shipped to Fortress matches what Shield can
// actually do for THIS agent. Without this, Fortress can mis-display
// "sync_confirm" UI on an agent that's only interrupt-capable, leading
// the operator to deploy Shield policies that won't pre-block.
export async function effectiveEnforcementMode(apiKey, agentId) {
  const agentConfig = await getAgentConfig(apiKey, agentId);
  return detectAlwaysAsk(agentConfig)
    ? ENFORCEMENT_MODES.SYNC_CONFIRM
    : ENFORCEMENT_MODES.SYNC_INTERRUPT;
}

function extractText(content) {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content.map(b => (typeof b === 'string' ? b : (b?.text || JSON.stringify(b)))).join(' ');
  }
  if (content && typeof content === 'object') return content.text || JSON.stringify(content);
  return '';
}

// ────────────────────────────────────────────────────────────────────────
// AnthropicManagedSource — V1 Source contract wrapper
// ────────────────────────────────────────────────────────────────────────
// Implements the Source ABC over the low-level functions above. New SDK
// code should use this class; the function exports stay public for
// backwards compat with the existing wma-fetch + wma-shield daemons
// (migration is PR-B / PR-D).
//
// Capability declaration:
//   sync_confirm — Anthropic Managed Agents exposes pre-execution
//   `user.tool_confirmation` (block before the tool runs) AND
//   `user.interrupt` (stop the current LLM turn). The stronger of the
//   two is sync_confirm.

export class AnthropicManagedSource extends Source {
  static providerName = PROVIDERS.ANTHROPIC_MANAGED;
  // v1.1.3: renamed from `enforcementMode` — the static field is the MAX
  // capability the provider exposes; the EFFECTIVE per-agent mode is
  // resolved at runtime via effectiveEnforcementMode() since v1.0.1 F-2.
  // The `enforcementMode` getter inherited from Source.enforcementMode
  // returns this value, so callers reading either name still work.
  static enforcementCapability = ENFORCEMENT_MODES.SYNC_CONFIRM;

  constructor({ apiKey } = {}) {
    super({ apiKey });
    if (!apiKey) throw new Error('AnthropicManagedSource requires an apiKey');
    this.apiKey = apiKey;
    // Per-agent effective enforcement mode cache. One getAgent call per
    // agent across the lifetime of the Source instance.
    this._modeCache = new Map();
  }

  /**
   * Resolve the effective enforcement mode for an agent and cache the
   * answer. Useful internally for enforce() to choose between
   * pre-execution confirmation (always_ask agents) and post-hoc
   * interrupt (default agents).
   */
  async _getEffectiveModeFor(agentId) {
    const cached = this._modeCache.get(agentId);
    if (cached) return cached;
    const mode = await effectiveEnforcementMode(this.apiKey, agentId);
    this._modeCache.set(agentId, mode);
    return mode;
  }

  /**
   * Discover Managed Agents under this API key. Returns the canonical
   * agent descriptor (`{ id, name, native }`) — the raw vendor agent
   * stays in `native` for adapters/UI that want richer metadata.
   */
  async listAgents() {
    const raw = await listAgents(this.apiKey);
    return raw.map((a) => ({
      id: a.id,
      name: a.name || null,
      native: a,
    }));
  }

  /**
   * Stream WMAAction entries for a session. Anthropic events are
   * per-session, so opts.sessionId is required — fleet-wide watching is
   * the caller's job (wma-fetch already orchestrates this).
   */
  async *streamEvents(agentId, { sessionId, model } = {}) {
    if (!sessionId) {
      throw new Error('AnthropicManagedSource.streamEvents requires opts.sessionId — Anthropic events are scoped to a session');
    }
    yield* fetchSessionEntries({
      apiKey: this.apiKey, agentId, sessionId, model,
    });
  }

  /**
   * Enforce a policy decision against a pending action — v1.0.1 F-4.
   *
   * Routes through the right Anthropic event depending on the agent's
   * effective enforcement mode:
   *   - sync_confirm  (agent has at least one tool with always_ask):
   *       'allow' → user.tool_confirmation { result: allow }
   *       'deny'  → user.tool_confirmation { result: deny }   (pre-execution block)
   *   - sync_interrupt (no always_ask available):
   *       'allow' → no-op (nothing to confirm — the tool already ran or
   *                 will run without a gate)
   *       'deny'  → user.interrupt + optional follow-up message
   *                 (post-hoc termination)
   *
   * Returns { enforced: boolean, mode: string, native_response?: object }
   * where `mode` describes the path taken so the caller can log it.
   *
   * @param {object} action    A WMAAction (must carry session_id and id)
   * @param {object} decision  { decision: 'allow'|'deny', reason?: string }
   */
  async enforce(action, decision) {
    if (!action || typeof action !== 'object') {
      throw new Error('enforce(action, decision): action must be a WMAAction object');
    }
    if (!action.session_id) {
      throw new Error('enforce(action, decision): action.session_id is required');
    }
    if (!action.agent_id) {
      throw new Error('enforce(action, decision): action.agent_id is required');
    }
    if (!decision || (decision.decision !== 'allow' && decision.decision !== 'deny')) {
      throw new Error(`enforce(action, decision): decision must be 'allow' or 'deny' (got ${decision?.decision})`);
    }

    const mode = await this._getEffectiveModeFor(action.agent_id);
    const isToolUse = action.action_type === ACTION_TYPES.TOOL_USE
      || action.action_type === ACTION_TYPES.MCP_TOOL_USE
      || action.action_type === ACTION_TYPES.CUSTOM_TOOL_USE;

    // Path 1 — pre-execution confirmation when the agent supports it AND
    // the pending action is a tool_use (only kind we can pre-block).
    if (mode === ENFORCEMENT_MODES.SYNC_CONFIRM && isToolUse && action.id) {
      if (decision.decision === 'allow') {
        const res = await confirmAllow({
          apiKey: this.apiKey,
          sessionId: action.session_id,
          toolUseId: action.id,
        });
        return { enforced: true, mode: 'confirm_allow', native_response: res };
      }
      const res = await confirmDeny({
        apiKey: this.apiKey,
        sessionId: action.session_id,
        toolUseId: action.id,
        denyMessage: decision.reason,
      });
      return { enforced: true, mode: 'confirm_deny', native_response: res };
    }

    // Path 2 — post-hoc interrupt. The only enforcement available when
    // the agent has no always_ask tools, OR for non-tool actions we
    // can't pre-block.
    if (decision.decision === 'deny') {
      const res = await interruptSession({
        apiKey: this.apiKey,
        sessionId: action.session_id,
        followUpMessage: decision.reason,
      });
      return { enforced: true, mode: 'interrupt', native_response: res };
    }

    // Allow + no pre-gate available = nothing to do at the SDK level.
    return { enforced: false, mode: 'no_op', reason: 'no pre-execution gate available for this action' };
  }
}
