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

const API_HOST = 'api.anthropic.com';
const BETA = 'managed-agents-2026-04-01';
const VERSION = '2023-06-01';
// Hard cap on any single GET so a hung connection can't pin Watch/Shield
// forever. getWithRetry will retry on timeout (the error propagates here).
const REQUEST_TIMEOUT_MS = 30_000;

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
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
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

export async function listSessions(apiKey, { agentId, since, limit = 100 } = {}) {
  const sessions = [];
  let after = null;
  while (true) {
    const qs = new URLSearchParams({ limit: String(limit) });
    if (agentId) qs.set('agent_id', agentId);
    if (after) qs.set('after_id', after);
    const data = await getWithRetry(apiKey, `/v1/sessions?${qs}`);
    const page = data.data || [];
    let stop = false;
    for (const s of page) {
      const created = s.created_at ? new Date(s.created_at) : null;
      if (since && created && created < since) { stop = true; break; }
      sessions.push(s);
    }
    if (stop || !data.has_more || page.length === 0) break;
    after = page[page.length - 1]?.id;
    if (!after) break;
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

export async function* fetchSessionEntries({ apiKey, agentId, sessionId, model }) {
  // Pair-tracking maps: event_id of the "start" → its timestamp + metadata
  const pendingModelReq = new Map();    // span.model_request_start.id → ts
  const pendingToolUse = new Map();     // agent.tool_use.id → { ts, name, isMcp, input }

  const base = { framework: 'anthropic-managed', agent_id: agentId, session_id: sessionId };

  // No server-side `types[]` filter: the API rejects unknown values, but the
  // exact filterable set is undocumented & evolves. We pull everything and
  // filter here, ensuring future event types are surfaced rather than dropped.
  const RELEVANT = new Set(RELEVANT_TYPES);
  for await (const ev of fetchRawEvents(apiKey, sessionId)) {
    if (!RELEVANT.has(ev.type)) continue;
    const type = ev.type;
    const ts = ev.processed_at || ev.created_at || new Date().toISOString();
    const tsMillis = tsMs(ev);

    if (type === 'span.model_request_start') {
      pendingModelReq.set(ev.id, tsMillis);
      continue;
    }
    if (type === 'span.model_request_end') {
      const startTs = pendingModelReq.get(ev.model_request_start_id);
      pendingModelReq.delete(ev.model_request_start_id);
      const u = ev.model_usage || {};
      const i = u.input_tokens || 0;
      const o = u.output_tokens || 0;
      const cr = u.cache_read_input_tokens || 0;
      const cw = u.cache_creation_input_tokens || 0;
      yield {
        ...base,
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
        name: ev.name || 'unknown',
        isMcp: type === 'agent.mcp_tool_use',
        input: ev.input ?? null,
        mcpServer: ev.server_name ?? ev.mcp_server_name ?? null,
      });
      continue;
    }
    if (type === 'agent.tool_result' || type === 'agent.mcp_tool_result') {
      const start = pendingToolUse.get(ev.tool_use_id);
      pendingToolUse.delete(ev.tool_use_id);
      const isError = ev.is_error === true;
      yield {
        ...base,
        id: ev.id,
        action_type: start?.isMcp ? 'mcp_tool_use' : 'tool_use',
        tool_name: start?.name || 'unknown',
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
        id: ev.id,
        action_type: 'custom_tool_use',
        tool_name: ev.name || 'unknown',
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
      yield {
        ...base,
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
}

function extractText(content) {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content.map(b => (typeof b === 'string' ? b : (b?.text || JSON.stringify(b)))).join(' ');
  }
  if (content && typeof content === 'object') return content.text || JSON.stringify(content);
  return '';
}
