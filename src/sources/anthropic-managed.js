// Anthropic Managed Agents — post-hoc fetcher
// Reads /v1/agents, /v1/sessions, /v1/sessions/{id}/events and yields
// entries in the WatchMyAgents schema (see logger.js EXPORT_FIELDS).
//
// Token attribution policy: token usage is attached to llm_call entries
// only (faithful to Anthropic's per-message usage). tool_use / mcp_tool_use
// carry duration + status but tokens_used = null.

import { request } from 'node:https';
import { URL, URLSearchParams } from 'node:url';

const API_HOST = 'api.anthropic.com';
const BETA = 'managed-agents-2026-04-01';
const VERSION = '2023-06-01';

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

export async function listSessions(apiKey, { agentId, since, limit = 100 } = {}) {
  const sessions = [];
  let after = null;
  while (true) {
    const qs = new URLSearchParams({ limit: String(limit) });
    if (agentId) qs.set('agent_id', agentId);
    if (after) qs.set('after_id', after);
    const data = await getWithRetry(apiKey, `/v1/sessions?${qs}`);
    const page = data.data || data.sessions || [];
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

async function* fetchRawEvents(apiKey, sessionId) {
  let after = null;
  while (true) {
    const qs = new URLSearchParams({ limit: '100' });
    if (after) qs.set('after_id', after);
    const data = await getWithRetry(apiKey, `/v1/sessions/${sessionId}/events?${qs}`);
    const page = data.data || data.events || [];
    for (const ev of page) yield ev;
    if (!data.has_more || page.length === 0) break;
    after = page[page.length - 1]?.id;
    if (!after) break;
  }
}

export { fetchRawEvents };

// Pull a usage object out of any of the shapes Anthropic uses.
function readUsage(ev) {
  return ev.usage || ev.message?.usage || ev.data?.usage || {};
}
// Pull a tool block out of tool_use / mcp_tool_use events.
function readToolBlock(ev) {
  return ev.content_block || ev.tool_use || ev.data?.content_block || ev.data || {};
}

export async function* fetchSessionEntries({ apiKey, agentId, sessionId, model }) {
  const pending = new Map(); // tool_use_id → { ts, name, isMcp }

  for await (const ev of fetchRawEvents(apiKey, sessionId)) {
    const type = ev.type || ev.event || '';
    const ts = ev.created_at || ev.timestamp || new Date().toISOString();
    const base = { framework: 'anthropic-managed', timestamp: ts, agent_id: agentId, session_id: sessionId, status: 'ok' };

    if (type.endsWith('message') || type === 'agent.message' || type === 'message') {
      const u = readUsage(ev);
      const i = u.input_tokens || 0;
      const o = u.output_tokens || 0;
      const cr = u.cache_read_input_tokens || 0;
      const cw = u.cache_creation_input_tokens || 0;
      yield {
        ...base,
        action_type: 'llm_call',
        tool_name: model || 'messages',
        model: model || null,
        input_tokens: i || null,
        output_tokens: o || null,
        cache_read_tokens: cr || null,
        cache_creation_tokens: cw || null,
        tokens_used: (i + o + cr + cw) || null,
      };
    } else if (type === 'agent.thinking' || type === 'thinking') {
      yield { ...base, action_type: 'thinking', tool_name: 'thinking', model: model || null };
    } else if (type === 'agent.tool_use' || type === 'agent.mcp_tool_use' || type === 'tool_use' || type === 'mcp_tool_use') {
      const block = readToolBlock(ev);
      const id = block.id || ev.id;
      if (id) pending.set(id, { ts: Date.parse(ts), name: block.name || 'unknown', isMcp: type.includes('mcp') });
    } else if (type === 'agent.tool_result' || type === 'tool_result') {
      const block = readToolBlock(ev);
      const id = block.tool_use_id || ev.tool_use_id || block.id;
      const start = pending.get(id);
      pending.delete(id);
      const isError = block.is_error === true || ev.is_error === true;
      yield {
        ...base,
        action_type: start?.isMcp ? 'mcp_tool_use' : 'tool_use',
        tool_name: start?.name || block.name || 'unknown',
        duration_ms: start ? Date.parse(ts) - start.ts : null,
        status: isError ? 'error' : 'ok',
        error: isError ? String(block.content || ev.content || 'tool error').slice(0, 500) : null,
      };
    }
    // session.* and other meta-events are not mapped — session_end is
    // emitted by the caller from the TokenTracker aggregate.
  }
}
