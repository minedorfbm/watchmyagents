// Shield enforcement — sends user.tool_confirmation back to Anthropic
// to allow or deny a pending tool call.
//
// Per Anthropic docs (managed-agents-2026-04-01 beta), when a tool requires
// confirmation (via a permission policy on the agent), the session emits
// agent.tool_use and then pauses on session.status_idle with
// stop_reason: requires_action. The user.tool_confirmation event resolves it.

const API_BASE = 'https://api.anthropic.com';
const BETA = 'managed-agents-2026-04-01';
const VERSION = '2023-06-01';
// Enforcement must be snappy: a hung confirm/interrupt would leave the agent
// paused (tool_confirmation) or running (interrupt) indefinitely. Fail fast.
const ENFORCE_TIMEOUT_MS = 15_000;

function authHeaders(apiKey) {
  return {
    'x-api-key': apiKey,
    'anthropic-version': VERSION,
    'anthropic-beta': BETA,
    'content-type': 'application/json',
  };
}

// fetch() has no built-in timeout — without one a stalled connection hangs the
// enforcement path forever. Abort after ENFORCE_TIMEOUT_MS with a clear error.
async function fetchWithTimeout(url, opts = {}, timeoutMs = ENFORCE_TIMEOUT_MS) {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  try {
    return await fetch(url, { ...opts, signal: ac.signal });
  } catch (e) {
    if (ac.signal.aborted) throw new Error(`request to ${url} timed out after ${timeoutMs}ms`);
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

// GET /v1/agents/{id} — used at Shield startup to determine which enforcement
// mode (tool_confirmation vs interrupt) is available.
export async function getAgentConfig(apiKey, agentId) {
  const url = `${API_BASE}/v1/agents/${agentId}`;
  const res = await fetchWithTimeout(url, { headers: authHeaders(apiKey) });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`getAgent failed: HTTP ${res.status}: ${body.slice(0, 300)}`);
  }
  return res.json();
}

// Inspect agent config to determine if any tool/toolset has
// permission_policy.type === "always_ask". When at least one tool does,
// Shield can use the precise tool_confirmation flow. Otherwise it falls
// back to user.interrupt (post-hoc termination).
export function detectAlwaysAsk(agent) {
  const tools = agent?.tools || [];
  const mcp = (agent?.mcp_servers || []).length > 0;
  for (const t of tools) {
    if (t?.default_config?.permission_policy?.type === 'always_ask') return true;
    if (Array.isArray(t?.configs)) {
      for (const c of t.configs) {
        if (c?.permission_policy?.type === 'always_ask') return true;
      }
    }
    // MCP toolsets default to always_ask per Anthropic docs (if any MCP server
    // is attached but no explicit always_allow override is set).
    if (t?.type === 'mcp_toolset' && !t?.default_config?.permission_policy) {
      return true;
    }
  }
  // If the agent has MCP servers but no explicit mcp_toolset config, MCP
  // defaults are always_ask — so we still get requires_action for MCP calls.
  return mcp;
}

async function sendEvents(apiKey, sessionId, events) {
  const url = `${API_BASE}/v1/sessions/${sessionId}/events?beta=true`;
  const res = await fetchWithTimeout(url, {
    method: 'POST',
    headers: authHeaders(apiKey),
    body: JSON.stringify({ events }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`enforce failed: HTTP ${res.status}: ${body.slice(0, 300)}`);
  }
  return res;
}

// Approve a pending tool_use by its event id.
export function confirmAllow({ apiKey, sessionId, toolUseId }) {
  return sendEvents(apiKey, sessionId, [{
    type: 'user.tool_confirmation',
    tool_use_id: toolUseId,
    result: 'allow',
  }]);
}

// Deny a pending tool_use with an explanatory message that surfaces to the
// agent (the agent sees the deny_message in its tool_result).
export function confirmDeny({ apiKey, sessionId, toolUseId, denyMessage }) {
  return sendEvents(apiKey, sessionId, [{
    type: 'user.tool_confirmation',
    tool_use_id: toolUseId,
    result: 'deny',
    deny_message: denyMessage || 'Blocked by Shield policy',
  }]);
}

// Interrupt the entire session (stops the agent loop). Used for serious
// policy violations where letting the agent continue is unsafe.
export function interruptSession({ apiKey, sessionId, followUpMessage }) {
  const events = [{ type: 'user.interrupt' }];
  if (followUpMessage) {
    events.push({
      type: 'user.message',
      content: [{ type: 'text', text: followUpMessage }],
    });
  }
  return sendEvents(apiKey, sessionId, events);
}
