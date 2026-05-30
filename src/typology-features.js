// Shared local-log feature extraction for the typology classifier (Modèle C).
// Both wma-agents (CLI snapshot) and the Watch daemon (continuous upload) use
// this to derive the anonymized behavioural FEATURE VECTOR from local NDJSON
// logs, then feed it to classifyAgentType() in ./typology.js.
//
// Modèle C invariant: only `action_type` and `tool_name` are read from each log
// line — the raw payload fields (input/output/content/error/thinking) are NEVER
// touched here, so no raw content can ever enter a feature.

import { readdir, stat } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { join } from 'node:path';

// Action types that represent a TOOL invocation (denominator for f_* fractions).
const TOOL_ACTIONS = new Set(['tool_use', 'mcp_tool_use', 'custom_tool_use']);

// Tool-name → category mapping. Anthropic Managed Agents expose tools as an
// opaque bundle, so tool_name is free-text. We match the confirmed built-ins
// (web_search, web_fetch, bash) plus best-effort regexes for common tool names.
// A tool that matches nothing contributes to the denominator but to no category
// (honest: unknown ≠ inferred).
const CATEGORY_RULES = [
  ['search',   (n) => /(^|_)web_search$|(^|_)search($|_)|google|brave/.test(n)],
  ['browser',  (n) => /web_fetch|browser|playwright|puppeteer|navigate|screenshot/.test(n)],
  ['http',     (n) => /(^|_)http|fetch_url|curl|request|webhook|api_call/.test(n)],
  ['code',     (n) => /bash|shell|terminal|code_exec|exec_|python|node_run|run_code|interpreter/.test(n)],
  ['database', (n) => /sql|query_db|database|postgres|mysql|mongo|redis|bigquery|snowflake/.test(n)],
  ['email',    (n) => /email|gmail|smtp|sendmail|mailgun|outlook/.test(n)],
  ['payment',  (n) => /payment|charge|transfer|invoice|stripe|paypal|payout|refund|checkout/.test(n)],
  ['secret',   (n) => /secret|vault|credential|kms|keychain|token_get/.test(n)],
  ['memory',   (n) => /memory|retriev|vector|(^|_)rag($|_)|knowledge|embed|pinecone|chroma/.test(n)],
  ['file',     (n) => /editor|str_replace|read_file|write_file|create_file|file_io|(^|_)file($|_)|fs_/.test(n)],
];

// Best-effort deploy detection (spec discriminator devops_infra vs coding).
const DEPLOY_RE = /deploy|terraform|kubectl|helm|(^|_)release($|_)|ansible|pulumi|cloudformation/;

// Features that the WMA NDJSON logs CANNOT reliably expose today (opaque tool
// names, no behavioural signal, or raw content off-limits under Modèle C).
// They default to 0/false; callers can surface this to the user.
export const NON_DERIVABLE = [
  'f_database', 'f_email', 'f_payment', 'f_secret', 'f_memory',
  'flag_internal_sys', 'flag_on_behalf', 'aux_untrusted', 'aux_sensitive',
];

function categoryOf(toolName) {
  const n = String(toolName || '').toLowerCase();
  for (const [cat, m] of CATEGORY_RULES) if (m(n)) return cat;
  return null;
}

// Aggregate raw counts from an agent's local NDJSON logs. Returns `hasLogs:false`
// when there's nothing to read (cold start).
export async function aggregate(logDir, agentId) {
  const actionCounts = {};
  const categoryCounts = {};
  let toolEvents = 0;
  let deployUses = 0;
  const dir = join(logDir, agentId);
  const s = await stat(dir).catch(() => null);
  if (!s || !s.isDirectory()) return { actionCounts, categoryCounts, toolEvents, deployUses, hasLogs: false };
  let names;
  try { names = await readdir(dir); } catch { return { actionCounts, categoryCounts, toolEvents, deployUses, hasLogs: false }; }
  const files = names.filter((n) => n.endsWith('.ndjson') && !n.startsWith('raw-'));
  if (files.length === 0) return { actionCounts, categoryCounts, toolEvents, deployUses, hasLogs: false };

  for (const f of files) {
    await new Promise((res) => {
      const rl = createInterface({ input: createReadStream(join(dir, f), { encoding: 'utf8' }), crlfDelay: Infinity });
      rl.on('line', (line) => {
        if (!line.trim()) return;
        let e; try { e = JSON.parse(line); } catch { return; }
        if (e.action_type) actionCounts[e.action_type] = (actionCounts[e.action_type] || 0) + 1;
        if (TOOL_ACTIONS.has(e.action_type)) {
          toolEvents += 1;
          const cat = categoryOf(e.tool_name);
          if (cat) categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
          if (DEPLOY_RE.test(String(e.tool_name || '').toLowerCase())) deployUses += 1;
        }
      });
      rl.on('close', res); rl.on('error', res);
    });
  }
  return { actionCounts, categoryCounts, toolEvents, deployUses, hasLogs: true };
}

// Build the canonical anonymized FEATURE VECTOR from the aggregated counts.
// fractions f_* = category_count / toolEvents ; event fractions = type_count /
// nEvents ; flags 0/1 ; aux ratios in [0,1] ; n_events = total observed events.
export function buildFeatures(agg) {
  const { actionCounts, categoryCounts, toolEvents, deployUses } = agg;
  const nEvents = Object.values(actionCounts).reduce((a, b) => a + b, 0);
  const frac = (c) => (toolEvents > 0 ? (categoryCounts[c] || 0) / toolEvents : 0);
  const eventFrac = (...types) => (nEvents > 0
    ? types.reduce((a, t) => a + (actionCounts[t] || 0), 0) / nEvents
    : 0);

  // f_handoff / f_user_msg are derived from event TYPE (not tool category):
  // confirmed action_types thread_message_* and user_message.
  const handoff = eventFrac('thread_message_sent', 'thread_message_received', 'thread_created');
  const userMsg = eventFrac('user_message');

  // aux_autonomy ≈ 1 − (human-in-the-loop event share). user_message /
  // user_interrupt / tool_confirmation mark human involvement.
  const hitlShare = eventFrac('user_message', 'user_interrupt', 'tool_confirmation');
  const auxAutonomy = nEvents > 0 ? Math.max(0, 1 - hitlShare) : 0;

  return {
    // tool-category fractions (over tool uses)
    f_code: frac('code'),
    f_browser: frac('browser'),
    f_database: frac('database'),     // non-derivable in practice → ~0
    f_http: frac('http'),
    f_email: frac('email'),           // non-derivable in practice → ~0
    f_payment: frac('payment'),       // non-derivable in practice → ~0
    f_secret: frac('secret'),         // non-derivable in practice → ~0
    f_search: frac('search'),
    f_memory: frac('memory'),         // non-derivable in practice → ~0
    f_file: frac('file'),
    // event-type fractions (over all events)
    f_handoff: handoff,
    f_user_msg: userMsg,
    // discriminator flags (best-effort; only flag_deploy has any behavioural
    // signal — and only if the agent literally names a deploy tool).
    flag_deploy: deployUses > 0 ? 1 : 0,
    flag_internal_sys: 0,             // no behavioural signal in logs
    flag_on_behalf: 0,                // no behavioural signal in logs
    // aux ratios
    aux_autonomy: auxAutonomy,        // heuristic (HITL-frequency)
    aux_untrusted: 0,                 // no honest source in logs
    aux_sensitive: 0,                 // no honest source in logs
    // window size
    n_events: nEvents,
  };
}
