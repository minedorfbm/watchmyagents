#!/usr/bin/env node
// wma-agents — discover all Managed Agents under your key and classify each
// agent's typology from its OBSERVED behaviour (for Shield template selection).
//
// Usage:
//   wma-agents [list] [--log-dir ~/.watchmyagents/logs] [--json]
//
// Reads the local Watch logs (NEVER leaves the machine — Modèle C) and derives
// the anonymized behavioural FEATURE VECTOR per the typology spec:
//   per-tool-category FRACTIONS (f_*), boolean local flags (flag_*), aux ratios
//   (aux_*), and n_events. It then calls classifyAgentType() and prints the
//   schema-conformant result. With <50 events an agent is `generic` (cold start)
//   and refines as activity accumulates.
//
// Modèle C invariant: only counts/ratios/flags are computed here — never raw
// prompt/output content, never the agent display name. Nothing is transmitted.
//
// ANTHROPIC_API_KEY from env (or --api-key, discouraged).

import os from 'node:os';
import { readdir, stat } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { join, resolve } from 'node:path';
import { listAgents } from '../src/sources/anthropic-managed.js';
import { classifyAgentType } from '../src/typology.js';
import { isValidAgentId, assertSafePathSegment } from '../src/validate.js';

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const k = a.slice(2); const n = argv[i + 1];
      if (n == null || n.startsWith('--')) out[k] = true; else { out[k] = n; i++; }
    } else out._.push(a);
  }
  return out;
}
function die(msg, code = 1) { process.stderr.write(`error: ${msg}\n`); process.exit(code); }
function info(msg) { process.stdout.write(`[wma-agents] ${msg}\n`); }

// Action types that represent a TOOL invocation (the denominator for f_* tool
// fractions). Confirmed produced by src/sources/anthropic-managed.js.
const TOOL_ACTIONS = new Set(['tool_use', 'mcp_tool_use', 'custom_tool_use']);

// ──────────────────────────────────────────────────────────────────────────
// Tool-name → category mapping (Modèle C: name-based, no content). Managed
// Agents expose tools as an opaque bundle, so tool_name is free-text. We match
// the confirmed built-ins (web_search, web_fetch, bash) plus best-effort
// regexes for common tool names. A tool that matches nothing contributes to the
// denominator but to no category (honest: unknown ≠ inferred).
// ──────────────────────────────────────────────────────────────────────────
const CATEGORY_RULES = [
  // category,    matcher (lower-cased tool_name)
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

function categoryOf(toolName) {
  const n = String(toolName || '').toLowerCase();
  for (const [cat, m] of CATEGORY_RULES) if (m(n)) return cat;
  return null;
}

// Aggregate raw counts from an agent's local NDJSON logs (Modèle C: counts only).
async function aggregate(logDir, agentId) {
  const actionCounts = {};       // action_type → count
  const categoryCounts = {};     // tool category → count
  let toolEvents = 0;            // denominator for f_* fractions
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

// Features that the WMA NDJSON logs CANNOT reliably expose today (opaque tool
// names / no behavioural signal / content off-limits under Modèle C). They
// default to 0/false; the caller prints a one-line note.
const NON_DERIVABLE = [
  'f_database', 'f_email', 'f_payment', 'f_secret', 'f_memory',
  'flag_internal_sys', 'flag_on_behalf', 'aux_untrusted', 'aux_sensitive',
];

// Build the canonical anonymized FEATURE VECTOR from the aggregated counts.
// Fractions = category_count / toolEvents. n_events = total observed events.
function buildFeatures(agg) {
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

  // aux_autonomy ≈ 1 − (human-in-the-loop event share). Confirmed action_types
  // user_message / user_interrupt / tool_confirmation mark human involvement; an
  // agent that proceeds without them is more autonomous. Heuristic — documented.
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

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args._[0] && args._[0] !== 'list') die(`unknown command "${args._[0]}" (only "list" supported)`);
  const apiKey = args['api-key'] || process.env.ANTHROPIC_API_KEY;
  if (!apiKey) die('--api-key or ANTHROPIC_API_KEY required');
  if (args['api-key']) process.stderr.write('[wma-agents] WARNING: --api-key is visible in shell history; prefer ANTHROPIC_API_KEY env\n');
  const logDir = resolve(args['log-dir'] || join(os.homedir(), '.watchmyagents', 'logs'));
  const asJson = !!args.json;

  let agents;
  try { agents = await listAgents(apiKey); }
  catch (e) { die(`failed to list agents: ${e.message}`); }

  const results = [];
  for (const a of agents) {
    if (!a.id || !isValidAgentId(a.id)) continue;
    assertSafePathSegment(a.id, 'agent id');
    const agg = await aggregate(logDir, a.id);
    const features = buildFeatures(agg);
    features.agent_id = a.id;
    // No prior state threaded here (single-shot CLI snapshot); the continuous
    // Watch daemon is responsible for threading window state across runs.
    const cls = classifyAgentType(features);
    results.push({
      id: a.id,
      name: a.name || '(unnamed)',     // shown for the human only — NOT a classification signal
      hasLogs: agg.hasLogs,
      ...cls,
    });
  }

  if (asJson) { process.stdout.write(JSON.stringify(results, null, 2) + '\n'); return; }

  info(`discovered ${results.length} agent(s) - classified from local logs in ${logDir}`);
  info(`Modele C: features below default to 0 (logs don't expose them): ${NON_DERIVABLE.join(', ')}`);
  process.stdout.write('\n');
  for (const r of results) {
    const mods = (r.modifiers && r.modifiers.length) ? ` [+${r.modifiers.join(',')}]` : '';
    const overlay = r.evidence?.payment_overlay ? '  (+transactional overlay)' : '';
    process.stdout.write(`  ${r.name}\n`);
    process.stdout.write(`    ${r.id}\n`);
    process.stdout.write(`    -> ${r.classified_type}  (conf ${Math.round(r.confidence * 100)}%, ${r.stage})${mods}${overlay}\n`);
    process.stdout.write(`    evidence: ${r.evidence.window_events} events, top2=${r.evidence.top2_type}, margin=${r.evidence.margin}\n`);
    if (!r.hasLogs) process.stdout.write('    (no local logs yet - cold start)\n');
    process.stdout.write('\n');
  }
  info('type drives the cold-start Shield template (Guardian Core §8). The global-baseline floor applies regardless of classification.');
}

main().catch((e) => { process.stderr.write(`error: ${e.stack || e.message}\n`); process.exit(1); });
