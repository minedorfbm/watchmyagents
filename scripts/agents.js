#!/usr/bin/env node
// wma-agents — discover all Managed Agents under your key and classify each
// agent's typology from its OBSERVED behaviour (for Shield template selection).
//
// Usage:
//   wma-agents [list] [--log-dir ~/.watchmyagents/logs] [--json]
//
// Reads the local Watch logs (NEVER leaves the machine — Containment) and derives
// the anonymized behavioural FEATURE VECTOR per the typology spec:
//   per-tool-category FRACTIONS (f_*), boolean local flags (flag_*), aux ratios
//   (aux_*), and n_events. It then calls classifyAgentType() and prints the
//   schema-conformant result. With <50 events an agent is `generic` (cold start)
//   and refines as activity accumulates.
//
// Containment invariant: only counts/ratios/flags are computed here — never raw
// prompt/output content, never the agent display name. Nothing is transmitted.
//
// ANTHROPIC_API_KEY from env (or --api-key, discouraged).

import os from 'node:os';
import { join, resolve } from 'node:path';
import { listAgents } from '../src/sources/anthropic-managed.js';
import { classifyAgentType } from '../src/typology.js';
import { aggregate, buildFeatures, NON_DERIVABLE } from '../src/typology-features.js';
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

// Feature aggregation lives in src/typology-features.js (shared with the Watch
// daemon so both CLI snapshot and continuous upload use the same Containment
// extraction). The rest of this file is just CLI presentation.

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
  info(`Containment: features below default to 0 (logs don't expose them): ${NON_DERIVABLE.join(', ')}`);
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
