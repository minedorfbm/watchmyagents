#!/usr/bin/env node
//
// WMA NDJSON → Guardian action-export.json converter.
//
// Bridges the WMA capture (Watch's local NDJSON of an Anthropic Managed
// Agent's activity) into the input format the Guardian agent in the
// sibling repo `openai-agent-sdk-test` consumes:
//   openai-agent-sdk-test/src/types.ts → actionExportSchema (zod, v1.0)
//
// Goal of the bridge: feed Guardian Core (WGS scoring + policy proposal)
// with REAL data captured by WMA from real Anthropic agents, not just the
// synthetic example fixture `fixtures/example-export.json`.
//
// Zero runtime deps. Plain Node 20+ ESM.
//
// Usage:
//   node tools/wma-to-guardian-export.js \
//     --input <path-to-wma-ndjson> \
//     --output <path-to-guardian-export.json> \
//     [--tenant <tenant-id>]   default: "tenant-local"
//     [--fleet <fleet-id>]     default: "fleet-default"
//     [--agent-type <type>]    default: "generic" — see AGENT_TYPES below
//     [--start <iso-ts>]       optional time-window filter
//     [--end <iso-ts>]         optional time-window filter
//     [--redaction <level>]    default: "pii_masked"
//
// Example flow (end-to-end Anthropic agent observability → Guardian):
//   # 1. WMA captures the agent's activity
//   wma-fetch --agent-id agent_01XaNB4M88ZvcW8FoQ5GC14A --since 1h
//
//   # 2. Convert the captured NDJSON to Guardian's input format
//   node tools/wma-to-guardian-export.js \
//     --input watchmyagents-logs/agent_01XaNB4M88ZvcW8FoQ5GC14A/2026-06-10.ndjson \
//     --output ../openai-agent-sdk-test/exports/deep-researcher-2026-06-10.json \
//     --tenant tenant-arma \
//     --fleet fleet-research \
//     --agent-type data_rag
//
//   # 3. Guardian's watch daemon (running in openai-agent-sdk-test)
//   #    picks up the file from exports/, runs the analysis, writes
//   #    .findings.json + .report.md (markdown) in exports/processed/.
//   #    Already wired in openai-agent-sdk-test/src/watch.ts line 62.

import { readFile, writeFile } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';

// ─── Vocabulary mappings ──────────────────────────────────────────────

// WMA action_type → Guardian event type. The Guardian schema only
// recognizes the set below; everything else is dropped (we don't want
// noise like 'message'/'thinking' polluting the security analysis).
const WMA_TO_GUARDIAN_EVENT = Object.freeze({
  llm_call:            'llm_call',
  tool_use:            'tool_call',
  custom_tool_use:     'tool_call',
  custom_tool_result:  'tool_call', // result event of a custom tool
  mcp_tool_use:        'tool_call',
  user_message:        'user_message',
  user_interrupt:      'user_message', // closest equivalent
  handoff:             'agent_handoff',
  tool_confirmation:   'policy_event',
  session_error:       'tool_call', // surfaced with result.status:"error"
  shield_decision:     'policy_event', // WMA's own enforcement decisions
});

// Tool name → Guardian tool category. Heuristic; mostly for the
// scoring side to flag categories that warrant tighter scrutiny.
function guessToolCategory(toolName) {
  if (!toolName) return 'other';
  const n = String(toolName).toLowerCase();
  if (n === 'bash' || n.includes('shell') || n.includes('exec')) return 'code_exec';
  if (n === 'web_fetch' || n === 'web_search' || n.startsWith('http') || n.includes('fetch')) return 'http';
  if (n.includes('query') || n.includes('sql') || /\.(query|find|select)/.test(n)) return 'database';
  if (n.startsWith('file_') || n === 'read' || n === 'write' || n === 'edit') return 'file_io';
  if (n.includes('email') || n.includes('mail') || n === 'send') return 'email';
  if (n === 'search' || n.endsWith('_search')) return 'search';
  if (n.includes('browser') || n === 'computer') return 'browser';
  if (n.includes('payment') || n.includes('stripe') || n.includes('charge')) return 'payment';
  if (n.includes('secret') || n.includes('vault') || n.includes('credential')) return 'secret_access';
  return 'other';
}

// Heuristic data classification — looks at payload content for PII /
// secret patterns. Defaults to "internal" if nothing surfaces. This is
// intentionally conservative — false negatives are acceptable; false
// positives that promote sensitivity are also acceptable for security
// analysis purposes.
function classifyDataSensitivity(payload) {
  if (payload == null) return 'internal';
  const text = typeof payload === 'string' ? payload : JSON.stringify(payload);
  if (!text || text === '{}' || text === 'null') return 'internal';

  // Secret patterns — highest sensitivity
  if (/sk-[a-zA-Z0-9_-]{20,}/.test(text)) return 'secret';
  if (/(?:api[_-]?key|secret|token|password|bearer)\s*[:=]\s*['"]\S{8,}/i.test(text)) return 'secret';
  if (/-----BEGIN [A-Z ]+PRIVATE KEY-----/.test(text)) return 'secret';
  if (/AKIA[0-9A-Z]{16}/.test(text)) return 'secret'; // AWS access key
  if (/ghp_[A-Za-z0-9]{36}/.test(text)) return 'secret'; // GitHub PAT

  // PII patterns
  if (/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/.test(text)) return 'pii'; // email
  if (/\b\d{3}-\d{2}-\d{4}\b/.test(text)) return 'pii'; // US SSN-shape
  if (/\b(?:\d{4}[\s-]?){3}\d{4}\b/.test(text)) return 'pii'; // credit card
  if (/\b\+?\d{1,3}[\s-]?\(?\d{1,4}\)?[\s-]?\d{3,4}[\s-]?\d{3,4}\b/.test(text)) return 'pii'; // phone

  return 'internal';
}

// Detect external egress — for events that move data out of the agent's
// trust boundary. Drives `network_egress` re-classification.
function isExternalEgress(toolName, input) {
  const cat = guessToolCategory(toolName);
  if (cat === 'http') return true;
  if (cat === 'browser') return true;
  if (cat === 'email') return true;
  if (input && typeof input === 'object') {
    if (typeof input.url === 'string' && /^https?:\/\//.test(input.url)) return true;
    if (typeof input.destination === 'string') return true;
  }
  return false;
}

function hostnameOf(url) {
  try { return new URL(url).hostname; } catch { return undefined; }
}

function sha256Digest(value) {
  if (value == null) return undefined;
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  return 'sha256:' + createHash('sha256').update(text).digest('hex').slice(0, 12);
}

// ─── Per-event mapping ───────────────────────────────────────────────

function mapWmaToGuardianEvent(wma, fallbackIdx) {
  const baseType = WMA_TO_GUARDIAN_EVENT[wma.action_type];
  if (!baseType) return null; // drop unsupported types (message/thinking/state_transition/…)

  const status = wma.status === 'ok' ? 'success'
    : wma.status === 'blocked' ? 'blocked'
    : 'error';

  const guardianEvt = {
    event_id: wma.id || `evt-${String(fallbackIdx).padStart(6, '0')}`,
    timestamp: wma.timestamp,
    agent_id: wma.agent_id || 'unknown',
    type: baseType,
    result: {
      status,
      duration_ms: typeof wma.duration_ms === 'number' ? wma.duration_ms : undefined,
      error_code: wma.error ? String(wma.error).slice(0, 200) : undefined,
    },
  };

  // Optional discriminators that help Guardian's fractal analysis
  if (wma.session_id) guardianEvt.session_id = wma.session_id;
  if (wma.parent_agent_id) guardianEvt.parent_span_id = wma.parent_agent_id;
  if (wma.session_thread_id) guardianEvt.trace_id = wma.session_thread_id;

  // ── tool_call enrichments ────────────────────────────────────────
  if (baseType === 'tool_call' && wma.tool_name) {
    guardianEvt.tool = {
      name: wma.tool_name,
      category: guessToolCategory(wma.tool_name),
    };
    if (wma.input && typeof wma.input === 'object') {
      // Keep params but strip large fields to keep the export portable
      guardianEvt.tool.parameters = trimLargeFields(wma.input);
    }
  }

  // ── LLM call enrichments ─────────────────────────────────────────
  if (baseType === 'llm_call') {
    const io = {};
    if (typeof wma.input_tokens === 'number') io.input_tokens = wma.input_tokens;
    if (typeof wma.output_tokens === 'number') io.output_tokens = wma.output_tokens;
    if (typeof wma.cost_usd === 'number') io.cost_usd = wma.cost_usd;
    if (wma.input != null) io.prompt_digest = sha256Digest(wma.input);
    if (wma.output != null) io.output_digest = sha256Digest(wma.output);
    if (Object.keys(io).length > 0) guardianEvt.io = io;
  }

  // ── security_context inference ───────────────────────────────────
  const ctx = {};
  const classification = classifyDataSensitivity(wma.input || wma.output);
  if (classification !== 'internal') ctx.data_classification = classification;

  const isEgress = baseType === 'tool_call' && isExternalEgress(wma.tool_name, wma.input);
  if (isEgress) {
    // Re-classify as network_egress — Guardian's scoring treats this
    // category with sharper rules.
    guardianEvt.type = 'network_egress';
    ctx.external_egress = true;
    if (wma.input?.url) {
      const host = hostnameOf(wma.input.url);
      if (host) ctx.destination = host;
    }
    // destination_allowlisted: we have no way to know from outside;
    // leave undefined so Guardian falls back to its default scoring.
  }

  if (Object.keys(ctx).length > 0) guardianEvt.security_context = ctx;

  return guardianEvt;
}

// Trim large strings inside the parameters object so the export stays
// manageable (Guardian only needs structure for analysis, not full
// content). Strings > 1024 chars are truncated with a sentinel.
function trimLargeFields(obj, maxStr = 1024) {
  if (obj == null || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(v => trimLargeFields(v, maxStr));
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (typeof v === 'string' && v.length > maxStr) {
      out[k] = v.slice(0, maxStr) + `…[truncated ${v.length - maxStr} chars]`;
    } else if (typeof v === 'object') {
      out[k] = trimLargeFields(v, maxStr);
    } else {
      out[k] = v;
    }
  }
  return out;
}

// ─── CLI ─────────────────────────────────────────────────────────────

function parseArgs() {
  const args = {};
  for (let i = 2; i < process.argv.length; i++) {
    const a = process.argv[i];
    if (a.startsWith('--')) {
      const k = a.slice(2);
      const next = process.argv[i + 1];
      if (next == null || next.startsWith('--')) args[k] = true;
      else { args[k] = next; i++; }
    }
  }
  return args;
}

function usage() {
  process.stderr.write(`\
Usage:
  node tools/wma-to-guardian-export.js \\
    --input <wma-ndjson-path> \\
    --output <guardian-export-json-path> \\
    [--tenant <tenant-id>]      default "tenant-local"
    [--fleet <fleet-id>]        default "fleet-default"
    [--agent-type <type>]       default "generic"
                                one of: ${AGENT_TYPES.join(', ')}
    [--start <iso-timestamp>]   filter events before this
    [--end <iso-timestamp>]     filter events after this
    [--redaction <level>]       default "pii_masked"
                                one of: none, pii_masked, params_hashed, full

Reads WMA NDJSON capture (one event per line, written by wma-fetch /
Watch). Emits a single Guardian-compatible action-export JSON suitable
for openai-agent-sdk-test's Guardian agent.
`);
}

const AGENT_TYPES = [
  'coding', 'devops_infra', 'data_rag', 'customer_facing',
  'browser_web', 'orchestrator', 'workflow_backoffice',
  'personal_assistant', 'transactional_financial', 'generic',
];

async function getWmaVersion() {
  try {
    const here = new URL('.', import.meta.url);
    const pkgUrl = new URL('../package.json', here);
    const pkg = JSON.parse(await readFile(pkgUrl, 'utf8'));
    return pkg.version || 'unknown';
  } catch { return 'unknown'; }
}

async function main() {
  const args = parseArgs();
  if (!args.input || !args.output) { usage(); process.exit(2); }
  if (args['agent-type'] && !AGENT_TYPES.includes(args['agent-type'])) {
    process.stderr.write(`Unknown --agent-type "${args['agent-type']}". Must be one of: ${AGENT_TYPES.join(', ')}\n`);
    process.exit(2);
  }

  const tenant      = args.tenant       || 'tenant-local';
  const fleet       = args.fleet        || 'fleet-default';
  const agentType   = args['agent-type'] || 'generic';
  const redaction   = args.redaction    || 'pii_masked';

  const raw = await readFile(args.input, 'utf8');
  const lines = raw.split('\n').map(l => l.trim()).filter(l => l.length > 0);
  if (lines.length === 0) {
    process.stderr.write('Input NDJSON is empty — nothing to convert.\n');
    process.exit(1);
  }

  const wmaEvents = [];
  for (let i = 0; i < lines.length; i++) {
    try { wmaEvents.push(JSON.parse(lines[i])); }
    catch (e) {
      process.stderr.write(`Skipped line ${i + 1}: invalid JSON (${e.message})\n`);
    }
  }

  // Time-window filter
  let filtered = wmaEvents;
  if (args.start) filtered = filtered.filter(e => !e.timestamp || e.timestamp >= args.start);
  if (args.end)   filtered = filtered.filter(e => !e.timestamp || e.timestamp <= args.end);

  if (filtered.length === 0) {
    process.stderr.write('After filtering, 0 events remain — refusing to write empty export.\n');
    process.exit(1);
  }

  // Map to Guardian events; drop unsupported types silently (logged below)
  const mapped = [];
  let dropped = 0;
  for (let i = 0; i < filtered.length; i++) {
    const g = mapWmaToGuardianEvent(filtered[i], i);
    if (g) mapped.push(g);
    else dropped += 1;
  }

  // Distinct agent IDs observed
  const agentIds = [...new Set(filtered.map(e => e.agent_id).filter(Boolean))];

  // Detect provider + model from first event(s) for the agents block
  const firstAgent = filtered.find(e => e.agent_id) || {};
  const firstWithModel = filtered.find(e => e.model);
  const provider = firstAgent.provider || 'anthropic-managed';
  const detectedModel = firstWithModel?.model;

  // Time window — first→last event timestamps observed
  const sorted = [...filtered].sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));
  const start = args.start || sorted[0]?.timestamp || new Date().toISOString();
  const end   = args.end   || sorted[sorted.length - 1]?.timestamp || new Date().toISOString();

  const guardianExport = {
    schema_version: '1.0',
    export: {
      export_id: randomUUID(),
      generated_at: new Date().toISOString(),
      source: `wma-sdk@${await getWmaVersion()}`,
      time_window: { start, end },
      redaction_level: redaction,
    },
    fractal_context: {
      tenant_id: tenant,
      fleet_id: fleet,
      teams: [],
      agents: agentIds.map(id => ({
        agent_id: id,
        agent_type: agentType,
        model: detectedModel || undefined,
        autonomy_level: 'autonomous',
        modifiers: undefined, // operator can hand-edit; leaving null avoids false positives
      })),
    },
    events: mapped,
  };

  await writeFile(args.output, JSON.stringify(guardianExport, null, 2) + '\n');

  // Report on stderr so stdout stays clean for piping
  process.stderr.write(`Converted ${mapped.length} events → ${args.output}\n`);
  if (dropped > 0) process.stderr.write(`  Dropped ${dropped} events with unsupported action_type (e.g. message, thinking, state_transition)\n`);
  process.stderr.write(`  Provider     : ${provider}\n`);
  process.stderr.write(`  Agents       : ${agentIds.join(', ') || '(none)'}\n`);
  if (detectedModel) process.stderr.write(`  Model        : ${detectedModel}\n`);
  process.stderr.write(`  Time window  : ${start} → ${end}\n`);
  process.stderr.write(`  Tenant/Fleet : ${tenant} / ${fleet}\n`);
  process.stderr.write(`\nNext step:\n`);
  process.stderr.write(`  cp ${args.output} ../openai-agent-sdk-test/exports/\n`);
  process.stderr.write(`  cd ../openai-agent-sdk-test && npm run watch\n`);
  process.stderr.write(`  # Guardian writes ${args.output.split('/').pop().replace('.json', '')}.report.md in exports/processed/\n`);
}

main().catch(err => {
  process.stderr.write(`Conversion failed: ${err.stack || err.message}\n`);
  process.exit(1);
});
