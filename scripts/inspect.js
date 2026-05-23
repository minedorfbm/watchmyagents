#!/usr/bin/env node
// WatchMyAgents log inspector
// Usage:
//   node scripts/inspect.js [path]
//
// path can be:
//   - a single .ndjson file
//   - a directory (recursively scans for .ndjson)
//   - omitted → defaults to ./watchmyagents-logs

import { readFile, readdir, stat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { TokenTracker } from '../src/tokens.js';

const target = resolve(process.argv[2] || './watchmyagents-logs');

async function collectFiles(p) {
  const s = await stat(p).catch(() => null);
  if (!s) return [];
  if (s.isFile()) return p.endsWith('.ndjson') ? [p] : [];
  const out = [];
  for (const name of await readdir(p)) {
    out.push(...(await collectFiles(join(p, name))));
  }
  return out;
}

function fmt(n) { return n.toLocaleString('en-US'); }
function ms(n) { return n == null ? '—' : `${n.toLocaleString('en-US')} ms`; }
function usd(n) { return `$${(n || 0).toFixed(6)}`; }

async function main() {
  const files = await collectFiles(target);
  if (files.length === 0) {
    process.stderr.write(`No .ndjson files found under ${target}\n`); process.exit(1);
  }

  const tracker = new TokenTracker();
  const entries = [];
  const errors = [];
  const sessionEnds = [];
  const bySession = new Map();
  const byStatus = { ok: 0, error: 0 };
  let firstTs = null, lastTs = null;

  for (const f of files) {
    const raw = await readFile(f, 'utf8');
    for (const line of raw.split('\n')) {
      if (!line.trim()) continue;
      let e; try { e = JSON.parse(line); } catch { continue; }
      entries.push(e);
      tracker.record(e);
      byStatus[e.status] = (byStatus[e.status] || 0) + 1;
      if (e.status === 'error') errors.push(e);
      if (e.action_type === 'session_end') sessionEnds.push(e);
      if (e.session_id) bySession.set(e.session_id, (bySession.get(e.session_id) || 0) + 1);
      if (!firstTs || e.timestamp < firstTs) firstTs = e.timestamp;
      if (!lastTs || e.timestamp > lastTs) lastTs = e.timestamp;
    }
  }

  const stats = tracker.stats();
  const t = stats.total;
  const durationMs = firstTs && lastTs ? new Date(lastTs) - new Date(firstTs) : 0;

  const out = [];
  out.push('━━━ WatchMyAgents log inspector ━━━');
  out.push(`source           : ${target}`);
  out.push(`files scanned    : ${files.length}`);
  out.push(`entries          : ${fmt(entries.length)}`);
  out.push(`sessions         : ${bySession.size} (session_end entries: ${sessionEnds.length})`);
  out.push(`window           : ${firstTs || '—'} → ${lastTs || '—'}`);
  out.push(`elapsed          : ${ms(durationMs)}`);
  out.push(`status           : ok=${byStatus.ok || 0}  error=${byStatus.error || 0}`);
  out.push('');
  out.push('── Tokens ──');
  out.push(`total            : ${fmt(t.sum)}  (in=${fmt(t.input)} out=${fmt(t.output)} cache_r=${fmt(t.cache_read)} cache_w=${fmt(t.cache_creation)})`);
  out.push(`estimated cost   : ${usd(t.cost_usd)}`);
  out.push('');

  const topRows = (obj, label, max = 10) => {
    const rows = Object.entries(obj)
      .sort((a, b) => b[1].sum - a[1].sum)
      .slice(0, max);
    if (rows.length === 0) return;
    out.push(`── By ${label} ──`);
    for (const [k, v] of rows) {
      out.push(`  ${k.padEnd(40)} calls=${String(v.calls).padStart(4)}  tokens=${String(v.sum).padStart(8)}  cost=${usd(v.cost_usd)}`);
    }
    out.push('');
  };
  topRows(stats.by_tool, 'tool');
  topRows(stats.by_action, 'action_type');
  topRows(stats.by_model, 'model');

  if (errors.length) {
    out.push(`── Errors (${errors.length}) ──`);
    for (const e of errors.slice(0, 10)) {
      out.push(`  [${e.timestamp}] ${e.tool_name || e.action_type}: ${e.error}`);
    }
    if (errors.length > 10) out.push(`  … and ${errors.length - 10} more`);
    out.push('');
  }

  const slowest = entries
    .filter(e => typeof e.duration_ms === 'number')
    .sort((a, b) => b.duration_ms - a.duration_ms).slice(0, 5);
  if (slowest.length) {
    out.push('── Slowest actions ──');
    for (const e of slowest) {
      out.push(`  ${ms(e.duration_ms).padStart(12)}  ${e.action_type.padEnd(14)} ${e.tool_name || ''}`);
    }
    out.push('');
  }

  for (const se of sessionEnds) {
    const st = se.session_tokens || {};
    out.push(`── Session ${se.session_id.slice(0, 8)} (from session_end) ──`);
    out.push(`  tokens : total=${fmt(st.total || 0)} in=${fmt(st.input || 0)} out=${fmt(st.output || 0)} cache_r=${fmt(st.cache_read || 0)} cache_w=${fmt(st.cache_creation || 0)}`);
    out.push(`  cost   : ${usd(se.session_cost_usd)}`);
    out.push('');
  }

  process.stdout.write(out.join('\n') + '\n');
}

main().catch(e => { process.stderr.write(`error: ${e.stack || e.message}\n`); process.exit(1); });
