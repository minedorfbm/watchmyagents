#!/usr/bin/env node
// WatchMyAgents log inspector
// Usage:
//   node scripts/inspect.js [path]
//
// path can be:
//   - a single .ndjson file
//   - a directory (recursively scans for .ndjson)
//   - omitted → defaults to ./watchmyagents-logs

import { readdir, stat } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { join, resolve } from 'node:path';
import { TokenTracker } from '../src/tokens.js';

// Streaming line-by-line reader — bounds memory usage on large NDJSON files
// (a long-running agent can produce hundreds of MB per day).
async function* readNdjsonLines(path) {
  const stream = createReadStream(path, { encoding: 'utf8' });
  const rl = createInterface({ input: stream, crlfDelay: Infinity });
  for await (const line of rl) {
    if (line.trim()) yield line;
  }
}

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
function pct(num, den) { return den ? `${((num / den) * 100).toFixed(1)}%` : '—'; }
function truncate(s, n) { s = String(s); return s.length > n ? s.slice(0, n - 1) + '…' : s; }

function percentile(arr, p) {
  if (arr.length === 0) return null;
  const sorted = [...arr].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx];
}

// Best-effort destination extraction from a tool_use input payload.
// Returns a short identifier of *what* the tool acted on (URL, query, path…).
function extractDestination(input) {
  if (input == null) return null;
  if (typeof input === 'string') return truncate(input, 60);
  if (typeof input !== 'object') return null;
  const url = input.url || input.uri || input.endpoint;
  if (url) return truncate(url, 60);
  if (input.query) return `"${truncate(input.query, 60)}"`;
  if (input.path || input.file_path) return truncate(input.path || input.file_path, 60);
  if (input.command) return `$ ${truncate(input.command, 60)}`;
  // Fallback: stringify first key/value
  const k = Object.keys(input)[0];
  return k ? `${k}=${truncate(JSON.stringify(input[k]), 50)}` : null;
}

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
  const models = new Set();
  let firstTs = null, lastTs = null;

  for (const f of files) {
    for await (const line of readNdjsonLines(f)) {
      let e; try { e = JSON.parse(line); } catch { continue; }
      entries.push(e);
      tracker.record(e);
      byStatus[e.status] = (byStatus[e.status] || 0) + 1;
      if (e.status === 'error') errors.push(e);
      if (e.action_type === 'session_end') sessionEnds.push(e);
      if (e.session_id) bySession.set(e.session_id, (bySession.get(e.session_id) || 0) + 1);
      if (e.model) models.add(typeof e.model === 'object' ? (e.model.id || JSON.stringify(e.model)) : e.model);
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
  out.push(`model            : ${models.size ? [...models].join(', ') : '—'}`);
  out.push(`window           : ${firstTs || '—'} → ${lastTs || '—'}`);
  out.push(`elapsed          : ${ms(durationMs)}`);
  out.push(`status           : ok=${byStatus.ok || 0}  error=${byStatus.error || 0}`);
  out.push('');
  out.push('── Tokens ──');
  out.push(`total            : ${fmt(t.sum)}  (in=${fmt(t.input)} out=${fmt(t.output)} cache_r=${fmt(t.cache_read)} cache_w=${fmt(t.cache_creation)})`);
  out.push('');

  const topRows = (obj, label, max = 10) => {
    const rows = Object.entries(obj)
      .sort((a, b) => b[1].sum - a[1].sum)
      .slice(0, max);
    if (rows.length === 0) return;
    out.push(`── By ${label} ──`);
    for (const [k, v] of rows) {
      out.push(`  ${k.padEnd(40)} calls=${String(v.calls).padStart(4)}  tokens=${String(v.sum).padStart(8)}`);
    }
    out.push('');
  };
  topRows(stats.by_tool, 'tool');
  topRows(stats.by_action, 'action_type');
  // "By model" is redundant when only one model is in use — shown in the header.
  if (Object.keys(stats.by_model).length > 1) topRows(stats.by_model, 'model');

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

  // ── Security Section 1: Top destinations (URLs / queries / paths) ──
  // Reveals where the agent reached: data exfiltration targets, repeated
  // queries (replay), unexpected hosts. Aggregated per (tool_name, destination).
  const destCounts = new Map();
  for (const e of entries) {
    if (!e.tool_name || (e.action_type !== 'tool_use' && e.action_type !== 'mcp_tool_use' && e.action_type !== 'custom_tool_use')) continue;
    const dest = extractDestination(e.input);
    if (!dest) continue;
    const key = `${e.tool_name}\t${dest}`;
    destCounts.set(key, (destCounts.get(key) || 0) + 1);
  }
  if (destCounts.size) {
    out.push('── Top destinations (tool inputs) ──');
    const rows = [...destCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
    for (const [k, n] of rows) {
      const [tool, dest] = k.split('\t');
      out.push(`  ${String(n).padStart(3)}×  ${tool.padEnd(16)} ${dest}`);
    }
    out.push('');
  }

  // ── Security Section 2: Action sequences (Markov transitions) ──
  // Reveals attack patterns: e.g. "tool_use(web_fetch) → tool_use(bash)" or
  // "context_compacted → message" (loss of safety context).
  const sorted = [...entries].sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));
  const seqCounts = new Map();
  for (let i = 0; i < sorted.length - 1; i++) {
    const a = sorted[i], b = sorted[i + 1];
    if (a.action_type === 'session_end' || b.action_type === 'session_end') continue;
    if (a.session_id && b.session_id && a.session_id !== b.session_id) continue;
    const key = `${a.action_type} → ${b.action_type}`;
    seqCounts.set(key, (seqCounts.get(key) || 0) + 1);
  }
  if (seqCounts.size) {
    out.push('── Action sequences (top transitions) ──');
    const rows = [...seqCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
    const totalSeq = [...seqCounts.values()].reduce((s, n) => s + n, 0);
    for (const [k, n] of rows) {
      out.push(`  ${String(n).padStart(3)}×  ${pct(n, totalSeq).padStart(5)}  ${k}`);
    }
    out.push('');
  }

  // ── Security Section 3: Tool error rate ──
  // High error rate on a tool may signal exploit attempts (malformed inputs).
  const toolStats = new Map();
  for (const e of entries) {
    if (!e.tool_name) continue;
    const s = toolStats.get(e.tool_name) || { calls: 0, errors: 0, durations: [] };
    s.calls++;
    if (e.status === 'error') s.errors++;
    if (typeof e.duration_ms === 'number') s.durations.push(e.duration_ms);
    toolStats.set(e.tool_name, s);
  }
  const toolsWithErrors = [...toolStats.entries()].filter(([, s]) => s.errors > 0);
  if (toolsWithErrors.length) {
    out.push('── Tool error rate ──');
    for (const [name, s] of toolsWithErrors.sort((a, b) => b[1].errors - a[1].errors)) {
      out.push(`  ${name.padEnd(20)} ${s.errors}/${s.calls}  (${pct(s.errors, s.calls)})`);
    }
    out.push('');
  }

  // ── Security Section 4: Tool latency p50/p95 ──
  // Outliers can hide exfiltration via timing channels or compromised MCPs.
  const toolsWithLatency = [...toolStats.entries()].filter(([, s]) => s.durations.length > 0);
  if (toolsWithLatency.length) {
    out.push('── Tool latency ──');
    for (const [name, s] of toolsWithLatency.sort((a, b) => percentile(b[1].durations, 95) - percentile(a[1].durations, 95))) {
      const p50 = percentile(s.durations, 50);
      const p95 = percentile(s.durations, 95);
      const maxv = Math.max(...s.durations);
      out.push(`  ${name.padEnd(20)} n=${String(s.durations.length).padStart(3)}  p50=${ms(p50).padStart(10)}  p95=${ms(p95).padStart(10)}  max=${ms(maxv).padStart(10)}`);
    }
    out.push('');
  }

  // ── Security Section 5: Rate metrics ──
  // Helps detect abuse loops, runaway agents, or cost spikes.
  if (durationMs > 0) {
    const minutes = durationMs / 60000;
    out.push('── Rate metrics ──');
    out.push(`  tokens/min       : ${fmt(Math.round(t.sum / minutes))}`);
    out.push(`  calls/min        : ${(entries.length / minutes).toFixed(2)}`);
    out.push(`  llm_calls/min    : ${((stats.by_action.llm_call?.calls || 0) / minutes).toFixed(2)}`);
    out.push('');
  }

  for (const se of sessionEnds) {
    const st = se.session_tokens || {};
    out.push(`── Session ${se.session_id.slice(0, 8)} (from session_end) ──`);
    out.push(`  tokens : total=${fmt(st.total || 0)} in=${fmt(st.input || 0)} out=${fmt(st.output || 0)} cache_r=${fmt(st.cache_read || 0)} cache_w=${fmt(st.cache_creation || 0)}`);
    out.push('');
  }

  process.stdout.write(out.join('\n') + '\n');
}

main().catch(e => { process.stderr.write(`error: ${e.stack || e.message}\n`); process.exit(1); });
