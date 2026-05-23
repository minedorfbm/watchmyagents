#!/usr/bin/env node
// wma-fetch — pull session events from Anthropic Managed Agents and
// write them as WatchMyAgents NDJSON, ready for `wma-inspect`.
//
// Usage:
//   wma-fetch --agent-id agent_xxx [--session-id sess_xxx] [--since 1h]
//             [--log-dir ./watchmyagents-logs] [--dump-raw]
//
// API key is read from --api-key or env ANTHROPIC_API_KEY.

import { mkdir, appendFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { Logger } from '../src/logger.js';
import { TokenTracker } from '../src/tokens.js';
import {
  getAgent, listSessions, fetchSessionEntries, fetchRawEvents,
} from '../src/sources/anthropic-managed.js';

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const k = a.slice(2);
      const n = argv[i + 1];
      if (n == null || n.startsWith('--')) out[k] = true;
      else { out[k] = n; i++; }
    }
  }
  return out;
}

function parseSince(s) {
  if (!s || s === true) return null;
  const m = String(s).match(/^(\d+)\s*([smhd])$/);
  if (m) {
    const n = parseInt(m[1], 10);
    const mult = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }[m[2]];
    return new Date(Date.now() - n * mult);
  }
  const d = new Date(s);
  if (isNaN(d)) throw new Error(`invalid --since value: ${s}`);
  return d;
}

function die(msg, code = 1) { process.stderr.write(`${msg}\n`); process.exit(code); }

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const apiKey = args['api-key'] || process.env.ANTHROPIC_API_KEY;
  const agentId = args['agent-id'];
  const sessionId = args['session-id'];
  const since = args.since ? parseSince(args.since) : null;
  const logDir = resolve(args['log-dir'] || './watchmyagents-logs');
  const dumpRaw = !!args['dump-raw'];

  if (!apiKey) die('error: --api-key or ANTHROPIC_API_KEY required');
  if (!agentId) die('error: --agent-id required (e.g. agent_01XaNB4M88ZvcW8FoQ5GC14A)');

  process.stdout.write(`[wma-fetch] resolving agent ${agentId}…\n`);
  const agent = await getAgent(apiKey, agentId).catch(e => die(`failed to GET agent: ${e.message}`));
  const rawModel = agent.model || agent.config?.model || null;
  // API may return model as { id, speed } object or as a plain string.
  const model = (rawModel && typeof rawModel === 'object') ? (rawModel.id || null) : rawModel;
  process.stdout.write(`[wma-fetch] model: ${model || '(unknown)'}\n`);

  let sessions;
  if (sessionId) {
    sessions = [{ id: sessionId, created_at: new Date().toISOString() }];
  } else {
    process.stdout.write(`[wma-fetch] listing sessions${since ? ` since ${since.toISOString()}` : ''}…\n`);
    sessions = await listSessions(apiKey, { agentId, since })
      .catch(e => die(`failed to list sessions: ${e.message}`));
  }

  if (sessions.length === 0) {
    process.stdout.write('[wma-fetch] no sessions to fetch\n');
    return;
  }
  process.stdout.write(`[wma-fetch] ${sessions.length} session(s) to fetch\n`);

  let totalEntries = 0;
  for (const s of sessions) {
    const sid = s.id;
    process.stdout.write(`\n[wma-fetch] session ${sid}\n`);

    if (dumpRaw) {
      const rawPath = join(logDir, agentId, `raw-${sid}.jsonl`);
      await mkdir(join(logDir, agentId), { recursive: true, mode: 0o700 });
      for await (const ev of fetchRawEvents(apiKey, sid)) {
        await appendFile(rawPath, JSON.stringify(ev) + '\n', { encoding: 'utf8', mode: 0o600 });
      }
      process.stdout.write(`  raw events  → ${rawPath}\n`);
    }

    const logger = new Logger({ logDir, agentId, sessionId: sid, silent: true });
    const tracker = new TokenTracker();

    let count = 0;
    for await (const entry of fetchSessionEntries({ apiKey, agentId, sessionId: sid, model })) {
      const written = await logger.write(entry);
      tracker.record(written);
      count++;
    }

    const stats = tracker.stats().total;
    const sessionEnd = await logger.write({
      action_type: 'session_end',
      framework: 'anthropic-managed',
      status: 'ok',
      model,
      session_tokens: {
        input: stats.input, output: stats.output,
        cache_read: stats.cache_read, cache_creation: stats.cache_creation,
        total: stats.sum,
      },
      session_cost_usd: stats.cost_usd || null,
    });

    process.stdout.write(`  entries     : ${count} (+1 session_end)\n`);
    process.stdout.write(`  tokens      : in=${stats.input} out=${stats.output} cache_r=${stats.cache_read} cache_w=${stats.cache_creation}\n`);
    process.stdout.write(`  written to  : ${logger._pathForToday()}\n`);
    totalEntries += count + 1;
  }

  process.stdout.write(`\n[wma-fetch] done — ${totalEntries} total entries across ${sessions.length} session(s)\n`);
  process.stdout.write(`[wma-fetch] inspect with: npx wma-inspect ${logDir}\n`);
}

main().catch(e => { process.stderr.write(`error: ${e.stack || e.message}\n`); process.exit(1); });
