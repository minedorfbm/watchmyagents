#!/usr/bin/env node
// wma-fetch — pull session events from Anthropic Managed Agents and write them
// as WatchMyAgents NDJSON, ready for `wma-inspect`.
//
// Two modes:
//
//   ONE-SHOT (default):
//     wma-fetch --agent-id agent_xxx [--session-id sess_xxx] [--since 1h]
//               [--log-dir ./watchmyagents-logs] [--dump-raw]
//
//   CONTINUOUS / DAEMON:
//     wma-fetch --agent-id agent_xxx --watch [--interval 5m] [--upload]
//     Loops until SIGINT. Each cycle incrementally fetches NEW events (deduped
//     by the stable Anthropic event id), appends them to the NDJSON, and — with
//     --upload — anonymizes the new window and ships signals to Fortress. This
//     automates the Watch leg of the WGS loop so Guardian gets fresh data with
//     no manual step. The raw NDJSON always stays local (Containment).
//
// API key from --api-key or env ANTHROPIC_API_KEY.
// --upload also needs: WMA_API_KEY, WMA_FORTRESS_BASE_URL, WMA_SIGNALS_SALT.

import { mkdir, appendFile, readdir } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { join, resolve } from 'node:path';
import { request as httpsRequest } from 'node:https';
import { URL } from 'node:url';
import { Logger, tightenMode } from '../src/logger.js';
import { TokenTracker } from '../src/tokens.js';
import { SignalsAggregator } from '../src/anonymizer.js';
import { resolveFortressBase, fortressEndpoint } from '../src/fortress/url.js';
import { cleanLabel } from '../src/labels.js';
import { isValidAgentId, isValidSessionId, assertSafePathSegment } from '../src/validate.js';
import { classifyAgentType } from '../src/typology.js';
import { aggregate, buildFeatures } from '../src/typology-features.js';
import {
  getAgent, listAgents, listSessions, fetchSessionEntries, fetchRawEvents,
  AnthropicManagedSource, effectiveEnforcementMode,
} from '../src/sources/anthropic-managed.js';
import { maybePrintVersionAndExit } from '../src/version.js';
import { SeenTracker } from '../src/watch-state.js';

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

function parseDurationMs(s, fallback) {
  if (!s || s === true) return fallback;
  const m = String(s).match(/^(\d+)\s*([smhd])$/);
  if (m) {
    const n = parseInt(m[1], 10);
    return n * { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }[m[2]];
  }
  throw new Error(`invalid duration: ${s} (use e.g. 30s, 5m, 1h, 2d)`);
}

function parseSince(s) {
  if (!s || s === true) return null;
  const m = String(s).match(/^(\d+)\s*([smhd])$/);
  if (m) return new Date(Date.now() - parseDurationMs(s));
  const d = new Date(s);
  if (isNaN(d)) throw new Error(`invalid --since value: ${s}`);
  return d;
}

function die(msg, code = 1) { process.stderr.write(`${msg}\n`); process.exit(code); }
function info(msg) { process.stdout.write(`[wma-fetch] ${msg}\n`); }
function warn(msg) { process.stderr.write(`[wma-fetch] ⚠️  ${msg}\n`); }
// v1.1.1 F-11: cleanLabel moved to src/labels.js so wma-upload-fortress
// (and any future consumer) shares the exact same sanitization. Defense
// in depth vs log/payload injection from customer-set agent names.

function resolveModel(agent) {
  const raw = agent.model || agent.config?.model || null;
  return (raw && typeof raw === 'object') ? (raw.id || null) : raw;
}

// HTTPS POST helper for the --upload signals push (mirrors wma-upload-fortress).
// v1.1.2 F-17: response body cap for the Fortress ingest-signals POST.
// The expected reply is a small JSON confirmation ({signal_id, agent_id,
// registered_new_agent}) — well under 1 MB. Any larger and the endpoint
// is misconfigured or compromised; abort.
const MAX_FORTRESS_RESPONSE_BYTES = 1 * 1024 * 1024;

// v1.1.6 F-22 (P2 Codex audit): hard ceiling on a Fortress POST round
// trip. Same rationale as in scripts/upload-fortress.js — without this,
// a slow/unresponsive endpoint hangs the daemon's session loop.
const FORTRESS_REQUEST_TIMEOUT_MS = 30_000;

function postJson(url, headers, body) {
  return new Promise((resolveReq, rejectReq) => {
    const u = new URL(url);
    if (u.protocol !== 'https:') return rejectReq(new Error(`refusing non-https URL: ${url}`));
    const data = Buffer.from(body);
    const req = httpsRequest({
      method: 'POST', hostname: u.hostname, port: u.port || 443,
      path: u.pathname + (u.search || ''),
      headers: { ...headers, 'content-type': 'application/json', 'content-length': data.length },
      rejectUnauthorized: true,
    }, (res) => {
      const chunks = [];
      let receivedBytes = 0;
      let aborted = false;
      res.on('data', (c) => {
        if (aborted) return;
        receivedBytes += c.length;
        if (receivedBytes > MAX_FORTRESS_RESPONSE_BYTES) {
          aborted = true;
          chunks.length = 0;
          try { req.destroy(); } catch { /* already destroyed */ }
          rejectReq(new Error(`Fortress response exceeded ${MAX_FORTRESS_RESPONSE_BYTES} bytes — aborting`));
          return;
        }
        chunks.push(c);
      });
      res.on('end', () => {
        if (aborted) return;
        const raw = Buffer.concat(chunks).toString('utf8');
        let parsed = null; try { parsed = JSON.parse(raw); } catch { /* keep raw */ }
        resolveReq({ status: res.statusCode || 0, body: parsed ?? raw });
      });
    });
    req.on('error', rejectReq);
    // v1.1.6 F-22: bound the round trip so a non-responding endpoint
    // can't hang the watch daemon's upload loop.
    req.setTimeout(FORTRESS_REQUEST_TIMEOUT_MS, () => {
      req.destroy(new Error(`Fortress request timed out after ${FORTRESS_REQUEST_TIMEOUT_MS}ms`));
    });
    req.write(data); req.end();
  });
}

// Anonymize a batch of just-written entries and ship them as one signals row.
// `classification` (optional) carries the agent's typology — Fortress upserts
// agent_type/confidence/stage on the agent row so the typology badge + the
// apply-template flow fill themselves with no manual click.
async function uploadSignals(uploadCtx, agentId, displayName, entries, classification, enforcementMode) {
  const agg = new SignalsAggregator({ salt: uploadCtx.salt });
  for (const e of entries) agg.add(e);
  const sig = agg.finalize();
  if (!sig.window_start || !sig.window_end) return null; // nothing datable to ship
  // PR-C: derive the agent's composition pattern + parent from the
  // observed entries. For Anthropic today, the Source yields solo/root
  // agents — sub-agent detection from thread_message_* events lands
  // with PR-D or a follow-up. Once a future adapter populates these on
  // the events themselves, this carries them up to Fortress without
  // any payload-shape change.
  const firstWithHierarchy = entries.find((e) => e.parent_agent_id != null);
  const parent_agent_id = firstWithHierarchy?.parent_agent_id ?? null;
  const composition_pattern = firstWithHierarchy?.composition_pattern
    || entries.find((e) => e.composition_pattern && e.composition_pattern !== 'solo')?.composition_pattern
    || 'solo';
  // PR-B: payload carries the canonical provider-agnostic identifiers
  // (`provider` + `native_agent_id`) AND the legacy `anthropic_agent_id`
  // so old Fortress instances still recognize the upload. Once the
  // Lovable-deployed ingest-signals migrates, future SDK releases will
  // stop emitting `anthropic_agent_id`.
  // PR-D / v1.0.1 F-2: enforcement_mode is the EFFECTIVE per-agent mode
  // (sync_confirm only if the agent has permission_policy: always_ask on
  // at least one tool; sync_interrupt otherwise). Falls back to the
  // Source's static MAX capability if the resolution failed upstream —
  // legacy behavior, but flags a warning in the daemon log.
  const body = JSON.stringify({
    provider: AnthropicManagedSource.providerName,
    native_agent_id: agentId,
    anthropic_agent_id: agentId,
    parent_agent_id,
    composition_pattern,
    enforcement_mode: enforcementMode || AnthropicManagedSource.enforcementMode,
    display_name: displayName,
    window_start: sig.window_start,
    window_end: sig.window_end,
    payload: sig.payload,
    ...(classification ? { classification } : {}),
  });
  const { status, body: resp } = await postJson(
    uploadCtx.url, { authorization: `Bearer ${uploadCtx.apiKey}` }, body,
  );
  if (status < 200 || status >= 300) {
    throw new Error(`ingest-signals HTTP ${status}: ${typeof resp === 'string' ? resp.slice(0, 200) : JSON.stringify(resp)}`);
  }
  return resp;
}

// v1.1.0 L2 — minimal one-shot registration signal sent to Fortress so
// a freshly-created Anthropic agent appears in the dashboard immediately,
// without waiting for the next Watch cycle AND without waiting for actual
// activity. The signal carries an empty SignalsAggregator payload + a
// degenerate window (window_start == window_end == now) so Fortress's
// ingest-signals upserts the agent row but contributes zero metrics.
// Used by --discover-now CLI mode.
async function uploadDiscoverySignal(uploadCtx, agentId, displayName, enforcementMode) {
  const now = new Date().toISOString();
  const body = JSON.stringify({
    provider: AnthropicManagedSource.providerName,
    native_agent_id: agentId,
    anthropic_agent_id: agentId,
    parent_agent_id: null,
    composition_pattern: 'solo',
    enforcement_mode: enforcementMode || AnthropicManagedSource.enforcementMode,
    display_name: displayName,
    window_start: now,
    window_end: now,
    payload: {
      counts: {},
      tool_counts: {},
      latencies_p50_ms: {},
      latencies_p95_ms: {},
      error_rate_by_tool: {},
      ioc_hashes: [],
      sequences_top10: [],
      stop_reasons: {},
      tokens_total: 0,
      session_ids: [],
    },
  });
  const { status, body: resp } = await postJson(
    uploadCtx.url, { authorization: `Bearer ${uploadCtx.apiKey}` }, body,
  );
  if (status < 200 || status >= 300) {
    throw new Error(`ingest-signals HTTP ${status}: ${typeof resp === 'string' ? resp.slice(0, 200) : JSON.stringify(resp)}`);
  }
  return resp;
}

// One-shot "discover and register" mode: list every agent the customer's
// Anthropic key can see, derive each effective enforcement mode, and push
// a discovery signal to Fortress so the agent appears in the dashboard
// immediately. Exits when done — no watch loop, no event polling.
async function runDiscoverNow({ apiKey, uploadCtx, sendNames }) {
  info('discover-now: listing agents from Anthropic…');
  let agents;
  try { agents = await listAgents(apiKey); }
  catch (e) { die(`failed to list agents: ${e.message}`); }
  info(`discover-now: ${agents.length} agent(s) found`);

  let registered = 0;
  let skipped = 0;
  let failed = 0;
  for (const a of agents) {
    if (!a.id || !isValidAgentId(a.id)) { skipped++; continue; }
    const displayName = sendNames ? cleanLabel(a.name) || a.id : a.id;
    // Resolve effective enforcement mode best-effort; fall back to provider max.
    let mode;
    try { mode = await effectiveEnforcementMode(apiKey, a.id); }
    catch (e) { warn(`  enforcement_mode resolution failed for ${a.id}: ${e.message} (using provider max)`); }
    try {
      const resp = await uploadDiscoverySignal(uploadCtx, a.id, displayName, mode);
      registered++;
      info(`  ✓ ${a.id} (${displayName})${resp?.registered_new_agent ? ' 🆕' : ''}`);
    } catch (e) {
      failed++;
      warn(`  ✗ ${a.id}: ${e.message}`);
    }
  }
  info(`discover-now: done — ${registered} registered, ${skipped} skipped, ${failed} failed`);
}

// Preload already-written entry ids so a restarted daemon doesn't re-append
// events captured in a previous run (dedup by the stable Anthropic event id).
async function preloadSeenIds(logDir, agentId) {
  const seen = new Set();
  const dir = join(logDir, agentId);
  let names;
  try { names = await readdir(dir); } catch { return seen; }
  for (const name of names) {
    if (!name.endsWith('.ndjson') || name.startsWith('raw-')) continue;
    await new Promise((res) => {
      const rl = createInterface({ input: createReadStream(join(dir, name), { encoding: 'utf8' }), crlfDelay: Infinity });
      rl.on('line', (line) => {
        if (!line.trim()) return;
        try { const e = JSON.parse(line); if (e.id) seen.add(e.id); } catch { /* skip */ }
      });
      rl.on('close', res);
      rl.on('error', res);
    });
  }
  return seen;
}

const sleep = (ms, signal) => new Promise((res) => {
  const t = setTimeout(res, ms);
  if (signal) signal.addEventListener('abort', () => { clearTimeout(t); res(); }, { once: true });
});

// ── ONE-SHOT ──────────────────────────────────────────────────────────────
async function fetchOneShot({ apiKey, agentId, model, logDir, since, sessionId, dumpRaw, forceDuplicates = false }) {
  let sessions;
  if (sessionId) {
    sessions = [{ id: sessionId, created_at: new Date().toISOString() }];
  } else {
    info(`listing sessions${since ? ` since ${since.toISOString()}` : ''}…`);
    sessions = await listSessions(apiKey, { agentId, since }).catch((e) => die(`failed to list sessions: ${e.message}`));
  }
  if (sessions.length === 0) { info('no sessions to fetch'); return; }
  info(`${sessions.length} session(s) to fetch`);

  // v1.1.1 F-10 (P2 Codex audit): preload the entry ids already on disk for
  // this agent so re-running the one-shot doesn't duplicate events. The
  // watch daemon does this already; the one-shot was the missing piece.
  // Operators who explicitly want the legacy duplicate-on-rerun behavior
  // can opt back in with --force-duplicates.
  const seenIds = forceDuplicates ? new Set() : await preloadSeenIds(logDir, agentId);
  if (!forceDuplicates && seenIds.size > 0) {
    info(`preloaded ${seenIds.size} known event id(s) for dedup`);
  }

  let totalEntries = 0;
  let totalSkipped = 0;
  for (const s of sessions) {
    const sid = s.id;
    process.stdout.write(`\n[wma-fetch] session ${sid}\n`);
    if (dumpRaw) {
      assertSafePathSegment(sid, 'session-id'); // defense-in-depth: sid → file path
      const rawDir = join(logDir, agentId);
      const rawPath = join(rawDir, `raw-${sid}.jsonl`);
      await mkdir(rawDir, { recursive: true, mode: 0o700 });
      // v1.4.1 F-34 (P2 Codex audit): mkdir/appendFile `mode` is creation-
      // only. If a previous `wma-fetch` run, a different user, or a hand-
      // rolled mkdir left the directory or file in place with loose perms
      // (typically 0755/0644 via umask), the original code path kept them.
      // The raw JSONL carries unredacted API events, so loose perms make
      // them readable to any local user. Tighten after the directory and
      // after the first append so an existing inode is brought in line
      // with the doc promise (0700/0600). Best-effort: chmod failures
      // here MUST NOT break wma-fetch.
      await tightenMode(rawDir, 0o700);
      let firstAppend = true;
      for await (const ev of fetchRawEvents(apiKey, sid)) {
        await appendFile(rawPath, JSON.stringify(ev) + '\n', { encoding: 'utf8', mode: 0o600 });
        if (firstAppend) {
          await tightenMode(rawPath, 0o600);
          firstAppend = false;
        }
      }
      process.stdout.write(`  raw events  → ${rawPath}\n`);
    }
    const logger = new Logger({ logDir, agentId, sessionId: sid, silent: true });
    const tracker = new TokenTracker();
    let count = 0;
    let skipped = 0;
    for await (const entry of fetchSessionEntries({ apiKey, agentId, sessionId: sid, model })) {
      if (entry.id && seenIds.has(entry.id)) { skipped++; continue; }
      const written = await logger.write(entry);
      if (entry.id) seenIds.add(entry.id);
      tracker.record(written);
      count++;
    }
    totalSkipped += skipped;
    const stats = tracker.stats().total;
    await logger.write({
      action_type: 'session_end', provider: 'anthropic-managed', status: 'ok', model,
      session_tokens: { input: stats.input, output: stats.output, cache_read: stats.cache_read, cache_creation: stats.cache_creation, total: stats.sum },
      session_cost_usd: stats.cost_usd || null,
    });
    process.stdout.write(`  entries     : ${count} (+1 session_end)${skipped ? ` · ${skipped} skipped (dedup)` : ''}\n`);
    process.stdout.write(`  tokens      : in=${stats.input} out=${stats.output} cache_r=${stats.cache_read} cache_w=${stats.cache_creation}\n`);
    process.stdout.write(`  written to  : ${logger._pathForToday()}\n`);
    totalEntries += count + 1;
  }
  process.stdout.write(`\n[wma-fetch] done — ${totalEntries} total entries across ${sessions.length} session(s)${totalSkipped ? `, ${totalSkipped} skipped (dedup)` : ''}\n`);
  process.stdout.write(`[wma-fetch] inspect with: npx wma-inspect ${logDir}\n`);
}

// ── CONTINUOUS / DAEMON (single agent or whole fleet) ───────────────────────
// resolveAgents() returns the current fleet [{agentId, model, displayName}] each
// cycle — in fleet mode it RE-DISCOVERS so agents created after startup get picked
// up. `windowMs` bounds discovery of NEW sessions, but sessions we're ALREADY
// tracking are re-fetched regardless of age, so a long-running (>window) session
// never drops out of capture. `sendNames`: include the human agent name in the
// Fortress display_name (opt-in); default sends the agent id only (Containment).
async function runWatch({ apiKey, resolveAgents, fleet, logDir, intervalMs, windowMs, uploadCtx, sendNames }) {
  let agents = await resolveAgents();
  // v1.4.3 F-51: bounded dedup. Preloaded on-disk ids are static; runtime ids
  // are tracked per-session and dropped on terminate (see src/watch-state.js).
  const seen = new SeenTracker();
  // v1.4.4 F-53: preload each agent's on-disk history the FIRST time we see it
  // — including agents that --all-agents discovers after startup. Pre-fix the
  // preload ran once for the initial fleet only, so a late-appearing agent with
  // existing logs re-appended + re-uploaded already-captured events.
  const preloadedAgents = new Set();
  async function ensurePreloaded(agentId) {
    if (preloadedAgents.has(agentId)) return;
    preloadedAgents.add(agentId);
    for (const id of await preloadSeenIds(logDir, agentId)) seen.addPreloaded(id);
  }
  for (const ag of agents) await ensurePreloaded(ag.agentId);
  const loggers = new Map();     // sessionId → Logger (session ids are globally unique)
  // terminated sessions (skip). v1.4.4 F-54: a Map<sid → terminatedAtMs> so we
  // can TTL-prune. A session terminated more than windowMs ago has created_at
  // older still, so listSessions (which filters created_at < since, since =
  // now - windowMs) can no longer return it — its id is then safe to forget,
  // bounding this map's growth on a long daemon with many short sessions.
  const ended = new Map();
  const sessionAgent = new Map();// sessionId → { agentId, model, displayName }
  const priors = new Map();      // agentId → previous classification (threads the
                                  // typology state machine across upload cycles)
  // F-2: cache the effective enforcement mode per agent. One getAgent call
  // per agent per daemon run (until the entry is evicted). Refreshed only
  // if upload fails — agent permission_policy doesn't change mid-flight.
  const enforcementModes = new Map(); // agentId → 'sync_confirm' | 'sync_interrupt'

  const ac = new AbortController();
  const shutdown = () => { info('shutting down…'); ac.abort(); };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  info(`watch mode — ${agents.length} agent(s)${fleet ? ' (fleet, re-discovered each cycle)' : ''}, interval ${Math.round(intervalMs / 1000)}s, discovery window ${Math.round(windowMs / 3600000)}h, upload ${uploadCtx ? 'ON' : 'OFF'}, ${seen.size} known events preloaded`);

  while (!ac.signal.aborted) {
    if (fleet) { const next = await resolveAgents(); if (next.length) agents = next; }
    const since = new Date(Date.now() - windowMs);

    // F-54: forget sessions terminated longer ago than the discovery window —
    // listSessions can no longer surface them (created_at < since), so their
    // skip-marker is no longer needed. Bounds `ended` on a long-running daemon.
    const ttlCutoff = Date.now() - windowMs;
    for (const [sid, terminatedAt] of ended) {
      if (terminatedAt < ttlCutoff) ended.delete(sid);
    }

    // (1) Discover sessions in the window; register the owning agent for each.
    for (const ag of agents) {
      if (ac.signal.aborted) break;
      // F-53: a late-discovered agent (fleet mode) gets its disk history
      // preloaded before we fetch any of its sessions, so dedup holds.
      await ensurePreloaded(ag.agentId);
      const tag = fleet ? `[${ag.displayName}] ` : '';
      let sessions = [];
      try { sessions = await listSessions(apiKey, { agentId: ag.agentId, since }); }
      catch (e) { warn(`${tag}listSessions failed: ${e.message}`); continue; }
      for (const s of sessions) {
        if (s.id && !ended.has(s.id) && !sessionAgent.has(s.id)) {
          sessionAgent.set(s.id, { agentId: ag.agentId, model: ag.model, displayName: ag.displayName });
        }
      }
    }

    // (2) Capture every tracked, not-yet-ended session — REGARDLESS of age. This
    // is what stops a long-running session created before the window from silently
    // dropping out of monitoring (and, paired with Shield, out of enforcement).
    let cycleNew = 0;
    for (const [sid, ag] of sessionAgent) {
      if (ac.signal.aborted) break;
      if (ended.has(sid)) continue;
      const tag = fleet ? `[${ag.displayName}] ` : '';
      // v1.4.3 F-51: top-level guard around the WHOLE per-session body. Pre-fix
      // only the fetch + upload had try/catch; an unguarded throw elsewhere
      // (e.g. ENOSPC/EACCES on the fail-loud session_end logger.write, or a
      // malformed entry in TokenTracker) propagated out of the loop and
      // KILLED the daemon — silent total collection-stop on a backgrounded
      // process. Now any single session's failure drops that session for the
      // cycle and the daemon survives.
      try {
      let logger = loggers.get(sid);
      if (!logger) { logger = new Logger({ logDir, agentId: ag.agentId, sessionId: sid, silent: true }); loggers.set(sid, logger); }

      const fresh = [];
      let sawTerminated = false;
      try {
        for await (const entry of fetchSessionEntries({ apiKey, agentId: ag.agentId, sessionId: sid, model: ag.model })) {
          if (entry.id && seen.has(sid, entry.id)) continue;
          if (entry.id) seen.add(sid, entry.id);
          const written = await logger.write(entry);
          fresh.push(written);
          if (entry.action_type === 'state_transition'
              && entry.output?.scope === 'session'
              && entry.output?.state === 'terminated') sawTerminated = true;
        }
      } catch (e) { warn(`${tag}session ${sid.slice(0, 16)}…: fetch failed: ${e.message}`); continue; }

      if (fresh.length === 0) continue;
      cycleNew += fresh.length;
      info(`${tag}session ${sid.slice(0, 16)}…: +${fresh.length} new event(s)`);

      if (uploadCtx) {
        try {
          // Compute the agent's typology from its CUMULATIVE local logs and
          // thread the prior across cycles so the state machine refines toward
          // stable (Containment: features = counts/categories only, no raw content).
          let classification;
          try {
            const features = buildFeatures(await aggregate(logDir, ag.agentId));
            features.agent_id = ag.agentId;
            const cls = classifyAgentType(features, priors.get(ag.agentId) || null);
            priors.set(ag.agentId, cls);
            classification = { agent_type: cls.classified_type, confidence: cls.confidence, stage: cls.stage };
          } catch (e) { warn(`  classification skipped: ${e.message}`); }

          // F-2: resolve the effective enforcement mode for this agent
          // (cached across cycles). On failure, fall back to the static
          // provider max so the upload still succeeds.
          let mode = enforcementModes.get(ag.agentId);
          if (!mode) {
            try {
              mode = await effectiveEnforcementMode(apiKey, ag.agentId);
              enforcementModes.set(ag.agentId, mode);
            } catch (e) {
              warn(`  enforcement_mode resolution failed for ${ag.agentId}: ${e.message} (falling back to provider max)`);
            }
          }
          const resp = await uploadSignals(uploadCtx, ag.agentId, sendNames ? ag.displayName : ag.agentId, fresh, classification, mode);
          if (resp?.signal_id) {
            const cTag = classification ? ` · type ${classification.agent_type} (${Math.round(classification.confidence * 100)}%, ${classification.stage})` : '';
            info(`  ↑ signals uploaded (signal_id ${resp.signal_id})${cTag}`);
          }
        } catch (e) { warn(`  signals upload failed: ${e.message}`); }
      }

      if (sawTerminated) {
        const tracker = new TokenTracker();
        for (const e of fresh) tracker.record(e);
        const stats = tracker.stats().total;
        await logger.write({
          action_type: 'session_end', provider: 'anthropic-managed', status: 'ok', model: ag.model,
          session_tokens: { input: stats.input, output: stats.output, cache_read: stats.cache_read, cache_creation: stats.cache_creation, total: stats.sum },
          session_cost_usd: stats.cost_usd || null,
        });
        ended.set(sid, Date.now());
        // v1.4.3 F-51: bound memory — terminated sessions aren't re-fetched,
        // so drop their per-session dedup set AND their Logger object (the
        // latter was never deleted pre-fix → unbounded growth of Logger
        // instances over a long daemon run).
        sessionAgent.delete(sid);
        seen.forgetSession(sid);
        loggers.delete(sid);
        info(`${tag}session ${sid.slice(0, 16)}… terminated — closed`);
      }
      } catch (e) {
        // F-51 top-level guard: never let one session's failure kill the loop.
        warn(`${tag}session ${sid.slice(0, 16)}…: cycle error (skipped): ${e.message}`);
      }
    }

    if (cycleNew === 0) info('cycle: no new events');
    await sleep(intervalMs, ac.signal);
  }
  info('stopped.');
}

async function main() {
  // v1.1.1 F-13: --version / -v short-circuit before any other parsing.
  maybePrintVersionAndExit(process.argv);
  const args = parseArgs(process.argv.slice(2));
  const apiKey = args['api-key'] || process.env.ANTHROPIC_API_KEY;
  const agentId = args['agent-id'];
  const logDir = resolve(args['log-dir'] || './watchmyagents-logs');
  const watch = !!args.watch;
  const upload = !!args.upload;
  const allAgents = !!args['all-agents'];
  const discoverNow = !!args['discover-now'];

  if (!apiKey) die('error: --api-key or ANTHROPIC_API_KEY required');
  // --discover-now is its own mode: list+register every agent immediately, exit.
  // It requires the same Fortress credentials as --upload (it IS a one-shot upload).
  if (discoverNow) {
    const wmaKey = process.env.WMA_API_KEY;
    const salt = process.env.WMA_SIGNALS_SALT;
    const base = resolveFortressBase({});
    if (!wmaKey) die('error: --discover-now needs WMA_API_KEY env (from Fortress dashboard → Settings → API Keys)');
    if (!base) die('error: --discover-now needs WMA_FORTRESS_BASE_URL env');
    if (!salt) die('error: --discover-now needs WMA_SIGNALS_SALT env');
    if (salt.length < 16) die('error: WMA_SIGNALS_SALT too short (need ≥16 hex chars)');
    const uploadCtx = { apiKey: wmaKey, salt, url: fortressEndpoint(base, 'ingest-signals') };
    const sendNames = args['no-send-agent-names'] !== true;
    return runDiscoverNow({ apiKey, uploadCtx, sendNames });
  }
  if (!allAgents && !agentId) die('error: --agent-id required (or --all-agents for fleet mode)');
  if (allAgents && !watch) die('error: --all-agents requires --watch (fleet daemon). For a one-shot, target a single --agent-id.');
  if (agentId && !isValidAgentId(agentId)) {
    die(`error: --agent-id has invalid format (expected "agent_" + alphanumeric, got "${agentId}")`);
  }
  const sessionIdArg = args['session-id'];
  if (sessionIdArg && !isValidSessionId(sessionIdArg)) {
    die(`error: --session-id has invalid format (expected "sesn_" + alphanumeric, got "${sessionIdArg}")`);
  }
  if (args['api-key']) {
    warn('--api-key on the command line is visible in shell history and the process list. Prefer: export ANTHROPIC_API_KEY=...');
  }
  if (upload && !watch) die('error: --upload requires --watch (continuous mode). For one-shot upload use wma-upload-fortress.');

  // Resolve upload config up-front (so a misconfig fails before the loop starts).
  let uploadCtx = null;
  if (upload) {
    const wmaKey = process.env.WMA_API_KEY;
    const salt = process.env.WMA_SIGNALS_SALT;
    const base = resolveFortressBase({});
    if (!wmaKey) die('error: --upload needs WMA_API_KEY env (from Fortress dashboard → Settings → API Keys)');
    if (!base) die('error: --upload needs WMA_FORTRESS_BASE_URL env (https://<project>.supabase.co/functions/v1)');
    if (!salt) die('error: --upload needs WMA_SIGNALS_SALT env (stable per-customer hex secret)');
    if (salt.length < 16) die('error: WMA_SIGNALS_SALT too short (need ≥16 hex chars)');
    uploadCtx = { apiKey: wmaKey, salt, url: fortressEndpoint(base, 'ingest-signals') };
  }

  if (watch) {
    // v1.1.0 Phase 1 L1: default Watch cycle = 60s (was 300s/5min). At this
    // cadence both event polling AND fleet re-discovery happen every minute,
    // bringing the agent-to-Fortress visibility from 5min worst-case down to
    // ~60s. ~1440 list/get calls/day against Anthropic — well inside free
    // tier limits, no behavioral risk. Operators who want the legacy 5min
    // cadence can still pass --interval 5m explicitly.
    const intervalMs = parseDurationMs(args.interval, 60_000);
    // Discovery window for NEW sessions (default 7d, configurable). Sessions we
    // already track are re-fetched regardless of age, so long-lived ones don't drop.
    let windowMs = parseDurationMs(args['discovery-since'], 7 * 24 * 3600_000);
    // v1.4.2 F-46 (P1 audit): the discovery window must comfortably exceed the
    // poll interval. Discovery runs once per cycle; a session that is created
    // AND ends/ages-out between two sweeps is never added to the tracked set,
    // so its events are never fetched (untraced activity). Requiring
    // windowMs >= 2*intervalMs guarantees every session appears in at least
    // two consecutive discovery sweeps before it can leave the window. The 7d
    // default is far above this; the guard only bites when an operator sets
    // --discovery-since too tight relative to --interval. Clamp + warn rather
    // than silently honoring a value that opens a per-cycle blind window.
    const minWindowMs = intervalMs * 2;
    if (windowMs < minWindowMs) {
      process.stderr.write(
        `[wma] --discovery-since (${Math.round(windowMs / 1000)}s) is below 2x --interval ` +
        `(${Math.round(intervalMs / 1000)}s) — a short-lived session could be missed between ` +
        `sweeps. Clamping discovery window up to ${Math.round(minWindowMs / 1000)}s.\n`,
      );
      windowMs = minWindowMs;
    }
    // display_name on the Fortress payload: defaults to the human agent name
    // (UX-friendly — operators identify agents by name in the dashboard). The
    // name is sanitized via cleanLabel() so log/payload injection is impossible.
    // Use --no-send-agent-names to opt OUT (sends the agent_id instead) for
    // setups where the agent name itself is considered sensitive metadata.
    const sendNames = args['no-send-agent-names'] !== true;

    let resolveAgents;
    if (allAgents) {
      // Re-discover the fleet each cycle: agents created after startup get picked
      // up, gone ones drop off. Keep the last good list if a discovery call fails.
      let lastFleet = [];
      resolveAgents = async () => {
        const all = await listAgents(apiKey).catch((e) => { warn(`fleet re-discovery failed (keeping last): ${e.message}`); return null; });
        if (!all) return lastFleet;
        const next = all
          .filter((a) => a.id && isValidAgentId(a.id))
          .map((a) => ({ agentId: a.id, model: resolveModel(a), displayName: cleanLabel(a.name || a.id) }));
        const prev = new Set(lastFleet.map((a) => a.agentId));
        const cur = new Set(next.map((a) => a.agentId));
        for (const a of next) if (!prev.has(a.agentId)) info(`fleet: + ${a.displayName}`);
        for (const a of lastFleet) if (!cur.has(a.agentId)) info(`fleet: − ${a.displayName} (gone)`);
        lastFleet = next;
        return next;
      };
      info('discovering agents (fleet mode)…');
      const first = await resolveAgents();
      if (first.length === 0) die('error: no agents found under this API key');
      info(`fleet: ${first.length} agent(s) — ${first.map((a) => a.displayName).join(', ')}`);
    } else {
      info(`resolving agent ${agentId}…`);
      const agent = await getAgent(apiKey, agentId).catch((e) => die(`failed to GET agent: ${e.message}`));
      const single = [{ agentId, model: resolveModel(agent), displayName: cleanLabel(agent.name || agentId) }];
      info(`model: ${single[0].model || '(unknown)'}`);
      resolveAgents = async () => single;
    }

    await runWatch({ apiKey, resolveAgents, fleet: allAgents, logDir, intervalMs, windowMs, uploadCtx, sendNames });
  } else {
    info(`resolving agent ${agentId}…`);
    const agent = await getAgent(apiKey, agentId).catch((e) => die(`failed to GET agent: ${e.message}`));
    const since = args.since ? parseSince(args.since) : null;
    await fetchOneShot({ apiKey, agentId, model: resolveModel(agent), logDir, since, sessionId: args['session-id'], dumpRaw: !!args['dump-raw'], forceDuplicates: !!args['force-duplicates'] });
  }
}

main().catch((e) => { process.stderr.write(`error: ${e.stack || e.message}\n`); process.exit(1); });
