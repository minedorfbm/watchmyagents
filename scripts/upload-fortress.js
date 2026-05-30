#!/usr/bin/env node
// wma-upload-fortress — anonymize local Watch NDJSON and POST signals to
// the Fortress ingest-signals Edge Function.
//
// Composable with the rest of the SDK:
//   wma-fetch  →  ./watchmyagents-logs/<agent_id>/<date>.ndjson   (local capture)
//   wma-anonymize  →  signals payload (Containment: no raw content)
//   wma-upload-fortress  →  POST signals to https://<project>.supabase.co/functions/v1/ingest-signals
//
// Usage:
//   wma-upload-fortress --agent-id agent_xxx \
//                       [--log-dir ./watchmyagents-logs] \
//                       [--fortress-url https://<project>.supabase.co/functions/v1/ingest-signals] \
//                       [--api-key wma_...] \
//                       [--salt <hex>] \
//                       [--display-name "My agent"] \
//                       [--dry-run]
//
// Env vars (preferred over CLI flags):
//   WMA_API_KEY            — the wma_xxx key from the Fortress dashboard
//   WMA_FORTRESS_URL       — full URL to the ingest-signals endpoint
//   WMA_SIGNALS_SALT       — per-customer hex salt for IoC hashing
//                            (must be stable across runs)

import { request as httpsRequest } from 'node:https';
import { URL } from 'node:url';
import { readdir, stat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { SignalsAggregator } from '../src/anonymizer.js';
import { resolveFortressBase, fortressEndpoint } from '../src/fortress/url.js';

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

function die(msg, code = 1) { process.stderr.write(`${msg}\n`); process.exit(code); }
function info(msg) { process.stdout.write(`[wma-upload-fortress] ${msg}\n`); }
function warn(msg) { process.stderr.write(`[wma-upload-fortress] ⚠️  ${msg}\n`); }

async function collectFiles(p) {
  const s = await stat(p).catch(() => null);
  if (!s) return [];
  if (s.isFile()) return p.endsWith('.ndjson') && !p.includes('raw-') ? [p] : [];
  const out = [];
  for (const name of await readdir(p)) {
    out.push(...(await collectFiles(join(p, name))));
  }
  return out;
}

function postJson(url, headers, body) {
  return new Promise((resolveReq, rejectReq) => {
    const u = new URL(url);
    if (u.protocol !== 'https:') {
      return rejectReq(new Error(`refusing non-https fortress URL: ${url}`));
    }
    const data = Buffer.from(body);
    const req = httpsRequest(
      {
        method: 'POST',
        hostname: u.hostname,
        port: u.port || 443,
        path: u.pathname + u.search,
        headers: {
          ...headers,
          'content-type': 'application/json',
          'content-length': data.length,
        },
        rejectUnauthorized: true,
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          let parsed = null;
          try { parsed = JSON.parse(raw); } catch { /* keep raw */ }
          resolveReq({ status: res.statusCode || 0, body: parsed ?? raw });
        });
      }
    );
    req.on('error', rejectReq);
    req.write(data);
    req.end();
  });
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  const agentId = args['agent-id'];
  const logDir = resolve(args['log-dir'] || './watchmyagents-logs');
  const apiKey = args['api-key'] || process.env.WMA_API_KEY;
  const salt = args.salt || process.env.WMA_SIGNALS_SALT;
  const displayName = args['display-name'] || agentId;
  const dryRun = !!args['dry-run'];

  // Resolve Fortress base URL. Accepts:
  //   --fortress-base-url <base>            (preferred CLI)
  //   --fortress-url <full ingest-signals>  (legacy CLI)
  //   WMA_FORTRESS_BASE_URL env             (preferred env)
  //   WMA_FORTRESS_URL env                  (legacy env, points at ingest-signals)
  const fortressBase = resolveFortressBase({
    explicitBase: args['fortress-base-url'],
    explicitUrl: args['fortress-url'],
  });
  const fortressUrl = fortressBase ? fortressEndpoint(fortressBase, 'ingest-signals') : null;

  // Validation
  if (!agentId) die('error: --agent-id required (Anthropic agent_id, e.g. agent_01ABC...)');
  // Strict alphanumeric to prevent path traversal in collectFiles below
  // (--agent-id ends up as a filesystem path segment).
  if (!/^agent_[a-zA-Z0-9]+$/.test(agentId)) {
    die(`error: --agent-id has invalid format (expected "agent_" + alphanumeric, got "${agentId}")`);
  }
  if (!dryRun && !fortressUrl) {
    die('error: --fortress-url or WMA_FORTRESS_URL required (full URL to /functions/v1/ingest-signals).\n' +
        '       Use --dry-run to print the payload without uploading.');
  }
  if (!dryRun && !apiKey) {
    die('error: --api-key or WMA_API_KEY required.\n' +
        '       Get one from your Fortress dashboard → Settings → API Keys.');
  }
  if (!dryRun && apiKey && !/^wma_[a-f0-9]{32}$/i.test(apiKey)) {
    warn(`API key format looks unusual (expected "wma_<32hex>", got "${apiKey.slice(0, 8)}…").`);
  }
  if (!salt) {
    die('error: --salt or WMA_SIGNALS_SALT required (per-customer hex secret for hashing IoCs).\n' +
        '       Generate once with:  node -e "console.log(require(\'crypto\').randomBytes(16).toString(\'hex\'))"\n' +
        '       Store stably in .env.local.');
  }
  if (salt.length < 16) die('error: salt too short (need ≥16 hex chars)');

  // Warn about CLI-passed secrets
  if (args['api-key']) {
    warn('--api-key on the command line is visible in shell history and process list.\n' +
         '                Prefer: export WMA_API_KEY=...');
  }
  if (args.salt) {
    warn('--salt on the command line is visible in shell history.\n' +
         '                Prefer: export WMA_SIGNALS_SALT=...');
  }

  // Discover the agent's NDJSON files
  const agentDir = join(logDir, agentId);
  const files = await collectFiles(agentDir);
  if (files.length === 0) {
    die(`error: no .ndjson files found under ${agentDir}. Run wma-fetch first?`);
  }
  info(`scanning ${files.length} ndjson file(s) under ${agentDir}`);

  // Aggregate into a single signals payload
  const agg = new SignalsAggregator({ salt });
  for (const f of files) {
    const stream = createReadStream(f, { encoding: 'utf8' });
    const rl = createInterface({ input: stream, crlfDelay: Infinity });
    for await (const line of rl) {
      if (!line.trim()) continue;
      let e; try { e = JSON.parse(line); } catch { continue; }
      agg.add(e);
    }
  }
  const signals = agg.finalize();
  if (!signals.window_start || !signals.window_end) {
    die('error: no entries had timestamps — nothing to upload');
  }

  // PR-B: provider-agnostic identifiers + legacy fallback (see fetch-anthropic.js).
  // PR-C: ship the agent's hierarchy + composition pattern. wma-upload-fortress
  // is a one-shot post-hoc tool — it has no per-entry context to derive
  // hierarchy from, so it sends defaults (solo / null) until a future
  // adapter writes those fields into the local NDJSON.
  const body = {
    provider: 'anthropic-managed',
    native_agent_id: agentId,
    anthropic_agent_id: agentId,
    parent_agent_id: null,
    composition_pattern: 'solo',
    display_name: displayName,
    window_start: signals.window_start,
    window_end: signals.window_end,
    payload: signals.payload,
  };
  const bodyJson = JSON.stringify(body);

  info(`payload built: ${signals._meta.entries_processed} entries → ${bodyJson.length} bytes`);
  info(`window: ${signals.window_start} → ${signals.window_end}`);
  info(`ioc_hashes: ${signals.payload.ioc_hashes.length}, tool_counts: ${Object.keys(signals.payload.tool_counts).length}`);

  if (dryRun) {
    info('--dry-run: payload that WOULD be POSTed:');
    process.stdout.write(JSON.stringify(body, null, 2) + '\n');
    return;
  }

  // POST it
  info(`POST ${fortressUrl}`);
  const { status, body: respBody } = await postJson(
    fortressUrl,
    { authorization: `Bearer ${apiKey}` },
    bodyJson
  );

  if (status >= 200 && status < 300) {
    info(`✅ HTTP ${status}`);
    if (typeof respBody === 'object' && respBody.signal_id) {
      info(`signal_id: ${respBody.signal_id}`);
      info(`agent_id:  ${respBody.agent_id}`);
      if (respBody.registered_new_agent) info('🆕 agent was auto-registered on this upload');
    } else {
      info(`response: ${typeof respBody === 'string' ? respBody.slice(0, 300) : JSON.stringify(respBody).slice(0, 300)}`);
    }
  } else {
    const msg = typeof respBody === 'object' ? JSON.stringify(respBody) : String(respBody).slice(0, 500);
    die(`error: upload failed (HTTP ${status}): ${msg}`);
  }
}

main().catch((e) => { process.stderr.write(`error: ${e.stack || e.message}\n`); process.exit(1); });
