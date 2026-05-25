#!/usr/bin/env node
// wma-anonymize — produce the anonymized signals payload that Watch would
// send to Fortress, for inspection / verification.
//
// Usage:
//   wma-anonymize <path-to-ndjson-or-dir> [--salt <hex>] [--out <file>]
//
// The `--salt` argument MUST be a stable per-customer secret. Using a
// random salt each run means hashes won't correlate across runs (useless
// for IoC tracking). Recommended: store the salt in `.env.local` as
// `WMA_SIGNALS_SALT=...`.
//
// If --salt is omitted and WMA_SIGNALS_SALT is set, that's used. Otherwise
// the script refuses to run (intentional — we don't want users to ship
// random-salt hashes by accident).

import { readdir, stat, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { SignalsAggregator, anonymizeFile } from '../src/anonymizer.js';

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const k = a.slice(2);
      const n = argv[i + 1];
      if (n == null || n.startsWith('--')) out[k] = true;
      else { out[k] = n; i++; }
    } else if (!out._target) {
      out._target = a;
    }
  }
  return out;
}

function die(msg, code = 1) {
  process.stderr.write(`${msg}\n`);
  process.exit(code);
}

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

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (!args._target) {
    die(`usage: wma-anonymize <path> [--salt <hex>] [--out <file>]

Reads Watch NDJSON logs and produces the anonymized signals payload
that would be sent to Fortress. Use this to inspect exactly what
leaves your machine BEFORE any upload feature is enabled.

Required: --salt <hex> or WMA_SIGNALS_SALT env var (per-customer secret).
If you don't have one, generate: node -e "console.log(require('crypto').randomBytes(16).toString('hex'))"
and save it in .env.local.`);
  }

  const salt = args.salt || process.env.WMA_SIGNALS_SALT;
  if (!salt) {
    die('error: --salt <hex> or WMA_SIGNALS_SALT env var required (per-customer secret for hashing).\n' +
        '       generate one with: node -e "console.log(require(\'crypto\').randomBytes(16).toString(\'hex\'))"');
  }
  if (args.salt) {
    process.stderr.write('[wma-anonymize] warning: --salt on the command line is visible in shell history.\n' +
                         '                Prefer: export WMA_SIGNALS_SALT=...\n');
  }
  if (salt.length < 16) {
    die('error: salt too short (need ≥16 hex chars / ≥8 bytes of entropy)');
  }

  const target = resolve(args._target);
  const files = await collectFiles(target);
  if (files.length === 0) {
    die(`error: no .ndjson files found at ${target}`);
  }

  // Aggregate across all files into one big payload (typical: one fetch run)
  const agg = new SignalsAggregator({ salt });
  for (const f of files) {
    const partial = await anonymizeFile(f, { salt });
    // Merge counts (a bit clunky — for the MVP we just re-iterate via agg)
    // Simpler: aggregate over the files using the same agg instance.
    // Re-implement here cleanly:
    void partial;
  }
  // Re-do cleanly with a single aggregator across files:
  const oneAgg = new SignalsAggregator({ salt });
  for (const f of files) {
    const { createReadStream } = await import('node:fs');
    const { createInterface } = await import('node:readline');
    const stream = createReadStream(f, { encoding: 'utf8' });
    const rl = createInterface({ input: stream, crlfDelay: Infinity });
    for await (const line of rl) {
      if (!line.trim()) continue;
      let e; try { e = JSON.parse(line); } catch { continue; }
      oneAgg.add(e);
    }
  }

  const signals = oneAgg.finalize();

  const json = JSON.stringify(signals, null, 2);
  if (args.out) {
    await writeFile(resolve(args.out), json + '\n', { encoding: 'utf8', mode: 0o600 });
    process.stderr.write(`[wma-anonymize] wrote ${args.out} (${signals._meta.entries_processed} entries processed)\n`);
  } else {
    process.stdout.write(json + '\n');
  }
}

main().catch(e => { process.stderr.write(`error: ${e.stack || e.message}\n`); process.exit(1); });
