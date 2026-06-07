// Fortress upload network timeout — v1.1.6 F-22 (P2 Codex audit).
//
// Codex flagged that scripts/upload-fortress.js and scripts/fetch-anthropic.js
// have response body caps but no network timeout — a slow or stalled
// Fortress endpoint can hang the daemon indefinitely.
//
// The fix mirrors src/shield/sources/fortress.js: req.setTimeout(ms, cb)
// where the callback destroys the request with a clear error.
//
// We don't want to spin up an HTTP server in tests just to assert
// timeout semantics. Instead we sanity-check the constants and grep
// the source to make sure the setTimeout call survives future edits.
// This is a regression bench, not a functional one.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, '..');

async function read(rel) {
  return readFile(join(repoRoot, rel), 'utf8');
}

test('F-22: upload-fortress.js declares a FORTRESS_REQUEST_TIMEOUT_MS constant', async () => {
  const src = await read('scripts/upload-fortress.js');
  // Must be a finite, positive number — using a Number literal so a
  // refactor that accidentally replaces it with a NaN/string lights up.
  const match = src.match(/const\s+FORTRESS_REQUEST_TIMEOUT_MS\s*=\s*([0-9_]+)/);
  assert.ok(match, 'FORTRESS_REQUEST_TIMEOUT_MS constant must be present');
  const value = Number(match[1].replace(/_/g, ''));
  assert.ok(Number.isFinite(value) && value > 0, 'timeout must be a finite positive number');
  assert.ok(value >= 5000 && value <= 120_000,
    `timeout should be between 5s and 120s for a small JSON POST; got ${value}ms`);
});

test('F-22: upload-fortress.js wires req.setTimeout to destroy on stall', async () => {
  const src = await read('scripts/upload-fortress.js');
  // The setTimeout call must be in postJson and reference the constant.
  assert.match(src, /req\.setTimeout\(FORTRESS_REQUEST_TIMEOUT_MS/,
    'req.setTimeout must reference the constant');
  // The callback must destroy the request with a meaningful error.
  assert.match(src, /req\.destroy\(new Error\(`Fortress request timed out after \$\{FORTRESS_REQUEST_TIMEOUT_MS\}ms`\)\)/,
    'timeout callback must destroy the request with a Fortress-specific error');
});

test('F-22: fetch-anthropic.js declares the same timeout constant', async () => {
  const src = await read('scripts/fetch-anthropic.js');
  const match = src.match(/const\s+FORTRESS_REQUEST_TIMEOUT_MS\s*=\s*([0-9_]+)/);
  assert.ok(match, 'FORTRESS_REQUEST_TIMEOUT_MS constant must be present');
  const value = Number(match[1].replace(/_/g, ''));
  assert.ok(Number.isFinite(value) && value > 0);
  assert.ok(value >= 5000 && value <= 120_000);
});

test('F-22: fetch-anthropic.js wires req.setTimeout to destroy on stall', async () => {
  const src = await read('scripts/fetch-anthropic.js');
  assert.match(src, /req\.setTimeout\(FORTRESS_REQUEST_TIMEOUT_MS/);
  assert.match(src, /req\.destroy\(new Error\(`Fortress request timed out after \$\{FORTRESS_REQUEST_TIMEOUT_MS\}ms`\)\)/);
});

test('F-22: both scripts use the SAME timeout value (consistency)', async () => {
  const a = (await read('scripts/upload-fortress.js'))
    .match(/const\s+FORTRESS_REQUEST_TIMEOUT_MS\s*=\s*([0-9_]+)/)[1].replace(/_/g, '');
  const b = (await read('scripts/fetch-anthropic.js'))
    .match(/const\s+FORTRESS_REQUEST_TIMEOUT_MS\s*=\s*([0-9_]+)/)[1].replace(/_/g, '');
  assert.equal(a, b, 'the two scripts should share the same Fortress timeout');
});

// Functional sanity check: spin up a server that NEVER responds, then
// invoke a minimal POST with a short timeout, and verify the promise
// rejects within the deadline. Cheap end-to-end proof that the
// pattern actually fires.

import { createServer } from 'node:http';
import { request as httpRequest } from 'node:http';

test('F-22 functional: req.setTimeout actually fires on a stalled HTTP server', async (t) => {
  // Spin up an HTTP server that accepts the request but never writes a
  // response — the exact scenario the timeout protects against.
  const server = createServer(() => { /* never send headers */ });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  t.after(() => new Promise((r) => server.close(() => r())));

  // Replicate the postJson pattern with a 100 ms timeout to keep the
  // test fast. If the setTimeout pattern is broken, this would hang
  // until Node's process timeout, which the test runner would catch
  // as a separate failure — either way we'd be surprised.
  const TIMEOUT_MS = 100;
  const start = Date.now();
  await assert.rejects(
    new Promise((resolve, reject) => {
      const req = httpRequest({ hostname: '127.0.0.1', port, method: 'POST', path: '/' }, () => {
        resolve('unexpected response');
      });
      req.on('error', reject);
      req.setTimeout(TIMEOUT_MS, () => {
        req.destroy(new Error(`request timed out after ${TIMEOUT_MS}ms`));
      });
      req.write('{}');
      req.end();
    }),
    (err) => err instanceof Error && /timed out/.test(err.message),
  );
  const elapsed = Date.now() - start;
  assert.ok(elapsed >= TIMEOUT_MS - 20, `should fire near timeoutMs; got ${elapsed}ms`);
  assert.ok(elapsed < 1000, `should not wait far past timeoutMs; got ${elapsed}ms`);
});
