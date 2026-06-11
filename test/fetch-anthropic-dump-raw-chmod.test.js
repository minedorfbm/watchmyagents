// v1.4.1 F-34 (P2 Codex audit on v1.4.0) — regression test.
//
// The `wma-fetch --dump-raw` path appends raw API events to
// `<logDir>/<agentId>/raw-<sid>.jsonl`. The dir + file MUST end up at
// 0700/0600 — even when the dir or file ALREADY EXISTS with looser
// perms (Node's mkdir/appendFile `mode` is creation-only).
//
// We can't easily exercise the full CLI here (would need a fake
// Anthropic API). Instead we lock the building block: the exported
// `tightenMode` helper from src/logger.js correctly downgrades perms
// on a pre-existing path. The fetch-anthropic.js change wires it into
// the dump-raw path immediately after mkdir + after the first append.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, chmod, stat, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { tightenMode } from '../src/logger.js';

test('F-34: tightenMode is exported from src/logger.js', () => {
  assert.equal(typeof tightenMode, 'function');
});

test('F-34: tightenMode downgrades a pre-existing loose dir to 0700', async () => {
  const root = await mkdtemp(join(tmpdir(), 'wma-f34-dir-'));
  try {
    const loose = join(root, 'pre-existing');
    // Simulate the wild: a prior wma-fetch run or hand mkdir left this
    // directory at 0755 (default umask) — that's the exact scenario
    // F-34 wants to catch.
    await mkdir(loose, { recursive: true });
    await chmod(loose, 0o755);

    const before = await stat(loose);
    assert.equal(before.mode & 0o777, 0o755);

    await tightenMode(loose, 0o700);

    const after = await stat(loose);
    assert.equal(after.mode & 0o777, 0o700);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('F-34: tightenMode downgrades a pre-existing loose file to 0600', async () => {
  const root = await mkdtemp(join(tmpdir(), 'wma-f34-file-'));
  try {
    const loose = join(root, 'raw-sess.jsonl');
    await writeFile(loose, '{"event":1}\n');
    await chmod(loose, 0o644);

    const before = await stat(loose);
    assert.equal(before.mode & 0o777, 0o644);

    await tightenMode(loose, 0o600);

    const after = await stat(loose);
    assert.equal(after.mode & 0o777, 0o600);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('F-34: tightenMode is best-effort — non-existent path does not throw', async () => {
  // Containment doctrine: chmod failures must NEVER break the calling
  // code. tightenMode catches and swallows.
  await assert.doesNotReject(async () => {
    await tightenMode('/tmp/wma-f34-nonexistent-xyz-' + Date.now(), 0o700);
  });
});
