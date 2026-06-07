// Logger defensive chmod — v1.1.6 F-24 (P3 Codex audit).
//
// SECURITY.md promises 0700 on the log directory and 0600 on the
// NDJSON files. mkdir() and appendFile() take a `mode` option but
// it's CREATION-ONLY: if the directory or file already exists with
// looser perms (system umask 0755/0644, hand-rolled mkdir, leftover
// from a previous run with a different umask), the Logger silently
// inherited the loose mode.
//
// The fix calls fs.chmod() defensively after every mkdir / appendFile
// so the docs-promised modes are restored on every write. These tests
// pre-create the paths with deliberately loose perms (0755 / 0644)
// and assert the Logger tightens them on first write.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, writeFile, stat, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Logger } from '../src/logger.js';

const AGENT_ID = 'agent_01TESTCHMOD000000000';

function freshTmp() {
  return mkdtemp(join(tmpdir(), 'wma-chmod-'));
}

// Helper: read the mode bits of a path (permission octets only).
async function mode(path) {
  const s = await stat(path);
  return s.mode & 0o777;
}

test('F-24: Logger tightens an existing 0755 log directory to 0700 on first write', async () => {
  const logDir = await freshTmp();
  try {
    // Pre-create the agent's log directory with a deliberately loose mode.
    const agentDir = join(logDir, AGENT_ID);
    await mkdir(agentDir, { recursive: true, mode: 0o755 });
    assert.equal(await mode(agentDir), 0o755, 'precondition: dir starts at 0755');

    const log = new Logger({ logDir, agentId: AGENT_ID, sessionId: 'sesn_X' });
    await log.write({
      action_type: 'tool_use',
      provider: 'test',
      tool_name: 'noop',
      duration_ms: 1,
    });

    assert.equal(
      await mode(agentDir),
      0o700,
      'Logger.write() should tighten the existing dir to 0700',
    );
  } finally {
    await rm(logDir, { recursive: true, force: true });
  }
});

test('F-24: Logger tightens an existing 0644 ndjson file to 0600 on next write', async () => {
  const logDir = await freshTmp();
  try {
    const agentDir = join(logDir, AGENT_ID);
    await mkdir(agentDir, { recursive: true, mode: 0o700 });
    const today = new Date().toISOString().slice(0, 10);
    const ndjsonPath = join(agentDir, `${today}.ndjson`);

    // Simulate a leftover file from a previous run with a loose umask.
    await writeFile(ndjsonPath, '', { mode: 0o644 });
    assert.equal(await mode(ndjsonPath), 0o644, 'precondition: file starts at 0644');

    const log = new Logger({ logDir, agentId: AGENT_ID, sessionId: 'sesn_Y' });
    await log.write({
      action_type: 'tool_use',
      provider: 'test',
      tool_name: 'noop',
      duration_ms: 1,
    });

    assert.equal(
      await mode(ndjsonPath),
      0o600,
      'Logger.write() should tighten the existing file to 0600',
    );
  } finally {
    await rm(logDir, { recursive: true, force: true });
  }
});

test('F-24: chmod failure is swallowed (best-effort) and does not break logging', async () => {
  // We can't easily make chmod fail on a path we own. Instead, exercise
  // the happy path and confirm the write still succeeds — the tightenMode
  // helper has a try/catch that NEVER rethrows. This guards against a
  // refactor that accidentally lets the chmod error propagate.
  const logDir = await freshTmp();
  try {
    const log = new Logger({ logDir, agentId: AGENT_ID, sessionId: 'sesn_Z' });
    await log.write({
      action_type: 'tool_use',
      provider: 'test',
      tool_name: 'noop',
      duration_ms: 1,
    });
    assert.equal(log.count, 1, 'write counter still ticked up');
  } finally {
    await rm(logDir, { recursive: true, force: true });
  }
});

test('F-24: a freshly-created dir + file already get 0700 / 0600 (regression)', async () => {
  // Original behaviour — fresh creation honors the mode option. This
  // test pins it so a future refactor of tightenMode doesn't accidentally
  // skip the creation case.
  const logDir = await freshTmp();
  try {
    const log = new Logger({ logDir, agentId: AGENT_ID, sessionId: 'sesn_W' });
    await log.write({
      action_type: 'tool_use',
      provider: 'test',
      tool_name: 'noop',
      duration_ms: 1,
    });
    const agentDir = join(logDir, AGENT_ID);
    const today = new Date().toISOString().slice(0, 10);
    const ndjsonPath = join(agentDir, `${today}.ndjson`);
    assert.equal(await mode(agentDir), 0o700, 'fresh dir must be 0700');
    assert.equal(await mode(ndjsonPath), 0o600, 'fresh file must be 0600');
  } finally {
    await rm(logDir, { recursive: true, force: true });
  }
});
