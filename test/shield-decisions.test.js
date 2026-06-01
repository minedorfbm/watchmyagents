// Shield DecisionLogger — v1.1.3 Phase 1.D
//
// Verifies that the `mode` field threads correctly from a Shield decision
// down to the NDJSON entry written to disk. Shadow mode must NOT mark the
// row as `status: 'error'` even when the rule said deny/interrupt — the
// agent ran, so the row reflects what happened, not what the rule said.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { DecisionLogger } from '../src/shield/decisions.js';

const AGENT_ID = 'agent_01TESTSHADOW1234567';

function freshLogDir() {
  return mkdtempSync(join(tmpdir(), 'wma-shield-dec-'));
}

function readOnlyLine(logDir, agentId) {
  const sub = join(logDir, agentId);
  const files = readdirSync(sub).filter((f) => f.endsWith('.ndjson'));
  assert.equal(files.length, 1, `expected exactly one ndjson, got ${files.join(', ')}`);
  const raw = readFileSync(join(sub, files[0]), 'utf8').trim();
  const lines = raw.split('\n').filter(Boolean);
  assert.equal(lines.length, 1, `expected exactly one line, got ${lines.length}`);
  return JSON.parse(lines[0]);
}

test('Phase 1.D: enforce + deny → status=error and output.mode=enforce', async () => {
  const logDir = freshLogDir();
  const log = new DecisionLogger({ logDir, agentId: AGENT_ID, sessionId: 'sesn_X' });
  await log.record({
    sourceEvent: { id: 'evt_1', type: 'tool_use', name: 'bash', input: { command: 'rm -rf /' } },
    decision: 'deny',
    ruleId: 'r-1', ruleName: 'no-bash', message: 'blocked',
    decidedInMs: 3,
    mode: 'enforce',
  });
  const entry = readOnlyLine(logDir, AGENT_ID);
  assert.equal(entry.action_type, 'shield_decision');
  assert.equal(entry.status, 'error', 'enforce + deny actually blocked → status=error');
  assert.equal(entry.error, 'blocked');
  assert.equal(entry.output.decision, 'deny');
  assert.equal(entry.output.mode, 'enforce');
});

test('Phase 1.D: shadow + deny → status=ok (tool ran) and output.mode=shadow', async () => {
  const logDir = freshLogDir();
  const log = new DecisionLogger({ logDir, agentId: AGENT_ID, sessionId: 'sesn_Y' });
  await log.record({
    sourceEvent: { id: 'evt_2', type: 'tool_use', name: 'bash', input: { command: 'ls' } },
    decision: 'deny',
    ruleId: 'r-2', ruleName: 'shadow-no-bash', message: 'would-block',
    decidedInMs: 2,
    mode: 'shadow',
  });
  const entry = readOnlyLine(logDir, AGENT_ID);
  assert.equal(entry.status, 'ok', 'shadow never enforces — row must not be marked as error');
  assert.equal(entry.error, null, 'no error message on the ndjson row (tool actually ran)');
  assert.equal(entry.output.decision, 'deny', 'rule\'s would-be decision is still captured for calibration');
  assert.equal(entry.output.mode, 'shadow');
  assert.equal(entry.output.message, 'would-block', 'rule message preserved for diff-in-diff efficacy');
});

test('Phase 1.D: shadow + interrupt → status=ok and output.mode=shadow', async () => {
  const logDir = freshLogDir();
  const log = new DecisionLogger({ logDir, agentId: AGENT_ID, sessionId: 'sesn_Z' });
  await log.record({
    sourceEvent: { id: 'evt_3', type: 'tool_use', name: 'web_fetch', input: { url: 'https://exfil.example' } },
    decision: 'interrupt',
    ruleId: 'r-3', ruleName: 'shadow-exfil', message: 'would-interrupt',
    decidedInMs: 1,
    mode: 'shadow',
  });
  const entry = readOnlyLine(logDir, AGENT_ID);
  assert.equal(entry.status, 'ok');
  assert.equal(entry.output.decision, 'interrupt');
  assert.equal(entry.output.mode, 'shadow');
});

test('Phase 1.D: enforce + allow → status=ok and output.mode=enforce', async () => {
  const logDir = freshLogDir();
  const log = new DecisionLogger({ logDir, agentId: AGENT_ID, sessionId: 'sesn_W' });
  await log.record({
    sourceEvent: { id: 'evt_4', type: 'tool_use', name: 'web_search', input: { query: 'hi' } },
    decision: 'allow',
    ruleId: null, ruleName: '(default)', message: null,
    decidedInMs: 0,
    mode: 'enforce',
  });
  const entry = readOnlyLine(logDir, AGENT_ID);
  assert.equal(entry.status, 'ok');
  assert.equal(entry.output.decision, 'allow');
  assert.equal(entry.output.mode, 'enforce');
});

test('Phase 1.D: missing mode field defaults to enforce (backwards compat)', async () => {
  const logDir = freshLogDir();
  const log = new DecisionLogger({ logDir, agentId: AGENT_ID, sessionId: 'sesn_V' });
  await log.record({
    sourceEvent: { id: 'evt_5', type: 'tool_use', name: 'bash' },
    decision: 'deny',
    ruleId: 'r-5', ruleName: 'old-rule', message: 'blocked',
    decidedInMs: 1,
    // mode omitted — older callers from before Phase 1.D
  });
  const entry = readOnlyLine(logDir, AGENT_ID);
  assert.equal(entry.status, 'error', 'absent mode → defaults to enforce → deny is real');
  assert.equal(entry.output.mode, 'enforce');
});
