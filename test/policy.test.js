// Shield policy loader — v1.1.2 F-14 Codex audit fix
//
// Tests the validation gates that loadPolicies() applies to local JSON
// policy files. The runtime evaluator is "first match wins" and falls
// back to ruleset.default.action, so any typo in default that slips
// through the loader silently breaks enforcement.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, unlinkSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadPolicies } from '../src/shield/policy.js';

const tmpRoot = mkdtempSync(join(tmpdir(), 'wma-policy-test-'));
let counter = 0;
function writeTmpPolicy(obj) {
  const path = join(tmpRoot, `policy-${++counter}.json`);
  writeFileSync(path, JSON.stringify(obj), { encoding: 'utf8', mode: 0o600 });
  return path;
}

// ── existing behavior (regression safety) ────────────────────────────────

test('loadPolicies accepts a minimal valid file with no default (defaults to allow)', async () => {
  const path = writeTmpPolicy({ policies: [{ id: 'p1', action: 'allow', match: {} }] });
  const data = await loadPolicies(path);
  assert.equal(data.default.action, 'allow', 'missing default → defaults to allow');
  assert.equal(data.policies.length, 1);
  unlinkSync(path);
});

test('loadPolicies accepts an explicit default.action of allow/deny/interrupt', async () => {
  for (const action of ['allow', 'deny', 'interrupt']) {
    const path = writeTmpPolicy({ policies: [], default: { action } });
    const data = await loadPolicies(path);
    assert.equal(data.default.action, action);
    unlinkSync(path);
  }
});

test('loadPolicies rejects a policy with an unsupported per-rule action', async () => {
  const path = writeTmpPolicy({ policies: [{ id: 'bad', action: 'maybe', match: {} }] });
  await assert.rejects(loadPolicies(path), /unsupported action/);
  unlinkSync(path);
});

// ── v1.1.2 F-14: default.action must be in {allow, deny, interrupt} ─────

test('F-14: loadPolicies rejects an invalid default.action like "drop"', async () => {
  const path = writeTmpPolicy({ policies: [], default: { action: 'drop' } });
  await assert.rejects(
    loadPolicies(path),
    /default\.action "drop" is invalid/,
    'a typo in default.action must fail loud at load time',
  );
  unlinkSync(path);
});

test('F-14: loadPolicies rejects default.action being a number', async () => {
  const path = writeTmpPolicy({ policies: [], default: { action: 42 } });
  await assert.rejects(loadPolicies(path), /default\.action/);
  unlinkSync(path);
});

test('F-14: loadPolicies rejects default.action being an empty string', async () => {
  const path = writeTmpPolicy({ policies: [], default: { action: '' } });
  await assert.rejects(loadPolicies(path), /default\.action/);
  unlinkSync(path);
});

test('F-14: loadPolicies rejects default with a typo in the action name (case-sensitive)', async () => {
  const path = writeTmpPolicy({ policies: [], default: { action: 'Deny' } });
  await assert.rejects(loadPolicies(path), /default\.action/);
  unlinkSync(path);
});
