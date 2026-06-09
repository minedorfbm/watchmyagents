// MITRE starter policy bundle — v1.2.1.
//
// Locks the shipped examples/policies/mitre-starter.json against the
// policy engine:
//   - file loads via loadPolicies() (catches ReDoS-heuristic regressions
//     in any regex we add later, plus schema drift)
//   - every advertised technique row fires on its canonical trigger
//   - every policy ships in mode='shadow' (lifecycle invariant — see
//     [[project_recursive_fractal_loop]])
//
// If this suite goes red, the starter is either no longer compatible
// with the policy DSL or the lifecycle invariant was broken in a
// hand-edit. Both are blocking for release.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadPolicies, evaluate } from '../src/shield/policy.js';

const STARTER_PATH = new URL('../examples/policies/mitre-starter.json', import.meta.url);

test('mitre starter: loads cleanly via loadPolicies (regex + schema validation)', async () => {
  const ruleset = await loadPolicies(STARTER_PATH.pathname);
  assert.ok(Array.isArray(ruleset.policies));
  assert.ok(ruleset.policies.length >= 10, `expected at least 10 starter policies, got ${ruleset.policies.length}`);
  assert.equal(ruleset.default.action, 'allow');
});

test('mitre starter: every policy ships in mode=shadow (lifecycle invariant)', async () => {
  const ruleset = await loadPolicies(STARTER_PATH.pathname);
  for (const p of ruleset.policies) {
    assert.equal(p.mode, 'shadow', `policy ${p.id} must ship in shadow, got ${p.mode}`);
  }
});

test('mitre starter: every policy carries a MITRE-prefixed id + human-readable message', async () => {
  const ruleset = await loadPolicies(STARTER_PATH.pathname);
  for (const p of ruleset.policies) {
    assert.match(p.id, /^mitre-/, `id ${p.id} must be MITRE-prefixed`);
    assert.equal(typeof p.message, 'string');
    assert.ok(p.message.length > 20, `message for ${p.id} is too short to be useful`);
  }
});

test('mitre starter: T1567 fires on a >1MB outbound POST', async () => {
  const ruleset = await loadPolicies(STARTER_PATH.pathname);
  const r = evaluate({
    action_type: 'tool_use',
    tool_name: 'web_fetch',
    input: { method: 'POST', bytes: 5_000_000 },
  }, ruleset);
  assert.equal(r.decision, 'deny');
  assert.equal(r.rule_id, 'mitre-t1567-exfil-large-post');
});

test('mitre starter: T1041 fires on non-allowlisted host (and NOT on allowlisted)', async () => {
  const ruleset = await loadPolicies(STARTER_PATH.pathname);
  const bad = evaluate({
    action_type: 'tool_use',
    tool_name: 'web_fetch',
    input: { url: 'https://evil.example/c2-channel' },
  }, ruleset);
  assert.equal(bad.rule_id, 'mitre-t1041-c2-host-allowlist');

  const good = evaluate({
    action_type: 'tool_use',
    tool_name: 'web_fetch',
    input: { url: 'https://api.anthropic.com/v1/messages' },
  }, ruleset);
  // Should NOT match T1041 (host is allowlisted); falls through to default allow.
  assert.equal(good.rule_id, null);
  assert.equal(good.decision, 'allow');
});

test('mitre starter: T1485 fires on rm -rf', async () => {
  const ruleset = await loadPolicies(STARTER_PATH.pathname);
  const r = evaluate({
    tool_name: 'bash',
    input: { command: 'rm -rf /var/log/wma-evidence' },
  }, ruleset);
  assert.equal(r.rule_id, 'mitre-t1485-data-destruction');
});

test('mitre starter: T1548 fires on sudo / pkexec', async () => {
  const ruleset = await loadPolicies(STARTER_PATH.pathname);
  for (const cmd of ['sudo cat /etc/shadow', 'pkexec /bin/bash', 'doas vim']) {
    const r = evaluate({ tool_name: 'bash', input: { command: cmd } }, ruleset);
    assert.equal(r.rule_id, 'mitre-t1548-privilege-escalation', `expected T1548 for: ${cmd}`);
  }
});

test('mitre starter: T1059 fires on improbably long bash command (length_gt)', async () => {
  const ruleset = await loadPolicies(STARTER_PATH.pathname);
  const r = evaluate({
    tool_name: 'bash',
    input: { command: 'a'.repeat(3000) },
  }, ruleset);
  assert.equal(r.rule_id, 'mitre-t1059-bash-command-length');
});

test('mitre starter: T1083 fires after-hours (uses ctx.hour_of_day_utc)', async () => {
  const ruleset = await loadPolicies(STARTER_PATH.pathname);
  // 23:00 UTC → late variant fires.
  const late = evaluate(
    { tool_name: 'bash', input: { command: 'ls /' } },
    ruleset,
    { hour_of_day_utc: 23 },
  );
  assert.equal(late.rule_id, 'mitre-t1083-after-hours-discovery');

  // 03:00 UTC → early variant fires.
  const early = evaluate(
    { tool_name: 'bash', input: { command: 'find / -name "*.key"' } },
    ruleset,
    { hour_of_day_utc: 3 },
  );
  assert.equal(early.rule_id, 'mitre-t1083-after-hours-discovery-early');

  // 14:00 UTC → no match (business hours).
  const work = evaluate(
    { tool_name: 'bash', input: { command: 'ls /' } },
    ruleset,
    { hour_of_day_utc: 14 },
  );
  assert.equal(work.decision, 'allow');
});

test('mitre starter: T1020 throttle fires on high recent_error_rate + enough samples', async () => {
  const ruleset = await loadPolicies(STARTER_PATH.pathname);
  const r = evaluate(
    { action_type: 'tool_use', tool_name: 'web_fetch' },
    ruleset,
    { recent_error_rate: 0.75, event_count_recent: 5 },
  );
  assert.equal(r.rule_id, 'mitre-t1020-flailing-agent-throttle');

  // High rate but not enough samples → no throttle yet.
  const small = evaluate(
    { action_type: 'tool_use', tool_name: 'web_fetch' },
    ruleset,
    { recent_error_rate: 0.9, event_count_recent: 2 },
  );
  assert.equal(small.rule_id, null);
});

test('mitre starter: T1053 fires on persistence-path writes', async () => {
  const ruleset = await loadPolicies(STARTER_PATH.pathname);
  for (const p of ['/etc/cron.d/backdoor', '/Library/LaunchAgents/com.evil.plist', '/etc/systemd/system/x.service']) {
    const r = evaluate({ tool_name: 'file_write', input: { path: p } }, ruleset);
    assert.equal(r.rule_id, 'mitre-t1053-cron-persistence', `expected T1053 for: ${p}`);
  }
});

test('mitre starter: T1552 fires on credential-store reads', async () => {
  const ruleset = await loadPolicies(STARTER_PATH.pathname);
  for (const p of ['/home/me/.aws/credentials', '/Users/me/.ssh/id_rsa', '/etc/shadow', '/Users/me/Library/Keychains/login.keychain']) {
    const r = evaluate({ tool_name: 'file_read', input: { path: p } }, ruleset);
    assert.equal(r.rule_id, 'mitre-t1552-credential-store-read', `expected T1552 for: ${p}`);
  }
});

test('mitre starter: benign tool use falls through to default allow', async () => {
  const ruleset = await loadPolicies(STARTER_PATH.pathname);
  const r = evaluate({
    action_type: 'tool_use',
    tool_name: 'web_search',
    input: { query: 'how to set up postgres' },
  }, ruleset, { hour_of_day_utc: 14, recent_error_rate: 0 });
  assert.equal(r.decision, 'allow');
  assert.equal(r.rule_name, '(default)');
});
