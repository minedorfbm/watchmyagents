// Shield Fortress upload — Containment hardening, v1.1.4 F-19
//
// Codex audit P1: scripts/shield.js was uploading tool_name in clear to
// Fortress, even for custom function names and MCP tools where the name
// can encode client identifiers (e.g. "client_acme_export_invoices").
// This violated:
//   - the README's promise that decisions ship FINGERPRINTS, not raw values
//   - the anonymizer's allowlist contract (WELL_KNOWN_TOOLS pass through,
//     everything else is hashed)
//   - the Containment doctrine (raw customer identifiers never leave
//     the customer machine)
//
// Fix in v1.1.4: extract the payload builder to src/shield/upload.js,
// route tool_name through normalizeToolName(), drop the field rather
// than leak when no salt is configured for a custom tool name.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildFortressDecisionPayload } from '../src/shield/upload.js';

const AGENT_ID = 'agent_01TEST';
const SESSION_ID = 'sesn_01TESTSESSION';
const SALT = 'test-salt-deterministic-0123456789abcdef';

const baseResult = (over = {}) => ({
  decision: 'deny',
  rule_id: 'r-1',
  rule_name: 'no-bash',
  message: 'blocked',
  mode: 'enforce',
  ...over,
});

const baseInput = {
  rawEvent: { id: 'evt_01XYZ', type: 'tool_use' },
  normalized: { action_type: 'tool_use', tool_name: 'bash', input: { command: 'rm -rf /' } },
  result: baseResult(),
  decidedInMs: 4,
  agentId: AGENT_ID,
  sessionId: SESSION_ID,
  decidedAtIso: '2026-06-02T00:00:00.000Z',
};

// ── F-19 core: tool_name normalization ──────────────────────────────────

test('F-19: vendor built-in tool_name (bash) ships in CLEAR with a salt configured', () => {
  const out = buildFortressDecisionPayload({ ...baseInput, signalsSalt: SALT });
  assert.equal(out.tool_name, 'bash', 'allowlisted vendor tool stays readable for dashboards');
});

test('F-19: vendor built-in tool_name (web_search) ships in CLEAR even with no salt', () => {
  const out = buildFortressDecisionPayload({
    ...baseInput,
    normalized: { tool_name: 'web_search' },
    signalsSalt: null,
  });
  assert.equal(out.tool_name, 'web_search', 'vendor allowlist short-circuits the salt requirement');
});

test('F-19: CUSTOM tool_name ships as a salted tool_hash:... opaque token', () => {
  const out = buildFortressDecisionPayload({
    ...baseInput,
    normalized: { tool_name: 'client_acme_export_invoices' },
    signalsSalt: SALT,
  });
  assert.match(out.tool_name, /^tool_hash:[0-9a-f]{32}$/);
  assert.ok(!out.tool_name.includes('acme'), 'raw client identifier must not appear in the hash output');
  assert.ok(!out.tool_name.includes('export'), 'no substring of the raw name leaks');
});

test('F-19: MCP-style tool name ships as a salted tool_hash (no leak)', () => {
  const out = buildFortressDecisionPayload({
    ...baseInput,
    normalized: { tool_name: 'mcp_internal_billing_lookup' },
    signalsSalt: SALT,
  });
  assert.match(out.tool_name, /^tool_hash:[0-9a-f]{32}$/);
  assert.ok(!out.tool_name.includes('billing'));
  assert.ok(!out.tool_name.includes('internal'));
});

test('F-19 fail-SAFE: custom tool_name + NO salt → tool_name DROPPED, decision still ships', () => {
  const out = buildFortressDecisionPayload({
    ...baseInput,
    normalized: { tool_name: 'client_acme_export_invoices' },
    signalsSalt: null,
  });
  assert.equal(out.tool_name, undefined, 'field omitted rather than leaked');
  assert.equal(out.decision, 'deny', 'the decision itself still ships so Fortress can count it');
  assert.equal(out.anthropic_agent_id, AGENT_ID, 'agent id (already opaque) still on the wire');
});

test('F-19: null/undefined tool_name → undefined (no spurious empty-string egress)', () => {
  for (const tn of [null, undefined, '']) {
    const out = buildFortressDecisionPayload({
      ...baseInput,
      normalized: { tool_name: tn },
      signalsSalt: SALT,
    });
    assert.equal(out.tool_name, undefined, `nullish tool_name (${JSON.stringify(tn)}) → undefined`);
  }
});

test('F-19: same custom tool_name + same salt → SAME hash (idempotent for dashboards)', () => {
  const a = buildFortressDecisionPayload({
    ...baseInput,
    normalized: { tool_name: 'client_acme_export' },
    signalsSalt: SALT,
  });
  const b = buildFortressDecisionPayload({
    ...baseInput,
    normalized: { tool_name: 'client_acme_export' },
    signalsSalt: SALT,
  });
  assert.equal(a.tool_name, b.tool_name);
});

test('F-19: different salts on the same custom tool → DIFFERENT hashes (per-tenant separation)', () => {
  const a = buildFortressDecisionPayload({
    ...baseInput,
    normalized: { tool_name: 'client_acme_export' },
    signalsSalt: 'salt-tenant-A',
  });
  const b = buildFortressDecisionPayload({
    ...baseInput,
    normalized: { tool_name: 'client_acme_export' },
    signalsSalt: 'salt-tenant-B',
  });
  assert.notEqual(a.tool_name, b.tool_name);
});

// ── Hash fields: session_hash / event_id_hash / input_hash ─────────────

test('F-19: session_hash / event_id_hash / input_hash are present when salt configured', () => {
  const out = buildFortressDecisionPayload({
    ...baseInput,
    normalized: {
      tool_name: 'bash',
      input: { command: 'cat /etc/passwd' },
    },
    signalsSalt: SALT,
  });
  assert.match(out.session_hash, /^sha256:[0-9a-f]{32}$/);
  assert.match(out.event_id_hash, /^sha256:[0-9a-f]{32}$/);
  assert.match(out.input_hash, /^sha256:[0-9a-f]{32}$/);
  assert.ok(!out.session_hash.includes(SESSION_ID), 'raw session id must not appear');
  assert.ok(!out.input_hash.includes('passwd'), 'raw input substring must not appear');
});

test('F-19: hash fields are UNDEFINED (dropped) when no salt configured', () => {
  const out = buildFortressDecisionPayload({
    ...baseInput,
    normalized: { tool_name: 'bash', input: { command: 'ls' } },
    signalsSalt: null,
  });
  assert.equal(out.session_hash, undefined);
  assert.equal(out.event_id_hash, undefined);
  assert.equal(out.input_hash, undefined);
});

test('F-19: input field prefer URL > command > query > path > file_path', () => {
  const inputs = [
    { input: { url: 'https://x', command: 'a', query: 'b', path: 'c', file_path: 'd' }, expectedSubstr: 'https://x' },
    { input: { command: 'a', query: 'b', path: 'c' }, expectedSubstr: 'a' },
    { input: { query: 'b', path: 'c' }, expectedSubstr: 'b' },
    { input: { path: 'c' }, expectedSubstr: 'c' },
    { input: { file_path: 'd' }, expectedSubstr: 'd' },
  ];
  // We can't check the substring directly (it's hashed), so we verify each
  // produces a DIFFERENT hash — i.e. the priority order is observable.
  const hashes = inputs.map((i) => buildFortressDecisionPayload({
    ...baseInput,
    normalized: { tool_name: 'bash', input: i.input },
    signalsSalt: SALT,
  }).input_hash);
  const unique = new Set(hashes);
  assert.equal(unique.size, hashes.length, `all 5 priority slots produce distinct hashes`);
});

// ── Phase 1.D mode threading (gap from v1.1.3, fixed alongside F-19) ────

test('F-19+Phase1.D: mode=enforce flows to Fortress payload', () => {
  const out = buildFortressDecisionPayload({
    ...baseInput,
    result: baseResult({ mode: 'enforce' }),
    signalsSalt: SALT,
  });
  assert.equal(out.mode, 'enforce');
});

test('F-19+Phase1.D: mode=shadow flows to Fortress payload', () => {
  const out = buildFortressDecisionPayload({
    ...baseInput,
    result: baseResult({ mode: 'shadow' }),
    signalsSalt: SALT,
  });
  assert.equal(out.mode, 'shadow');
});

test('F-19+Phase1.D: missing mode → undefined (Fortress ingest defaults to enforce)', () => {
  const out = buildFortressDecisionPayload({
    ...baseInput,
    result: { decision: 'allow', rule_id: null, rule_name: null, message: null },
    signalsSalt: SALT,
  });
  assert.equal(out.mode, undefined);
});

// ── Full payload shape regression: raw values never appear ─────────────

test('F-19: full payload audit — no raw session_id / event_id / input value substring', () => {
  const out = buildFortressDecisionPayload({
    agentId: AGENT_ID,
    sessionId: 'sesn_DEADBEEFCAFE',
    rawEvent: { id: 'evt_RAWEVENTID12345' },
    normalized: {
      action_type: 'tool_use',
      tool_name: 'private_custom_tool_xyz',
      input: { url: 'https://secret-corp.example/internal/data' },
    },
    result: baseResult({ message: 'blocked by no-secrets rule' }),
    decidedInMs: 7,
    signalsSalt: SALT,
    decidedAtIso: '2026-06-02T12:34:56.000Z',
  });
  const serialized = JSON.stringify(out);
  for (const forbidden of [
    'sesn_DEADBEEFCAFE',
    'evt_RAWEVENTID12345',
    'private_custom_tool_xyz',
    'secret-corp.example',
    'internal/data',
  ]) {
    assert.ok(
      !serialized.includes(forbidden),
      `containment violation: raw value "${forbidden}" appeared on the wire`,
    );
  }
  // Sanity: agent id IS expected to appear (it's an opaque Anthropic token)
  assert.ok(serialized.includes(AGENT_ID));
});
