// Containment invariant — V1 (PR-E)
//
// These tests verify the WMA architectural invariant: no raw payload bytes
// can escape via the signals payload that ships to Fortress. We inject
// fixtures with KNOWN secret strings into the SignalsAggregator and then
// stringify its output to assert the secrets do NOT appear anywhere in
// the signals — neither in plain text, nor in any field name, nor in any
// nested structure.
//
// A regression that adds a new field carrying raw content flips one of
// these tests red on the next commit.
//
// See: docs/CONTAINMENT.md

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SignalsAggregator, hashWithSalt, normalizeToolName } from '../src/anonymizer.js';

// Distinctive sentinel strings chosen so a substring match would never
// false-positive against legitimate signals payload content.
const SECRET_URL      = 'https://internal.example.com/secret-xyzWKL2026';
const SECRET_COMMAND  = 'curl -H "Authorization: Bearer SECRETtoken9999" example.com';
const SECRET_QUERY    = 'SELECT password FROM users WHERE id=42_SECRET_QUERY_MARKER';
const SECRET_PROMPT   = 'WMA_TEST_SECRET_PROMPT_PLAINTEXT_MARKER';
const SECRET_OUTPUT   = 'WMA_TEST_SECRET_OUTPUT_CONFIDENTIAL_MARKER';
const SECRET_ERROR    = 'Could not parse: SECRET_ERROR_BODY_42_MARKER';
const SECRET_PATH     = '/Users/customer/.ssh/id_rsa_SECRET_PATH_MARKER';

const SALT = 'test-salt-deterministic-1234567890abcdef';

function syntheticEvent(overrides = {}) {
  return {
    id: 'evt_synthetic',
    provider: 'anthropic-managed',
    agent_id: 'agent_under_test',
    session_id: 'sess_under_test',
    timestamp: '2026-05-30T20:00:00Z',
    status: 'ok',
    action_type: 'tool_use',
    tool_name: 'web_fetch',
    duration_ms: 142,
    ...overrides,
  };
}

// ── Invariant tests ─────────────────────────────────────────────────────

test('Containment: SignalsAggregator output never carries raw input bytes', () => {
  const agg = new SignalsAggregator({ salt: SALT });
  agg.add(syntheticEvent({
    input: {
      url: SECRET_URL,
      query: SECRET_QUERY,
      command: SECRET_COMMAND,
      path: SECRET_PATH,
    },
  }));
  const out = agg.finalize();
  const serialized = JSON.stringify(out);

  for (const secret of [SECRET_URL, SECRET_QUERY, SECRET_COMMAND, SECRET_PATH]) {
    assert.ok(
      !serialized.includes(secret),
      `Containment leak: raw input substring "${secret}" found in signals output`,
    );
  }
});

test('Containment: SignalsAggregator output never carries raw prompt/output content', () => {
  const agg = new SignalsAggregator({ salt: SALT });
  agg.add(syntheticEvent({
    action_type: 'user_message',
    input: { content: SECRET_PROMPT },
  }));
  agg.add(syntheticEvent({
    id: 'evt_2',
    action_type: 'message',
    output: { content: SECRET_OUTPUT },
  }));
  agg.add(syntheticEvent({
    id: 'evt_3',
    status: 'error',
    error: SECRET_ERROR,
  }));
  const out = agg.finalize();
  const serialized = JSON.stringify(out);

  for (const secret of [SECRET_PROMPT, SECRET_OUTPUT, SECRET_ERROR]) {
    assert.ok(
      !serialized.includes(secret),
      `Containment leak: raw content substring "${secret}" found in signals output`,
    );
  }
});

test('Containment: hashWithSalt is deterministic for the same (value, salt)', () => {
  const h1 = hashWithSalt(SECRET_URL, SALT);
  const h2 = hashWithSalt(SECRET_URL, SALT);
  assert.equal(h1, h2, 'salted hash must be deterministic for same input + salt');
  assert.ok(h1.startsWith('sha256:'), 'IoC hash should have sha256: prefix');
  assert.equal(h1.length, 'sha256:'.length + 32, 'hash is sha256: + 32-char prefix');
});

test('Containment: raw URLs appear as their salted hash in ioc_hashes', () => {
  const agg = new SignalsAggregator({ salt: SALT });
  agg.add(syntheticEvent({ input: { url: SECRET_URL } }));
  const out = agg.finalize();
  const expected = hashWithSalt(SECRET_URL, SALT);
  assert.ok(
    out.payload.ioc_hashes.includes(expected),
    `Expected hashed IoC ${expected} not found in ioc_hashes`,
  );
});

test('Containment: signals payload shape contains only the documented keys', () => {
  const agg = new SignalsAggregator({ salt: SALT });
  agg.add(syntheticEvent({
    input: { url: SECRET_URL },
    output: { content: SECRET_OUTPUT },
  }));
  const out = agg.finalize();

  // Top level: only the envelope and the inner payload + meta. Any new
  // key here is a Containment review trigger.
  const allowedTopLevel = new Set(['window_start', 'window_end', 'payload', '_meta']);
  for (const k of Object.keys(out)) {
    assert.ok(allowedTopLevel.has(k), `Unexpected top-level signals key: "${k}" — needs Containment review`);
  }

  // Inside `payload`: the exact set documented in src/anonymizer.js. A
  // new aggregator output field that carries raw bytes would surface here.
  const allowedPayloadKeys = new Set([
    'counts',
    'tool_counts',
    'latencies_p50_ms', 'latencies_p95_ms',
    'error_rate_by_tool',
    'ioc_hashes',
    'sequences_top10',
    'stop_reasons',
    'tokens_total',
    // v1.0.2 F-6c — opaque session_ids list for operator forensics
    'session_ids',
  ]);
  for (const k of Object.keys(out.payload)) {
    assert.ok(
      allowedPayloadKeys.has(k),
      `Unexpected payload key: "${k}" — adding fields requires Containment review (docs/CONTAINMENT.md)`,
    );
  }
});

test('Containment: SignalsAggregator refuses to operate without a salt', () => {
  assert.throws(() => new SignalsAggregator({}), /salt/);
  assert.throws(() => new SignalsAggregator(), /salt/);
});

// ── F-3 (Codex audit): tool_name Containment ────────────────────────────

test('Containment F-3: custom tool names are hashed before egress', () => {
  // Customer-defined tool name that could carry client/project identifiers.
  // The Codex audit example was literally `client_acme_export`.
  const CUSTOM_TOOL = 'client_acme_export_v2_MARKER';

  const agg = new SignalsAggregator({ salt: SALT });
  agg.add(syntheticEvent({
    tool_name: CUSTOM_TOOL,
    duration_ms: 250,
  }));
  agg.add(syntheticEvent({
    id: 'evt_2',
    tool_name: CUSTOM_TOOL,
    status: 'error',
    duration_ms: 100,
  }));
  const out = agg.finalize();
  const serialized = JSON.stringify(out);

  // The raw custom name MUST NOT appear anywhere — not as a key, not as
  // a value, not as part of a longer string.
  assert.ok(
    !serialized.includes(CUSTOM_TOOL),
    `Containment leak: custom tool name "${CUSTOM_TOOL}" found in signals output`,
  );

  // The expected hashed token should be present — proves the activity was
  // captured WITHOUT revealing the underlying name.
  const expected = normalizeToolName(CUSTOM_TOOL, SALT);
  assert.match(expected, /^tool_hash:[a-f0-9]{32}$/, 'hash token has the documented shape');
  assert.ok(
    serialized.includes(expected),
    `expected hashed token ${expected} not present in signals output`,
  );

  // And the counts/error_rate/latency maps must be keyed by the hashed
  // token, not by the raw name.
  assert.ok(expected in out.payload.tool_counts, 'tool_counts is keyed by hashed name');
  assert.ok(expected in out.payload.error_rate_by_tool, 'error_rate_by_tool is keyed by hashed name');
  assert.ok(expected in out.payload.latencies_p50_ms, 'latencies_p50_ms is keyed by hashed name');
});

test('Containment F-3: well-known vendor built-ins are KEPT in clear (dashboard legibility)', () => {
  // The whitelist is a feature, not a bug: operators must see
  // "web_search" or "bash" in plain text to act on the signals.
  const agg = new SignalsAggregator({ salt: SALT });
  agg.add(syntheticEvent({ tool_name: 'web_search', duration_ms: 50 }));
  agg.add(syntheticEvent({ id: 'evt_2', tool_name: 'bash', duration_ms: 30 }));
  agg.add(syntheticEvent({ id: 'evt_3', tool_name: 'code_execution', duration_ms: 200 }));
  const out = agg.finalize();

  for (const builtin of ['web_search', 'bash', 'code_execution']) {
    assert.ok(builtin in out.payload.tool_counts,
      `well-known built-in "${builtin}" should be kept in clear in tool_counts`);
  }
});

test('Containment F-3: normalizeToolName is deterministic for the same (name, salt)', () => {
  const a = normalizeToolName('custom_unknown_tool', SALT);
  const b = normalizeToolName('custom_unknown_tool', SALT);
  assert.equal(a, b, 'tool_hash must be deterministic so cross-window aggregation works');
  assert.ok(a.startsWith('tool_hash:'));
});

test('Containment F-3: normalizeToolName refuses to operate without salt on unknown tools', () => {
  // Well-known names need no salt (they are returned as-is).
  assert.equal(normalizeToolName('web_search', null), 'web_search');
  // Unknown names without salt would leak the raw name silently — refuse.
  assert.throws(() => normalizeToolName('custom_unknown_tool', null), /salt/);
});

// ── F-6 (Codex audit follow-up): session_ids forensic trail ─────────────

test('Containment F-6: payload.session_ids collects distinct session_ids from the window', () => {
  const agg = new SignalsAggregator({ salt: SALT });
  agg.add(syntheticEvent({ session_id: 'sess_A1', id: 'evt_1' }));
  agg.add(syntheticEvent({ session_id: 'sess_B2', id: 'evt_2' }));
  agg.add(syntheticEvent({ session_id: 'sess_A1', id: 'evt_3' })); // dup
  const out = agg.finalize();

  assert.ok(Array.isArray(out.payload.session_ids), 'session_ids is an array');
  // Deduplicated + sorted (deterministic across reruns)
  assert.deepEqual(out.payload.session_ids, ['sess_A1', 'sess_B2']);
});

test('Containment F-6: payload.session_ids is empty when no entries have session_id', () => {
  const agg = new SignalsAggregator({ salt: SALT });
  agg.add(syntheticEvent({ session_id: null, id: 'evt_1' }));
  agg.add(syntheticEvent({ session_id: undefined, id: 'evt_2' }));
  agg.add(syntheticEvent({ session_id: '', id: 'evt_3' }));
  const out = agg.finalize();

  assert.deepEqual(out.payload.session_ids, [],
    'session_ids must be an empty array when no session_id is present, never null/undefined');
});

test('Containment F-6: session_ids carry only opaque tokens, never raw content', () => {
  // Even when an entry has rich raw content (which the aggregator never
  // ships anyway), the session_id is taken VERBATIM from the entry's
  // session_id field — no transformation, no merging with any other field.
  // The Anthropic format is `sess_<base62>` which is what we expect.
  const agg = new SignalsAggregator({ salt: SALT });
  agg.add(syntheticEvent({
    session_id: 'sess_01XaNB4M88ZvcW8FoQ5GC14A',
    input: { url: SECRET_URL, query: SECRET_QUERY },
    output: { content: SECRET_OUTPUT },
    error: SECRET_ERROR,
  }));
  const out = agg.finalize();

  // The opaque session_id IS present (forensic value)
  assert.deepEqual(out.payload.session_ids, ['sess_01XaNB4M88ZvcW8FoQ5GC14A']);
  // No raw content leaked anywhere in the serialized payload
  const serialized = JSON.stringify(out);
  for (const secret of [SECRET_URL, SECRET_QUERY, SECRET_OUTPUT, SECRET_ERROR]) {
    assert.ok(!serialized.includes(secret), `Containment leak via F-6: "${secret}"`);
  }
});
