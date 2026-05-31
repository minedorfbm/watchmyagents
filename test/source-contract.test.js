// Source contract — V1 (PR-A)
// Verifies that the canonical Source ABC + WMAAction vocabulary hold,
// and that AnthropicManagedSource satisfies the contract.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  Source,
  ACTION_TYPES,
  STATUS_VALUES,
  ENFORCEMENT_MODES,
  COMPOSITION_PATTERNS,
  PROVIDERS,
  validateWMAAction,
  assertImplementsSource,
} from '../src/sources/contract.js';
import { AnthropicManagedSource } from '../src/sources/anthropic-managed.js';

// ── Constants ────────────────────────────────────────────────────────────

test('ACTION_TYPES is frozen and contains the documented canonical set', () => {
  assert.ok(Object.isFrozen(ACTION_TYPES));
  // A few load-bearing ones — full set is in contract.js.
  for (const k of ['LLM_CALL', 'TOOL_USE', 'TOOL_CONFIRMATION', 'STATE_TRANSITION', 'SHIELD_DECISION']) {
    assert.ok(k in ACTION_TYPES, `missing canonical action type: ${k}`);
  }
});

test('STATUS_VALUES is frozen and is exactly {ok, error, blocked}', () => {
  assert.ok(Object.isFrozen(STATUS_VALUES));
  assert.deepEqual(new Set(Object.values(STATUS_VALUES)), new Set(['ok', 'error', 'blocked']));
});

test('ENFORCEMENT_MODES is frozen and is exactly the documented 3 modes', () => {
  assert.ok(Object.isFrozen(ENFORCEMENT_MODES));
  assert.deepEqual(
    new Set(Object.values(ENFORCEMENT_MODES)),
    new Set(['sync_confirm', 'sync_interrupt', 'detect_only']),
  );
});

test('COMPOSITION_PATTERNS is frozen and is exactly the documented 4 patterns', () => {
  assert.ok(Object.isFrozen(COMPOSITION_PATTERNS));
  assert.deepEqual(
    new Set(Object.values(COMPOSITION_PATTERNS)),
    new Set(['solo', 'hierarchy', 'graph', 'peer']),
  );
});

// ── validateWMAAction ────────────────────────────────────────────────────

const validAction = () => ({
  id: 'evt_123',
  provider: PROVIDERS.ANTHROPIC_MANAGED,
  agent_id: 'agent_abc',
  session_id: 'sess_xyz',
  action_type: ACTION_TYPES.TOOL_USE,
  timestamp: '2026-05-30T18:00:00Z',
  status: STATUS_VALUES.OK,
});

test('validateWMAAction accepts a minimally valid action', () => {
  const r = validateWMAAction(validAction());
  assert.equal(r.valid, true, r.errors.join('; '));
  assert.deepEqual(r.errors, []);
});

test('validateWMAAction rejects when required fields are missing', () => {
  const bad = validAction();
  delete bad.id;
  delete bad.agent_id;
  const r = validateWMAAction(bad);
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => e.includes('missing required field: id')));
  assert.ok(r.errors.some((e) => e.includes('missing required field: agent_id')));
});

test('validateWMAAction rejects unknown action_type', () => {
  const r = validateWMAAction({ ...validAction(), action_type: 'totally_made_up' });
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => e.includes('unknown action_type')));
});

test('validateWMAAction rejects unknown status', () => {
  const r = validateWMAAction({ ...validAction(), status: 'maybe' });
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => e.includes('unknown status')));
});

test('validateWMAAction rejects unparseable timestamp', () => {
  const r = validateWMAAction({ ...validAction(), timestamp: 'last tuesday' });
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => e.includes('timestamp not parseable')));
});

test('validateWMAAction rejects unknown composition_pattern', () => {
  const r = validateWMAAction({ ...validAction(), composition_pattern: 'mesh' });
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => e.includes('unknown composition_pattern')));
});

test('validateWMAAction accepts null composition_pattern (PR-C will populate it)', () => {
  const r = validateWMAAction({ ...validAction(), composition_pattern: null });
  assert.equal(r.valid, true, r.errors.join('; '));
});

test('validateWMAAction rejects non-object input', () => {
  for (const v of [null, undefined, 'a string', 42, true]) {
    const r = validateWMAAction(v);
    assert.equal(r.valid, false);
  }
});

// ── Source ABC ───────────────────────────────────────────────────────────

test('Source cannot be instantiated directly (abstract)', () => {
  assert.throws(() => new Source(), /Source is abstract/);
});

test('Source default methods all throw "not implemented"', async () => {
  class Stub extends Source {
    static providerName = 'anthropic-managed';
    static enforcementMode = 'sync_confirm';
  }
  const s = new Stub();
  await assert.rejects(s.listAgents(), /not implemented/);
  await assert.rejects((async () => { for await (const _ of s.streamEvents('a')) { /* */ } })(), /not implemented/);
  await assert.rejects(s.enforce({}, { decision: 'allow' }), /not implemented/);
});

// ── AnthropicManagedSource ───────────────────────────────────────────────

test('AnthropicManagedSource satisfies the Source contract', () => {
  assert.doesNotThrow(() => assertImplementsSource(AnthropicManagedSource));
});

test('AnthropicManagedSource declares the expected static fields', () => {
  assert.equal(AnthropicManagedSource.providerName, 'anthropic-managed');
  assert.equal(AnthropicManagedSource.enforcementMode, 'sync_confirm');
});

test('AnthropicManagedSource constructor requires apiKey', () => {
  assert.throws(() => new AnthropicManagedSource(), /apiKey/);
  assert.throws(() => new AnthropicManagedSource({}), /apiKey/);
});

test('AnthropicManagedSource constructor accepts apiKey', () => {
  const s = new AnthropicManagedSource({ apiKey: 'sk-fake' });
  assert.equal(s.apiKey, 'sk-fake');
});

test('AnthropicManagedSource.streamEvents requires sessionId', async () => {
  const s = new AnthropicManagedSource({ apiKey: 'sk-fake' });
  await assert.rejects(
    (async () => { for await (const _ of s.streamEvents('agent_x')) { /* */ } })(),
    /sessionId/,
  );
});

// ── F-4 (Codex audit): AnthropicManagedSource.enforce() argument guards ──

test('F-4: enforce rejects non-object action', async () => {
  const s = new AnthropicManagedSource({ apiKey: 'sk-fake' });
  await assert.rejects(s.enforce(null, { decision: 'allow' }), /action must be a WMAAction/);
  await assert.rejects(s.enforce('foo', { decision: 'allow' }), /action must be a WMAAction/);
});

test('F-4: enforce requires action.session_id', async () => {
  const s = new AnthropicManagedSource({ apiKey: 'sk-fake' });
  await assert.rejects(
    s.enforce({ agent_id: 'a', action_type: 'tool_use', id: 'evt' }, { decision: 'allow' }),
    /session_id/,
  );
});

test('F-4: enforce requires action.agent_id', async () => {
  const s = new AnthropicManagedSource({ apiKey: 'sk-fake' });
  await assert.rejects(
    s.enforce({ session_id: 's', action_type: 'tool_use', id: 'evt' }, { decision: 'allow' }),
    /agent_id/,
  );
});

test('F-4: enforce requires decision in {allow, deny}', async () => {
  const s = new AnthropicManagedSource({ apiKey: 'sk-fake' });
  const validAction = { agent_id: 'a', session_id: 's', action_type: 'tool_use', id: 'evt' };
  await assert.rejects(s.enforce(validAction, { decision: 'maybe' }), /'allow' or 'deny'/);
  await assert.rejects(s.enforce(validAction, {}), /'allow' or 'deny'/);
  await assert.rejects(s.enforce(validAction, null), /'allow' or 'deny'/);
});

test('F-4: AnthropicManagedSource exposes a _modeCache for per-agent memoization', () => {
  const s = new AnthropicManagedSource({ apiKey: 'sk-fake' });
  assert.ok(s._modeCache instanceof Map, 'cache must be a Map instance');
  assert.equal(s._modeCache.size, 0, 'cache starts empty');
});

// ── assertImplementsSource — defensive checks ────────────────────────────

test('assertImplementsSource rejects classes that do not extend Source', () => {
  class NotASource { static providerName = 'anthropic-managed'; static enforcementMode = 'sync_confirm'; }
  assert.throws(() => assertImplementsSource(NotASource), /does not extend Source/);
});

test('assertImplementsSource rejects unknown providerName', () => {
  class Bad extends Source {
    static providerName = 'made-up';
    static enforcementMode = 'sync_confirm';
    async listAgents() { return []; }
    async *streamEvents() { /* */ }
    async enforce() { return { enforced: true }; }
  }
  assert.throws(() => assertImplementsSource(Bad), /providerName/);
});

test('assertImplementsSource rejects unknown enforcementMode', () => {
  class Bad extends Source {
    static providerName = 'anthropic-managed';
    static enforcementMode = 'gentle_nudge';
    async listAgents() { return []; }
    async *streamEvents() { /* */ }
    async enforce() { return { enforced: true }; }
  }
  assert.throws(() => assertImplementsSource(Bad), /enforcementMode/);
});

test('assertImplementsSource requires enforce() override unless detect_only', () => {
  class NoEnforce extends Source {
    static providerName = 'anthropic-managed';
    static enforcementMode = 'sync_confirm';
    async listAgents() { return []; }
    async *streamEvents() { /* */ }
  }
  assert.throws(() => assertImplementsSource(NoEnforce), /enforce.*overridden/);
});

test('assertImplementsSource allows detect_only sources to skip enforce()', () => {
  class WatchOnly extends Source {
    static providerName = 'anthropic-managed'; // any known provider
    static enforcementMode = 'detect_only';
    async listAgents() { return []; }
    async *streamEvents() { /* */ }
  }
  assert.doesNotThrow(() => assertImplementsSource(WatchOnly));
});
