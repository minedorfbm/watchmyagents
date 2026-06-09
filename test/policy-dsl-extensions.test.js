// Policy DSL extensions — v1.2.0 (pre-Phase-2 hardening).
//
// Mapping to Anthropic's agentic security framework (May 2026):
//   Part IV §Phase 5 — "Securing tool access". The framework explicitly
//   calls out "parameter validation (agent AND tool side)" as a Phase
//   foundation. v1.1.6 only had eq / in / regex; we now add numeric
//   comparators and length checks so a policy can express things like
//   "bytes_sent > 1 MB" or "url longer than 2 KB" — common exfil
//   heuristics that previously had to be smuggled into a regex.
//
// Operators added in this release:
//   - gt, gte, lt, lte          numeric comparison (finite only)
//   - in_range: [min, max]      inclusive both sides
//   - length_gt, length_gte,
//     length_lt, length_lte     applies to strings AND arrays
//
// Design rules:
//   - fail-closed everywhere (non-numeric value vs numeric operator,
//     malformed operand, inverted range)
//   - no coercion ever ("3" never compares equal to 3)
//   - mutual exclusivity within a single condition object preserved
//     (use multiple fields in `match` for AND, in_range for "between")

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { matchesPolicy } from '../src/shield/policy.js';

// Helper to build a one-clause policy for these tests.
const p = (field, condition) => ({ match: { [field]: condition } });

// ── gt / gte / lt / lte ────────────────────────────────────────────────

test('v1.2.0 DSL: gt matches when value strictly greater', () => {
  assert.equal(matchesPolicy({ x: 10 }, p('x', { gt: 5 })), true);
  assert.equal(matchesPolicy({ x: 5 }, p('x', { gt: 5 })), false);
  assert.equal(matchesPolicy({ x: 4 }, p('x', { gt: 5 })), false);
});

test('v1.2.0 DSL: gte includes the equal case', () => {
  assert.equal(matchesPolicy({ x: 5 }, p('x', { gte: 5 })), true);
  assert.equal(matchesPolicy({ x: 4 }, p('x', { gte: 5 })), false);
});

test('v1.2.0 DSL: lt and lte', () => {
  assert.equal(matchesPolicy({ x: 3 }, p('x', { lt: 5 })), true);
  assert.equal(matchesPolicy({ x: 5 }, p('x', { lt: 5 })), false);
  assert.equal(matchesPolicy({ x: 5 }, p('x', { lte: 5 })), true);
});

test('v1.2.0 DSL: numeric ops fail-closed on non-numeric value', () => {
  assert.equal(matchesPolicy({ x: '5' }, p('x', { gt: 1 })), false);
  assert.equal(matchesPolicy({ x: null }, p('x', { gte: 0 })), false);
  assert.equal(matchesPolicy({ x: undefined }, p('x', { lt: 100 })), false);
  assert.equal(matchesPolicy({ x: true }, p('x', { lte: 1 })), false);
  assert.equal(matchesPolicy({ x: NaN }, p('x', { gt: 0 })), false);
  assert.equal(matchesPolicy({ x: Infinity }, p('x', { gt: 0 })), false);
});

test('v1.2.0 DSL: numeric ops fail-closed when operand itself is malformed', () => {
  // typeof NaN === 'number' but Number.isFinite(NaN) is false, so it's
  // rejected. Same for Infinity.
  assert.equal(matchesPolicy({ x: 10 }, p('x', { gt: NaN })), false);
  assert.equal(matchesPolicy({ x: 10 }, p('x', { gt: Infinity })), false);
  assert.equal(matchesPolicy({ x: 10 }, p('x', { gt: '5' })), false);
  assert.equal(matchesPolicy({ x: 10 }, p('x', { gt: null })), false);
});

test('v1.2.0 DSL: gt 0 fires on negative-then-positive transition', () => {
  // Anti-regression: a falsy-like operand (0) must still be honoured.
  assert.equal(matchesPolicy({ x: 1 }, p('x', { gt: 0 })), true);
  assert.equal(matchesPolicy({ x: 0 }, p('x', { gt: 0 })), false);
  assert.equal(matchesPolicy({ x: -1 }, p('x', { gt: 0 })), false);
});

// ── in_range ───────────────────────────────────────────────────────────

test('v1.2.0 DSL: in_range matches when both bounds satisfied (inclusive)', () => {
  assert.equal(matchesPolicy({ x: 50 }, p('x', { in_range: [10, 100] })), true);
  assert.equal(matchesPolicy({ x: 10 }, p('x', { in_range: [10, 100] })), true);
  assert.equal(matchesPolicy({ x: 100 }, p('x', { in_range: [10, 100] })), true);
});

test('v1.2.0 DSL: in_range fails-closed outside bounds', () => {
  assert.equal(matchesPolicy({ x: 9 }, p('x', { in_range: [10, 100] })), false);
  assert.equal(matchesPolicy({ x: 101 }, p('x', { in_range: [10, 100] })), false);
});

test('v1.2.0 DSL: in_range fails-closed on inverted bounds (operator typo guard)', () => {
  // [100, 10] is most likely a swap mistake. We refuse to match anything
  // rather than silently flip semantics or always-true / always-false.
  assert.equal(matchesPolicy({ x: 50 }, p('x', { in_range: [100, 10] })), false);
  assert.equal(matchesPolicy({ x: 50 }, p('x', { in_range: [10, 'oops'] })), false);
  assert.equal(matchesPolicy({ x: 50 }, p('x', { in_range: [10] })), false);
  assert.equal(matchesPolicy({ x: 50 }, p('x', { in_range: [10, 20, 30] })), false);
});

// ── length_* ───────────────────────────────────────────────────────────

test('v1.2.0 DSL: length_gt on a string', () => {
  assert.equal(matchesPolicy({ s: 'hi' }, p('s', { length_gt: 1 })), true);
  assert.equal(matchesPolicy({ s: 'h' }, p('s', { length_gt: 1 })), false);
});

test('v1.2.0 DSL: length_gte includes the equal case on strings', () => {
  assert.equal(matchesPolicy({ s: 'abc' }, p('s', { length_gte: 3 })), true);
  assert.equal(matchesPolicy({ s: 'ab' }, p('s', { length_gte: 3 })), false);
});

test('v1.2.0 DSL: length_lt and length_lte', () => {
  assert.equal(matchesPolicy({ s: 'ab' }, p('s', { length_lt: 3 })), true);
  assert.equal(matchesPolicy({ s: 'ab' }, p('s', { length_lte: 2 })), true);
  assert.equal(matchesPolicy({ s: 'abc' }, p('s', { length_lt: 3 })), false);
});

test('v1.2.0 DSL: length_* also works on arrays', () => {
  assert.equal(matchesPolicy({ list: [1, 2, 3] }, p('list', { length_gt: 2 })), true);
  assert.equal(matchesPolicy({ list: [1] }, p('list', { length_gte: 1 })), true);
  assert.equal(matchesPolicy({ list: [] }, p('list', { length_gt: 0 })), false);
});

test('v1.2.0 DSL: length_* fails-closed on values without .length semantics', () => {
  // Plain objects, numbers, null all lack a meaningful length here.
  // We won't reach into Object.keys() — that would be a "guess the
  // intent" coercion. Fail-closed.
  assert.equal(matchesPolicy({ x: { a: 1, b: 2 } }, p('x', { length_gt: 0 })), false);
  assert.equal(matchesPolicy({ x: 42 }, p('x', { length_gt: 0 })), false);
  assert.equal(matchesPolicy({ x: null }, p('x', { length_gt: 0 })), false);
  assert.equal(matchesPolicy({ x: undefined }, p('x', { length_gte: 0 })), false);
});

// ── Composition with the rest of the matcher ───────────────────────────

test('v1.2.0 DSL: multiple fields in match still AND together', () => {
  // The new ops behave the same way: every clause in `match` must hold.
  const policy = {
    match: {
      tool_name: 'bash',
      'input.bytes_sent': { gt: 1_000_000 },
      'input.url': { length_gt: 100 },
    },
  };
  assert.equal(
    matchesPolicy(
      { tool_name: 'bash', input: { bytes_sent: 5_000_000, url: 'x'.repeat(200) } },
      policy,
    ),
    true,
  );
  // Volume met but URL short → does not fire.
  assert.equal(
    matchesPolicy(
      { tool_name: 'bash', input: { bytes_sent: 5_000_000, url: 'short' } },
      policy,
    ),
    false,
  );
});

test('v1.2.0 DSL: unknown operator still fails-closed (anti-typo guard)', () => {
  // A typo'd operator must never silently allow.
  assert.equal(matchesPolicy({ x: 100 }, p('x', { gtt: 5 })), false);
  assert.equal(matchesPolicy({ x: 'abc' }, p('x', { length_greater_than: 1 })), false);
});

// ── Realistic exfil-detection scenario ────────────────────────────────

test('v1.2.0 DSL: realistic exfil policy — large outbound POST', () => {
  // This is the kind of rule that previously had to be expressed via
  // brittle regex on a stringified payload. Now it's a structural check.
  const policy = {
    id: 'exfil-large-outbound',
    name: 'Block large outbound POST',
    action: 'deny',
    match: {
      action_type: 'tool_use',
      tool_name: { in: ['web_fetch', 'http_post'] },
      'input.method': 'POST',
      'input.bytes': { gt: 1_000_000 },
    },
  };
  const malicious = {
    action_type: 'tool_use',
    tool_name: 'web_fetch',
    input: { method: 'POST', bytes: 2_500_000, url: 'https://x.example' },
  };
  const benign = {
    action_type: 'tool_use',
    tool_name: 'web_fetch',
    input: { method: 'POST', bytes: 4_000, url: 'https://x.example' },
  };
  assert.equal(matchesPolicy(malicious, policy), true);
  assert.equal(matchesPolicy(benign, policy), false);
});
