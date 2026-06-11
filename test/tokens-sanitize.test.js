// v1.4.2 F-49 (P2 audit) — token usage sanitization.
//
// `x || 0` is a falsy guard, not a numeric one: it passes negatives and lets
// NaN propagate to poison totals (zeroing real activity → under-reporting the
// security-relevant consumption signal). safeNonNegInt clamps anything that
// is not a finite non-negative number to 0.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { safeNonNegInt, TokenTracker, estimateCost } from '../src/tokens.js';
import { SignalsAggregator } from '../src/anonymizer.js';

const SALT = 'test-salt-deterministic-0123456789abcdef';

test('F-49: safeNonNegInt clamps NaN / Infinity / negative / non-number to 0', () => {
  assert.equal(safeNonNegInt(NaN), 0);
  assert.equal(safeNonNegInt(Infinity), 0);
  assert.equal(safeNonNegInt(-Infinity), 0);
  assert.equal(safeNonNegInt(-5), 0);
  assert.equal(safeNonNegInt('123'), 0);     // strings are not numbers here
  assert.equal(safeNonNegInt(undefined), 0);
  assert.equal(safeNonNegInt(null), 0);
});

test('F-49: safeNonNegInt keeps and truncates valid non-negative numbers', () => {
  assert.equal(safeNonNegInt(0), 0);
  assert.equal(safeNonNegInt(42), 42);
  assert.equal(safeNonNegInt(99.9), 99);     // truncated to int
});

test('F-49: TokenTracker does not let a negative or NaN entry corrupt totals', () => {
  const tt = new TokenTracker();
  tt.record({ action_type: 'llm_call', model: 'm', input_tokens: 100, output_tokens: 50 });
  tt.record({ action_type: 'llm_call', model: 'm', input_tokens: -1000 });    // adversarial negative
  tt.record({ action_type: 'llm_call', model: 'm', output_tokens: NaN });     // poison NaN
  const s = tt.stats();
  assert.equal(s.total.input, 100, 'negative input ignored, not subtracted');
  assert.equal(s.total.output, 50, 'NaN output ignored, not propagated');
  assert.ok(Number.isFinite(s.total.sum), 'sum stays finite');
  assert.ok(s.total.sum >= 0, 'sum stays non-negative');
});

test('F-49: a NaN tokens_used does not zero out a real call (components used)', () => {
  const tt = new TokenTracker();
  tt.record({ action_type: 'llm_call', model: 'm', input_tokens: 10, output_tokens: 20, tokens_used: NaN });
  // provided NaN → sanitized to 0 → falls back to component sum 30.
  assert.equal(tt.stats().total.sum, 30);
});

test('F-49: estimateCost ignores poisoned usage values', () => {
  const pricing = { m: { input: 1, output: 1, cache_read: 0, cache_write: 0 } };
  const cost = estimateCost('m', { input_tokens: 1_000_000, output_tokens: NaN }, pricing);
  // 1M input * $1/1M = $1.00; NaN output contributes 0, not NaN.
  assert.equal(cost, 1);
});

test('F-49: SignalsAggregator.tokens_total ignores a poison value', () => {
  const agg = new SignalsAggregator({ salt: SALT });
  agg.add({ action_type: 'llm_call', tool_name: null, tokens_used: 500 });
  agg.add({ action_type: 'llm_call', tool_name: null, tokens_used: Infinity });  // poison
  agg.add({ action_type: 'llm_call', tool_name: null, tokens_used: -9999 });     // negative
  const payload = agg.finalize().payload;
  assert.equal(payload.tokens_total, 500, 'only the valid value counted');
  assert.ok(Number.isFinite(payload.tokens_total));
});
