// Shield policy ReDoS protection — v1.1.4 F-20 (P2 Codex audit).
//
// The Codex auditor flagged two gaps in the existing heuristic:
//   - ambiguous alternation `(a|a)*` not detected (only nested-quantifier-
//     in-group was), so a malicious policy from Fortress could still pin
//     Shield's CPU.
//   - MAX_REGEX_INPUT at 8192 was generous enough that even the truncated
//     input window left room for exponential-time backtracking on pathological
//     patterns that slipped through the heuristic.
//
// Fix in v1.1.4:
//   - heuristic for grouped-alternation + quantifier
//   - MAX_REGEX_INPUT lowered from 8192 → 2048 (still > any real IoC value)
//   - regex source max length 2000 → 1024 to shrink the smuggling window
//
// These tests pin both the additions and the legitimate patterns we
// MUST keep accepting so the new heuristic doesn't break real policies.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateRegexString } from '../src/shield/policy.js';

// ── Existing heuristic (regression) ────────────────────────────────────

test('F-20 regression: (a+)+ rejected (nested quantifier in group)', () => {
  assert.throws(() => validateRegexString('(a+)+', 'test'), /catastrophic backtracking/);
});

test('F-20 regression: (a*)* rejected', () => {
  assert.throws(() => validateRegexString('(a*)*', 'test'), /catastrophic backtracking/);
});

test('F-20 regression: .*.*.*.* rejected (multiple .* in a row)', () => {
  assert.throws(() => validateRegexString('.*.*.*.*', 'test'), /catastrophic backtracking/);
});

// ── F-20 NEW: alternation-in-group + quantifier ────────────────────────

test('F-20 new: (a|a)* rejected (overlapping branches + quantifier = exponential)', () => {
  assert.throws(() => validateRegexString('(a|a)*', 'test'), /catastrophic backtracking/);
});

test('F-20 new: (a|ab)+ rejected (overlapping branches)', () => {
  assert.throws(() => validateRegexString('(a|ab)+', 'test'), /catastrophic backtracking/);
});

test('F-20 new: (.|.)* rejected (any-char alternation)', () => {
  assert.throws(() => validateRegexString('(.|.)*', 'test'), /catastrophic backtracking/);
});

test('F-20 new: (foo|bar|baz)* rejected (over-broad — must use char-class or move quantifier)', () => {
  // Intentionally over-broad: a customer who wants this should use
  // [a-z]+ or move the optional letters inside (e.g. `(foo)|(bar)|(baz)`).
  assert.throws(() => validateRegexString('(foo|bar|baz)*', 'test'), /catastrophic backtracking/);
});

test('F-20 new: (a|b|c)+ rejected (even non-overlapping alternation falls in the over-broad heuristic)', () => {
  // We err toward false-positive: rejecting a safe (a|b|c)+ is loud
  // (the rule is dropped at load time with a clear error), but letting
  // a (a|a)+ through would degrade Shield silently.
  assert.throws(() => validateRegexString('(a|b|c)+', 'test'), /catastrophic backtracking/);
});

// ── Legitimate patterns that MUST keep working ─────────────────────────

test('F-20 legit: ^https:// accepted (prefix match, no quantifier outside group)', () => {
  assert.doesNotThrow(() => validateRegexString('^https://', 'test'));
});

test('F-20 legit: https?:// accepted (optional letter, no group)', () => {
  // https? is the canonical way to allow http or https — does NOT use
  // a group + quantifier so it never trips the heuristic.
  assert.doesNotThrow(() => validateRegexString('^https?://', 'test'));
});

test('F-20 legit: [a-zA-Z]+ accepted (character class + quantifier, no nesting)', () => {
  assert.doesNotThrow(() => validateRegexString('[a-zA-Z]+', 'test'));
});

test('F-20 legit: \\d{1,5} accepted (bounded quantifier)', () => {
  assert.doesNotThrow(() => validateRegexString('\\d{1,5}', 'test'));
});

test('F-20 legit: single-branch group (foo)+ accepted', () => {
  // No `|` inside, so the new alternation heuristic does not trip.
  assert.doesNotThrow(() => validateRegexString('(foo)+', 'test'));
});

test('F-20 legit: exact-URL match accepted', () => {
  assert.doesNotThrow(() => validateRegexString('^https://api\\.github\\.com/repos/[^/]+/[^/]+/issues$', 'test'));
});

test('F-20 legit: command-prefix match accepted', () => {
  assert.doesNotThrow(() => validateRegexString('^rm\\s+-rf\\s+/', 'test'));
});

// ── Length caps ────────────────────────────────────────────────────────

test('F-20: regex source > 1024 chars rejected (was 2000 pre-F-20)', () => {
  const long = 'a'.repeat(1025);
  assert.throws(() => validateRegexString(long, 'test'), /too long/);
});

test('F-20: regex source at the 1024 boundary accepted', () => {
  const right = 'a'.repeat(1024);
  assert.doesNotThrow(() => validateRegexString(right, 'test'));
});

// ── Input cap (indirect: via the evaluate() path) ──────────────────────

test('F-20: long input value is truncated to MAX_REGEX_INPUT before regex test', async () => {
  // Build a ruleset that uses a regex on `input.url`, then evaluate
  // an event whose URL is 100KB. The evaluator must complete in
  // bounded time (truncation kicks in at 2048).
  const { evaluate, compileMatchRegexes } = await import('../src/shield/policy.js');
  const policy = {
    id: 'p1', name: 'deny-long-suffix', action: 'deny',
    match: { 'input.url': { regex: 'EVIL$' } },
  };
  compileMatchRegexes(policy.match);
  const ruleset = { version: 1, policies: [policy], default: { action: 'allow' } };

  // 100 KB of harmless content, then "EVIL" at the very end.
  // Post-truncation, the "EVIL" suffix is past the 2048 cap and the
  // regex anchored at $ should NOT match the truncated input.
  const huge = 'a'.repeat(100_000) + 'EVIL';
  const t0 = Date.now();
  const result = evaluate({ input: { url: huge } }, ruleset);
  const dt = Date.now() - t0;
  assert.ok(dt < 500, `evaluate() should be fast even on huge input; took ${dt}ms`);
  // The regex is anchored at $ — after truncation the EVIL suffix is
  // gone, so the rule must NOT match (decision falls through to default).
  assert.equal(result.decision, 'allow', 'truncation prevents the regex from matching past-cap suffixes');
});
