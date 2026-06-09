// Policy context-aware authorization — v1.2.0.
//
// Maps to Anthropic's agentic security framework Part IV §Phase 4:
// "context-aware authorization". v1.1.6's matcher only saw the event
// payload; this test suite exercises the new `ctx.` namespace and the
// session-scoped tracker that feeds it.
//
// The tests cover both halves:
//   (1) policy.js — the ctx.* path prefix resolves from the second
//                   namespace, NOT from event. Existing event-only paths
//                   keep working (backwards compatibility).
//   (2) context.js — createContextTracker() correctly computes the six
//                    attributes, rolls the recent window correctly, and
//                    exposes a fail-safe order: compute → evaluate → record.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { matchesPolicy, evaluate } from '../src/shield/policy.js';
import { createContextTracker, defaultIsError } from '../src/shield/context.js';

// ── Policy: ctx.* namespace ────────────────────────────────────────────

test('v1.2.0 ctx: ctx.* field resolves from context, not event', () => {
  const policy = { match: { 'ctx.hour_of_day_utc': { gte: 22 } } };
  const event = { tool_name: 'bash' };
  // Same event, two different contexts → opposite decisions.
  assert.equal(matchesPolicy(event, policy, { hour_of_day_utc: 23 }), true);
  assert.equal(matchesPolicy(event, policy, { hour_of_day_utc: 15 }), false);
});

test('v1.2.0 ctx: event paths and ctx paths AND together in one match', () => {
  const policy = {
    match: {
      tool_name: 'bash',
      'ctx.recent_error_rate': { gt: 0.5 },
    },
  };
  const event = { tool_name: 'bash' };
  // Both clauses satisfied → match.
  assert.equal(matchesPolicy(event, policy, { recent_error_rate: 0.75 }), true);
  // Event clause satisfied but context says agent is healthy → no match.
  assert.equal(matchesPolicy(event, policy, { recent_error_rate: 0.1 }), false);
  // Context risky but tool is not bash → no match.
  assert.equal(matchesPolicy({ tool_name: 'web_search' }, policy, { recent_error_rate: 0.9 }), false);
});

test('v1.2.0 ctx: omitting ctx preserves v1.1.x behavior', () => {
  // Same policy + event as in a hypothetical v1.1.x test — calling
  // matchesPolicy without a ctx arg must not throw and must behave as
  // if ctx were an empty object.
  const policy = { match: { tool_name: 'bash' } };
  assert.equal(matchesPolicy({ tool_name: 'bash' }, policy), true);
  assert.equal(matchesPolicy({ tool_name: 'web_search' }, policy), false);
});

test('v1.2.0 ctx: missing ctx field fails-closed (no silent allow)', () => {
  // ctx.* reference on an empty ctx must NOT match a literal — it's
  // undefined, same as a missing event field.
  const policy = { match: { 'ctx.agent_age_minutes': 0 } };
  assert.equal(matchesPolicy({}, policy, {}), false);
  assert.equal(matchesPolicy({}, policy, { agent_age_minutes: 0 }), true);
});

test('v1.2.0 ctx: shadowing — an event.ctx field cannot leak into ctx.* path', () => {
  // Defence in depth: even if a future Anthropic event shape has a
  // top-level `ctx` field, our matcher must resolve `ctx.*` from the
  // dedicated namespace, not from the event.
  const event = { ctx: { hour_of_day_utc: 23 } };
  const policy = { match: { 'ctx.hour_of_day_utc': 23 } };
  // ctx arg is the truth source; event.ctx is ignored.
  assert.equal(matchesPolicy(event, policy, { hour_of_day_utc: 10 }), false);
  assert.equal(matchesPolicy(event, policy, { hour_of_day_utc: 23 }), true);
});

test('v1.2.0 ctx: evaluate() threads ctx through to matchesPolicy', () => {
  const ruleset = {
    policies: [
      {
        id: 'after-hours-bash',
        action: 'deny',
        match: {
          tool_name: 'bash',
          'ctx.hour_of_day_utc': { in_range: [22, 23] },
        },
      },
    ],
    default: { action: 'allow' },
  };
  const event = { tool_name: 'bash' };

  // 22:00 UTC → policy fires.
  let r = evaluate(event, ruleset, { hour_of_day_utc: 22 });
  assert.equal(r.decision, 'deny');
  assert.equal(r.rule_id, 'after-hours-bash');

  // 10:00 UTC → falls through to default.
  r = evaluate(event, ruleset, { hour_of_day_utc: 10 });
  assert.equal(r.decision, 'allow');
  assert.equal(r.rule_name, '(default)');
});

test('v1.2.0 ctx: evaluate() without ctx arg still works (backwards compat)', () => {
  const ruleset = {
    policies: [{ id: 'p', action: 'deny', match: { tool_name: 'bash' } }],
    default: { action: 'allow' },
  };
  assert.equal(evaluate({ tool_name: 'bash' }, ruleset).decision, 'deny');
});

// ── Context tracker ────────────────────────────────────────────────────

test('v1.2.0 tracker: compute() at t=0 returns sane initial state', () => {
  // Pin the clock to a known UTC instant: 2026-06-09T14:30:00Z (Tuesday).
  const fixedMs = Date.UTC(2026, 5, 9, 14, 30, 0); // month is 0-indexed
  const tracker = createContextTracker({ now: () => fixedMs });
  const ctx = tracker.compute({ tool_name: 'bash' });

  assert.equal(ctx.hour_of_day_utc, 14);
  assert.equal(ctx.day_of_week_utc, 2); // Tuesday
  assert.equal(ctx.agent_age_minutes, 0);
  assert.equal(ctx.session_duration_ms, 0);
  assert.equal(ctx.recent_error_rate, 0);
  assert.equal(ctx.event_count_recent, 0);
  assert.equal(ctx.event_count_total, 0);
});

test('v1.2.0 tracker: record() advances total + recent counts', () => {
  let nowMs = 1_000_000;
  const tracker = createContextTracker({ now: () => nowMs });

  tracker.record({ type: 'tool_use', tool_name: 'bash' }, { isError: false });
  let ctx = tracker.compute({});
  assert.equal(ctx.event_count_total, 1);
  assert.equal(ctx.event_count_recent, 1);
  assert.equal(ctx.recent_error_rate, 0);

  tracker.record({ type: 'tool_use', tool_name: 'web_search' }, { isError: true });
  ctx = tracker.compute({});
  assert.equal(ctx.event_count_total, 2);
  assert.equal(ctx.event_count_recent, 2);
  assert.equal(ctx.recent_error_rate, 0.5);
});

test('v1.2.0 tracker: agent_age_minutes + session_duration_ms advance with wall clock', () => {
  let nowMs = 0;
  const tracker = createContextTracker({ now: () => nowMs });

  // First record establishes the anchor.
  tracker.record({ type: 'tool_use' }, { isError: false });

  // 5 minutes later.
  nowMs += 5 * 60_000;
  let ctx = tracker.compute({});
  assert.equal(ctx.agent_age_minutes, 5);
  assert.equal(ctx.session_duration_ms, 5 * 60_000);

  // 90 seconds further.
  nowMs += 90_000;
  ctx = tracker.compute({});
  // 6 min 30s → floor → 6
  assert.equal(ctx.agent_age_minutes, 6);
  assert.equal(ctx.session_duration_ms, 5 * 60_000 + 90_000);
});

test('v1.2.0 tracker: recent_error_rate rolls when window fills', () => {
  const tracker = createContextTracker({ recentWindowSize: 4, now: () => 0 });

  // Window: [err, err, ok, ok] → rate 0.5
  tracker.record({}, { isError: true });
  tracker.record({}, { isError: true });
  tracker.record({}, { isError: false });
  tracker.record({}, { isError: false });
  assert.equal(tracker.compute({}).recent_error_rate, 0.5);

  // Push another ok → window slides [err, ok, ok, ok] → rate 0.25
  tracker.record({}, { isError: false });
  assert.equal(tracker.compute({}).recent_error_rate, 0.25);

  // Push another ok → window [ok, ok, ok, ok] → rate 0
  tracker.record({}, { isError: false });
  assert.equal(tracker.compute({}).recent_error_rate, 0);
});

test('v1.2.0 tracker: recent_error_rate uses heuristic when isError omitted', () => {
  const tracker = createContextTracker({ recentWindowSize: 10, now: () => 0 });

  tracker.record({ type: 'tool_use', tool_name: 'bash' });               // no error markers → ok
  tracker.record({ type: 'tool_result', is_error: true });               // is_error → ERROR
  tracker.record({ error: { message: 'rate_limited' } });                // error field → ERROR
  tracker.record({                                                       // content carries tool_result with is_error
    type: 'message',
    content: [{ type: 'tool_result', is_error: true, content: 'oops' }],
  });
  tracker.record({ type: 'overloaded_error' });                          // type contains 'error' → ERROR

  const ctx = tracker.compute({});
  // 4 out of 5 events flagged as error.
  assert.equal(ctx.event_count_recent, 5);
  assert.equal(ctx.recent_error_rate, 0.8);
});

test('v1.2.0 tracker: defaultIsError heuristic — direct calls', () => {
  // The helper is exported for callers that want to classify without
  // going through a tracker; lock the contract here.
  assert.equal(defaultIsError(null), false);
  assert.equal(defaultIsError(undefined), false);
  assert.equal(defaultIsError({}), false);
  assert.equal(defaultIsError({ type: 'tool_use' }), false);
  assert.equal(defaultIsError({ is_error: true }), true);
  assert.equal(defaultIsError({ is_error: false }), false);
  assert.equal(defaultIsError({ error: 'boom' }), true);
  assert.equal(defaultIsError({ type: 'rate_limit_error' }), true);
  assert.equal(defaultIsError({
    type: 'message',
    content: [{ type: 'tool_result', is_error: true }],
  }), true);
  assert.equal(defaultIsError({
    type: 'message',
    content: [{ type: 'tool_result', is_error: false }],
  }), false);
});

test('v1.2.0 tracker: reset() clears all state', () => {
  let nowMs = 1000;
  const tracker = createContextTracker({ now: () => nowMs });
  tracker.record({}, { isError: true });
  tracker.record({}, { isError: true });
  assert.equal(tracker.compute({}).event_count_total, 2);

  tracker.reset();
  const ctx = tracker.compute({});
  assert.equal(ctx.event_count_total, 0);
  assert.equal(ctx.event_count_recent, 0);
  assert.equal(ctx.recent_error_rate, 0);
  assert.equal(ctx.agent_age_minutes, 0);
  assert.equal(ctx.session_duration_ms, 0);
});

test('v1.2.0 tracker: constructor rejects malformed recentWindowSize', () => {
  assert.throws(() => createContextTracker({ recentWindowSize: 0 }), /recentWindowSize/);
  assert.throws(() => createContextTracker({ recentWindowSize: -1 }), /recentWindowSize/);
  assert.throws(() => createContextTracker({ recentWindowSize: 1.5 }), /recentWindowSize/);
  assert.throws(() => createContextTracker({ recentWindowSize: 10_001 }), /recentWindowSize/);
  assert.throws(() => createContextTracker({ recentWindowSize: 'twenty' }), /recentWindowSize/);
});

// ── Realistic end-to-end scenario ──────────────────────────────────────

test('v1.2.0 ctx+tracker: realistic — throttle a flailing agent', () => {
  // Policy: deny tool_use if more than half of the agent's recent calls
  // errored out. Combines Item 1's `gt` comparator with Item 2's ctx.
  const ruleset = {
    policies: [
      {
        id: 'flailing-throttle',
        name: 'Throttle agent after error streak',
        action: 'interrupt',
        match: {
          action_type: 'tool_use',
          'ctx.recent_error_rate': { gt: 0.5 },
          'ctx.event_count_recent': { gte: 4 },
        },
      },
    ],
    default: { action: 'allow' },
  };

  let nowMs = 0;
  const tracker = createContextTracker({ recentWindowSize: 10, now: () => nowMs });

  // Simulate 4 events: 3 errors, 1 OK → rate 0.75
  const errorEvt = { action_type: 'tool_use', is_error: true };
  const okEvt = { action_type: 'tool_use' };
  tracker.record(errorEvt);
  tracker.record(errorEvt);
  tracker.record(okEvt);
  tracker.record(errorEvt);

  // 5th event: should be interrupted.
  nowMs += 1000;
  const ctx = tracker.compute(okEvt);
  assert.equal(ctx.recent_error_rate, 0.75);
  assert.equal(ctx.event_count_recent, 4);

  const result = evaluate(okEvt, ruleset, ctx);
  assert.equal(result.decision, 'interrupt');
  assert.equal(result.rule_id, 'flailing-throttle');
});

test('v1.2.0 ctx+tracker: realistic — after-hours bash deny', () => {
  // Policy: bash outside business hours (00–07 UTC or 22–23 UTC) → deny.
  // Uses Item 1's in_range — we express it as two policies because
  // a single in_range covers a contiguous interval only.
  const ruleset = {
    policies: [
      {
        id: 'after-hours-bash-late',
        action: 'deny',
        match: { tool_name: 'bash', 'ctx.hour_of_day_utc': { in_range: [22, 23] } },
      },
      {
        id: 'after-hours-bash-early',
        action: 'deny',
        match: { tool_name: 'bash', 'ctx.hour_of_day_utc': { in_range: [0, 7] } },
      },
    ],
    default: { action: 'allow' },
  };

  // 23:00 UTC Tuesday → late-night deny.
  let fixedMs = Date.UTC(2026, 5, 9, 23, 0, 0);
  let tracker = createContextTracker({ now: () => fixedMs });
  let r = evaluate({ tool_name: 'bash' }, ruleset, tracker.compute({}));
  assert.equal(r.decision, 'deny');
  assert.equal(r.rule_id, 'after-hours-bash-late');

  // 03:00 UTC → early-morning deny.
  fixedMs = Date.UTC(2026, 5, 10, 3, 0, 0);
  tracker = createContextTracker({ now: () => fixedMs });
  r = evaluate({ tool_name: 'bash' }, ruleset, tracker.compute({}));
  assert.equal(r.decision, 'deny');
  assert.equal(r.rule_id, 'after-hours-bash-early');

  // 14:00 UTC → allow.
  fixedMs = Date.UTC(2026, 5, 9, 14, 0, 0);
  tracker = createContextTracker({ now: () => fixedMs });
  r = evaluate({ tool_name: 'bash' }, ruleset, tracker.compute({}));
  assert.equal(r.decision, 'allow');
});
