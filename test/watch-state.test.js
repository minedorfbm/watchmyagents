// v1.4.3 F-51 (P2 audit) — SeenTracker bounded dedup.
//
// The watch daemon must (a) never double-write an already-seen event, and
// (b) not grow its dedup memory without bound over a long run. SeenTracker
// keeps preloaded ids static and per-session runtime ids that are dropped on
// terminate, so live memory is bounded by ACTIVE sessions.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SeenTracker } from '../src/watch-state.js';

test('F-51: preloaded ids are seen for any session', () => {
  const t = new SeenTracker(['e1', 'e2']);
  assert.equal(t.has('sX', 'e1'), true);
  assert.equal(t.has('sY', 'e2'), true);
  assert.equal(t.has('sX', 'e3'), false);
});

test('F-51: runtime add is remembered within the same session', () => {
  const t = new SeenTracker();
  assert.equal(t.has('s1', 'e1'), false);
  t.add('s1', 'e1');
  assert.equal(t.has('s1', 'e1'), true, 'dedup holds after add');
});

test('F-51: forgetSession drops that session\'s runtime ids (bounds memory)', () => {
  const t = new SeenTracker();
  t.add('s1', 'e1');
  t.add('s1', 'e2');
  t.add('s2', 'e3');
  assert.equal(t.sessionCount, 2);
  assert.equal(t.size, 3);

  t.forgetSession('s1');
  assert.equal(t.sessionCount, 1, 's1 dropped');
  assert.equal(t.has('s1', 'e1'), false, 'dropped session ids are no longer remembered');
  assert.equal(t.has('s2', 'e3'), true, 's2 unaffected');
});

test('F-51: preloaded ids survive forgetSession (they are static)', () => {
  const t = new SeenTracker(['p1']);
  t.add('s1', 'e1');
  t.forgetSession('s1');
  assert.equal(t.has('any', 'p1'), true, 'preloaded set is not session-scoped');
});

test('F-51: size reflects preloaded + all live per-session sets', () => {
  const t = new SeenTracker(['p1', 'p2']);
  t.add('s1', 'e1');
  t.add('s2', 'e2');
  assert.equal(t.size, 4);
  t.forgetSession('s1');
  assert.equal(t.size, 3);
});

test('F-51: equivalence with a global set for the membership test', () => {
  // For globally-unique ids (one event → one session), SeenTracker membership
  // must match a naive global Set across a realistic add sequence.
  const t = new SeenTracker(['pre1']);
  const global = new Set(['pre1']);
  const ops = [['s1', 'a'], ['s1', 'b'], ['s2', 'c'], ['s2', 'd'], ['s3', 'e']];
  for (const [sid, id] of ops) {
    assert.equal(t.has(sid, id), global.has(id), `pre-add parity for ${id}`);
    t.add(sid, id); global.add(id);
    assert.equal(t.has(sid, id), true);
  }
});
