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

test('F-53: addPreloaded folds late-agent disk ids into the static set', () => {
  // A fleet daemon discovers an agent AFTER startup; its on-disk history must
  // be dedupable against so it doesn't re-append already-captured events.
  const t = new SeenTracker(['boot1']);
  assert.equal(t.has('sLate', 'disk1'), false, 'late agent id not yet known');
  t.addPreloaded('disk1');
  t.addPreloaded('disk2');
  assert.equal(t.has('sLate', 'disk1'), true, 'preloaded id now deduped for any session');
  assert.equal(t.has('other', 'disk2'), true);
  // Preloaded ids are static — surviving forgetSession.
  t.add('sLate', 'rt1');
  t.forgetSession('sLate');
  assert.equal(t.has('any', 'disk1'), true, 'late-preloaded id is static like the constructor set');
  assert.equal(t.has('sLate', 'rt1'), false, 'but the session runtime id was dropped');
});

test('F-53: addPreloaded ignores falsy ids', () => {
  const t = new SeenTracker();
  t.addPreloaded(undefined);
  t.addPreloaded('');
  t.addPreloaded(null);
  assert.equal(t.size, 0, 'no junk ids added');
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
