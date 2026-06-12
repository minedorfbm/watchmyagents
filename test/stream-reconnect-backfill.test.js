// v1.4.5 F-55 (P1 audit) — SSE reconnect backfill + dedup.
//
// Before F-55, a dropped SSE stream reconnected at the LIVE position with no
// resume cursor, silently losing every event emitted during the drop window
// (including a requires_action that pauses the agent, or the tool_use that must
// be cached before it) — an enforcement blind window. streamWithReconnect now
// backfills the gap via an injected `backfill(afterId)` and de-duplicates by
// event id so the backfill/live overlap can't double-process.
//
// We exercise the orchestration through the `_openStream` test seam (no fetch,
// no network) and a stub `backfill`, the same way readWithInactivityTimeout is
// unit-tested directly.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { streamWithReconnect, makeSeenIdSet } from '../src/shield/stream.js';

async function* gen(...items) { for (const x of items) yield x; }
async function drain(it) { const out = []; for await (const x of it) out.push(x); return out; }

test('F-55: a clean stream (no drop) yields all events, backfill never called', async () => {
  let backfillCalls = 0;
  const out = await drain(streamWithReconnect({
    apiKey: 'k', sessionId: 's',
    backfill: () => { backfillCalls++; return gen(); },
    _openStream: () => gen({ id: 'e1', type: 'a' }, { id: 'e2', type: 'b' }),
  }));
  assert.deepEqual(out.map(e => e.id), ['e1', 'e2']);
  assert.equal(backfillCalls, 0, 'no reconnect → no backfill');
});

test('F-55: on drop, the gap is backfilled after the last-seen id, then live resumes', async () => {
  let opens = 0;
  const backfillAfter = [];
  const out = await drain(streamWithReconnect({
    apiKey: 'k', sessionId: 's', maxAttempts: 3,
    // first open yields e1 then drops; second open yields the resumed live tail.
    _openStream: () => {
      opens++;
      if (opens === 1) {
        return (async function* () {
          yield { id: 'e1', type: 'tool_use' };
          throw new Error('stream dropped');
        })();
      }
      return gen({ id: 'e4', type: 'live_after_gap' });
    },
    // the gap the live stream missed: e2 (requires_action), e3.
    backfill: (afterId) => {
      backfillAfter.push(afterId);
      return gen({ id: 'e2', type: 'requires_action' }, { id: 'e3', type: 'tool_use' });
    },
    onReconnect: () => {},
  }));
  assert.deepEqual(out.map(e => e.id), ['e1', 'e2', 'e3', 'e4'],
    'missed events e2/e3 are recovered in order between the drop and the live resume');
  assert.deepEqual(backfillAfter, ['e1'],
    'backfill is requested AFTER the last id yielded before the drop (exclusive)');
});

test('F-55: backfill/live overlap is de-duplicated by event id (no double-enforce)', async () => {
  let opens = 0;
  const out = await drain(streamWithReconnect({
    apiKey: 'k', sessionId: 's', maxAttempts: 3,
    _openStream: () => {
      opens++;
      if (opens === 1) {
        return (async function* () { yield { id: 'e1' }; throw new Error('drop'); })();
      }
      // live resume RE-DELIVERS e2 (overlap with backfill) then a fresh e3.
      return gen({ id: 'e2' }, { id: 'e3' });
    },
    backfill: () => gen({ id: 'e2' }), // gap also contains e2
    onReconnect: () => {},
  }));
  assert.deepEqual(out.map(e => e.id), ['e1', 'e2', 'e3'],
    'e2 appears once despite being in both the backfill and the live resume');
});

test('F-55: a backfill failure does not abort enforcement — live stream still resumes', async () => {
  let opens = 0; let sawBackfillError = false;
  const out = await drain(streamWithReconnect({
    apiKey: 'k', sessionId: 's', maxAttempts: 3,
    _openStream: () => {
      opens++;
      if (opens === 1) {
        return (async function* () { yield { id: 'e1' }; throw new Error('drop'); })();
      }
      return gen({ id: 'e2' });
    },
    backfill: () => { throw new Error('backfill endpoint 500'); },
    onReconnect: ({ backfillError }) => { if (backfillError) sawBackfillError = true; },
  }));
  assert.deepEqual(out.map(e => e.id), ['e1', 'e2'], 'live resumes despite backfill failure');
  assert.ok(sawBackfillError, 'the backfill failure is surfaced via onReconnect');
});

test('F-55: abort during a reconnect stops cleanly without re-opening', async () => {
  const ac = new AbortController();
  let opens = 0;
  const out = await drain(streamWithReconnect({
    apiKey: 'k', sessionId: 's', signal: ac.signal, maxAttempts: 3,
    _openStream: () => {
      opens++;
      return (async function* () {
        yield { id: 'e1' };
        ac.abort();                 // operator Ctrl-C mid-stream
        throw new Error('drop');
      })();
    },
    backfill: () => gen({ id: 'eX' }),
    onReconnect: () => {},
  }));
  assert.deepEqual(out.map(e => e.id), ['e1'], 'no backfill / no re-open after abort');
  assert.equal(opens, 1);
});

// ── the bounded dedup set ────────────────────────────────────────────────

test('F-55: makeSeenIdSet dedupes and is bounded with oldest-first eviction', () => {
  const s = makeSeenIdSet(10);
  assert.equal(s.seen('a'), false);
  assert.equal(s.seen('a'), true, 'second sighting is a dup');
  // Fill past the cap; the oldest survivors get evicted, newest are retained.
  for (let i = 0; i < 100; i++) s.seen('k' + i);
  assert.equal(s.seen('k99'), true, 'most-recent id still remembered (not evicted)');
});
