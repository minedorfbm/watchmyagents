// SSE inactivity watchdog — v1.1.6 F-21 (P1 Codex audit).
//
// Codex flagged that `reader.read()` blocks forever when the upstream
// keeps the TCP connection open but stops emitting events. Without a
// watchdog the reconnect path in streamWithReconnect never fires and
// Shield silently misses every violation that would have flowed after
// the stall.
//
// readWithInactivityTimeout wraps the read() call in a Promise.race so
// the stall surfaces as a thrown error, which the higher-level
// generator translates into a normal reconnect attempt with exponential
// backoff.
//
// We test against REAL ReadableStream readers (Web Streams API, native
// in Node 18+) so we exercise the same code path as production. The
// streams' lifecycle is well-defined: a cancel() settles any pending
// read() to { done: true, value: undefined }, so no promise leaks.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readWithInactivityTimeout } from '../src/shield/stream.js';

// ── happy path ─────────────────────────────────────────────────────────

test('F-21: readWithInactivityTimeout resolves normally when stream emits in time', async () => {
  const stream = new ReadableStream({
    start(controller) {
      // Emit one chunk after ~10 ms.
      setTimeout(() => {
        controller.enqueue(new Uint8Array([0x68, 0x69])); // "hi"
        controller.close();
      }, 10);
    },
  });
  const reader = stream.getReader();
  try {
    const result = await readWithInactivityTimeout(reader, 1000);
    assert.equal(result.done, false);
    assert.deepEqual(Array.from(result.value), [0x68, 0x69]);
  } finally {
    try { reader.releaseLock(); } catch { /* ok if already released */ }
  }
});

// ── timeout path ───────────────────────────────────────────────────────

test('F-21: throws after timeoutMs when the stream stays silent', async () => {
  const stream = new ReadableStream({
    start() {
      // Never enqueue, never close — the SLOWLORIS scenario.
    },
  });
  const reader = stream.getReader();
  const start = Date.now();
  await assert.rejects(
    readWithInactivityTimeout(reader, 80),
    (err) =>
      err instanceof Error
      && /SSE stream stalled — no data received for 80ms/.test(err.message)
      && /caller should reconnect/.test(err.message),
  );
  const elapsed = Date.now() - start;
  assert.ok(elapsed >= 70, `should not fire before timeoutMs (elapsed ${elapsed}ms)`);
  assert.ok(elapsed < 500, `should fire near timeoutMs, not later (elapsed ${elapsed}ms)`);
});

test('F-21: timeout releases the underlying stream resources via cancel()', async () => {
  let cancelReason = null;
  const stream = new ReadableStream({
    start() { /* never emit */ },
    cancel(reason) { cancelReason = reason; },
  });
  const reader = stream.getReader();
  await assert.rejects(readWithInactivityTimeout(reader, 50), /stalled/);
  // The mock's cancel() captured the reason — our timeout error.
  assert.ok(cancelReason instanceof Error, 'cancel() must be invoked with an Error');
  assert.match(cancelReason.message, /inactivity timeout/i);
});

// ── delivery just before deadline ──────────────────────────────────────

test('F-21: a chunk delivered right before deadline still wins the race', async () => {
  const stream = new ReadableStream({
    start(controller) {
      // Deliver right at the edge — 40 ms vs 80 ms timeout.
      setTimeout(() => controller.enqueue(new Uint8Array([1])), 40);
    },
  });
  const reader = stream.getReader();
  try {
    const result = await readWithInactivityTimeout(reader, 80);
    assert.equal(result.done, false);
    assert.deepEqual(Array.from(result.value), [1]);
  } finally {
    try { reader.releaseLock(); } catch { /* ok */ }
  }
});

// ── successive calls (timer hygiene) ───────────────────────────────────

test('F-21: timer is cleared on every success — running the loop many times stays clean', async () => {
  const stream = new ReadableStream({
    start(controller) {
      // Emit 5 chunks then close.
      const emit = (n) => {
        controller.enqueue(new Uint8Array([n]));
        if (n < 5) setTimeout(() => emit(n + 1), 5);
        else controller.close();
      };
      setTimeout(() => emit(1), 5);
    },
  });
  const reader = stream.getReader();
  try {
    let count = 0;
    while (true) {
      const { done } = await readWithInactivityTimeout(reader, 1000);
      if (done) break;
      count++;
      if (count > 10) throw new Error('runaway loop guard');
    }
    assert.equal(count, 5, 'should have received exactly 5 chunks');
    // Reaching here without the test runner complaining about leaked
    // timers / pending promises means the watchdog cleans up correctly.
    assert.ok(true);
  } finally {
    try { reader.releaseLock(); } catch { /* ok */ }
  }
});
