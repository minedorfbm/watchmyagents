// Anthropic Managed Agents SSE stream client.
//
// Opens GET /v1/sessions/{id}/events/stream and yields one parsed event per
// SSE `data:` line. Handles reconnection on stream drop (exponential backoff,
// max attempts configurable).
//
// Uses built-in fetch + ReadableStream (Node 18+). Zero deps.

import { normalizeSseBuffer } from './sse.js';

const API_BASE = 'https://api.anthropic.com';
const BETA = 'managed-agents-2026-04-01';
const VERSION = '2023-06-01';
// v1.1.2 F-16 (P2 Codex audit): hard cap on a single SSE frame buffer.
// A buggy upstream proxy that strips event separators OR a compromised
// Anthropic-style endpoint streaming bytes forever without "\n\n" would
// otherwise OOM Shield's host. 1 MB is far above any real Anthropic
// event payload (the heaviest events are agent.thinking + agent.message
// which carry at most a few hundred KB of text). On overflow we throw,
// which propagates through the generator and triggers the caller's
// reconnect logic — same outcome as a network error.
const MAX_SSE_FRAME_BYTES = 1 * 1024 * 1024;

// v1.1.6 F-21 (P1 Codex audit): inactivity watchdog on the SSE reader.
// `reader.read()` blocks until the upstream sends bytes — there is no
// built-in heartbeat check. A misbehaving proxy or compromised upstream
// can keep the TCP connection open without ever emitting another event,
// which freezes Shield indefinitely without triggering the reconnect
// path in streamWithReconnect. 45 s is well above Anthropic's normal
// inter-event latency (typically sub-second when an agent is active,
// and the API sends SSE comment heartbeats `: ping` every ~15-30 s
// when it's idle), so 45 s without any byte at all is a strong signal
// the stream is dead but TCP-alive. On timeout we throw, the existing
// try/finally releases the reader, and the caller reconnects with
// exponential backoff.
const SSE_INACTIVITY_TIMEOUT_MS = 45_000;

function authHeaders(apiKey) {
  return {
    'x-api-key': apiKey,
    'anthropic-version': VERSION,
    'anthropic-beta': BETA,
    'accept': 'text/event-stream',
  };
}

// Async generator that yields parsed event objects from the SSE stream.
// Caller decides what to do with each (typically: evaluate policy + enforce).
//
// On stream end or network error, the generator throws. The caller should
// wrap it in retry logic if appropriate.
export async function* openEventStream({ apiKey, sessionId, signal }) {
  const url = `${API_BASE}/v1/sessions/${sessionId}/events/stream?beta=true`;
  const res = await fetch(url, { headers: authHeaders(apiKey), signal });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`stream open failed: HTTP ${res.status}: ${body.slice(0, 300)}`);
  }
  if (!res.body) throw new Error('stream open failed: no response body');

  const reader = res.body.getReader();
  const decoder = new TextDecoder('utf-8');
  let buffer = '';

  try {
    while (true) {
      // v1.1.6 F-21: race the reader against the inactivity watchdog so
      // a stalled-but-open stream cannot freeze us indefinitely. We
      // cancel the reader on timeout to release the underlying TCP
      // resources before throwing — otherwise the pending read() would
      // leak. The thrown error propagates to streamWithReconnect which
      // initiates a fresh open with backoff.
      const { done, value } = await readWithInactivityTimeout(
        reader,
        SSE_INACTIVITY_TIMEOUT_MS,
      );
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      // v1.1.4 F-18 (P1 Codex audit): normalize all SSE line terminators
      // (CR, CRLF) to LF so the indexOf('\n\n') scan below catches every
      // event boundary the spec allows. Without this, an upstream that
      // emits CRLF (common in reverse-proxy paths) yielded a buffer that
      // never matched and Shield silently lost the live enforcement loop.
      buffer = normalizeSseBuffer(buffer);

      // v1.1.2 F-16: guard against an upstream that never emits "\n\n" —
      // throw to abort the stream cleanly, the caller's reconnect logic
      // will pick up. Drop the buffer to free memory before throwing.
      if (buffer.length > MAX_SSE_FRAME_BYTES) {
        buffer = '';
        throw new Error(`SSE frame exceeded ${MAX_SSE_FRAME_BYTES} bytes — aborting stream (caller should reconnect)`);
      }

      // SSE frames are separated by a blank line. Post-normalize, the
      // canonical separator is "\n\n"; each frame may contain multiple
      // lines; we only care about `data:` lines for now.
      let nlIdx;
      while ((nlIdx = buffer.indexOf('\n\n')) !== -1) {
        const frame = buffer.slice(0, nlIdx);
        buffer = buffer.slice(nlIdx + 2);
        const data = parseFrame(frame);
        if (data) yield data;
      }
    }
    // Stream ended cleanly. Flush any final frame missing trailing \n\n.
    if (buffer.trim()) {
      const data = parseFrame(buffer);
      if (data) yield data;
    }
  } finally {
    try { reader.releaseLock(); } catch {}
  }
}

/**
 * Race a ReadableStreamDefaultReader's `.read()` against an inactivity
 * timeout. v1.1.6 F-21 (P1 Codex audit).
 *
 * Why this exists: a TCP-alive but byte-silent upstream (proxy with
 * keepalive but no SSE heartbeat, compromised endpoint, slowloris-style
 * stall) can leave `reader.read()` pending forever, freezing Shield's
 * event loop. Bounding the wait surfaces the stall as an error so
 * `streamWithReconnect` initiates a fresh connection.
 *
 * Exported so the unit tests can hit it directly with a mock reader
 * that never resolves.
 *
 * @param {ReadableStreamDefaultReader} reader
 * @param {number} timeoutMs
 * @returns {Promise<{ done: boolean, value?: Uint8Array }>}
 */
export async function readWithInactivityTimeout(reader, timeoutMs) {
  // We deliberately avoid Promise.race here: racing two pending promises
  // leaves the loser in a perpetual pending state, which Node's test
  // runner (rightly) flags as a resource leak. Instead we use the
  // Web Streams contract — `reader.cancel()` settles a pending read()
  // to `{ done: true }` — and a simple flag to distinguish the cancel
  // we issued from a legitimate end-of-stream.
  let timedOut = false;
  const timeoutId = setTimeout(() => {
    timedOut = true;
    // Cancel resolves the pending read() promise. We swallow any
    // rejection from cancel (some readers throw on already-cancelled
    // state) because the relevant error is the timeout itself.
    Promise.resolve(reader.cancel(new Error('SSE inactivity timeout')))
      .catch(() => undefined);
  }, timeoutMs);
  // NOTE: we deliberately do NOT call timeoutId.unref() here. The
  // unref() would make the timer non-blocking for the event loop, but
  // for a Web Stream backed by no actual I/O (e.g. unit tests, in-memory
  // sources) Node may then consider the loop empty and never fire the
  // timer at all — the call hangs forever. Since the timer is short-
  // lived (single-shot, cleared on the success path), keeping it ref'd
  // is harmless even in long-running daemons.
  try {
    const result = await reader.read();
    if (timedOut) {
      throw new Error(
        `SSE stream stalled — no data received for ${timeoutMs}ms (caller should reconnect)`,
      );
    }
    return result;
  } finally {
    clearTimeout(timeoutId);
  }
}

function parseFrame(frame) {
  // Concatenate all `data:` lines per the SSE spec (multi-line payload).
  const parts = [];
  for (const line of frame.split('\n')) {
    if (line.startsWith('data:')) parts.push(line.slice(5).trim());
  }
  if (parts.length === 0) return null;
  const payload = parts.join('\n');
  try { return JSON.parse(payload); }
  catch { return null; }
}

// High-level wrapper: stream forever, reconnecting on transient errors.
// Yields events; on fatal/permanent errors throws after maxAttempts.
export async function* streamWithReconnect({ apiKey, sessionId, signal, maxAttempts = 5, onReconnect }) {
  let attempt = 0;
  while (true) {
    try {
      for await (const ev of openEventStream({ apiKey, sessionId, signal })) {
        attempt = 0; // any event resets the backoff
        yield ev;
      }
      // Stream ended without throwing — session likely closed cleanly. Exit.
      return;
    } catch (e) {
      if (signal?.aborted) return;
      attempt++;
      if (attempt > maxAttempts) {
        throw new Error(`stream failed after ${maxAttempts} attempts: ${e.message}`);
      }
      const backoffMs = Math.min(30_000, 1000 * 2 ** (attempt - 1));
      if (onReconnect) onReconnect({ attempt, backoffMs, error: e });
      await new Promise(r => setTimeout(r, backoffMs));
    }
  }
}
