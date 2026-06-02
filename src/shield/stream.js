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
      const { done, value } = await reader.read();
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
