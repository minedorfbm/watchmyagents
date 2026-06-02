// SSE buffer normalization — v1.1.4 F-18 (P1 Codex audit).
//
// Before the fix, Shield's two SSE consumers only matched "\n\n" as an
// event separator. Production-grade reverse proxies (and the SSE spec
// itself) allow CRLF and bare CR line terminators. The streams silently
// stopped emitting events when fronted by such a proxy — breaking
// sub-second policy enforcement on agent events and instant policy
// propagation from Fortress.
//
// These tests verify normalizeSseBuffer handles every separator combo
// the spec allows AND remains chunk-safe (trailing CR is deferred,
// not eagerly converted, so a CRLF split across two chunks is not
// mis-interpreted as two empty lines).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeSseBuffer } from '../src/shield/sse.js';

// ── Single-shot normalization ──────────────────────────────────────────

test('F-18: LF-LF separator passes through unchanged', () => {
  const buf = 'data: foo\n\ndata: bar\n\n';
  assert.equal(normalizeSseBuffer(buf), buf);
});

test('F-18: CRLF-CRLF separator normalized to LF-LF', () => {
  const buf = 'data: foo\r\n\r\ndata: bar\r\n\r\n';
  assert.equal(normalizeSseBuffer(buf), 'data: foo\n\ndata: bar\n\n');
});

test('F-18: CR-CR separator normalized to LF-LF (with chunk-safe trailing CR deferred)', () => {
  const buf = 'data: foo\r\rdata: bar\r\r';
  // Trailing CR is deferred verbatim per the chunk-safe contract — it
  // might be the first half of an incoming CRLF on the next read.
  assert.equal(normalizeSseBuffer(buf), 'data: foo\n\ndata: bar\n\r');
  // When the stream actually ends (no more chunks), the caller's
  // existing end-of-stream flush handles the dangling CR — same as
  // any other partial frame.
});

test('F-18: CR-CR separator with a sentinel byte after → fully normalized to LF-LF', () => {
  // A non-CR character after the final CR proves both CRs convert.
  const buf = 'data: foo\r\rdata: bar\r\rEOM';
  assert.equal(normalizeSseBuffer(buf), 'data: foo\n\ndata: bar\n\nEOM');
});

test('F-18: mixed CR + LF terminators all collapse to LF', () => {
  // Spec-valid mix: CRLF line end then LF line end → "\r\n\n" is a
  // 2-line-terminator sequence = an event boundary.
  const buf = 'data: foo\r\n\ndata: bar';
  assert.equal(normalizeSseBuffer(buf), 'data: foo\n\ndata: bar');
});

test('F-18: mixed LF + CRLF terminators normalize correctly', () => {
  const buf = 'data: foo\n\r\ndata: bar';
  assert.equal(normalizeSseBuffer(buf), 'data: foo\n\ndata: bar');
});

test('F-18: empty buffer is a no-op', () => {
  assert.equal(normalizeSseBuffer(''), '');
});

test('F-18: buffer with no line terminators is a no-op', () => {
  assert.equal(normalizeSseBuffer('data: still-streaming'), 'data: still-streaming');
});

// ── Chunk-safe streaming behaviour ─────────────────────────────────────

test('F-18 chunk-safe: a TRAILING CR is preserved (not eagerly converted)', () => {
  // The trailing CR could be the first half of a CRLF arriving in the
  // next chunk. Eagerly converting it to LF would create a phantom
  // event boundary.
  const buf = 'data: foo\r';
  assert.equal(normalizeSseBuffer(buf), 'data: foo\r', 'trailing CR preserved verbatim');
});

test('F-18 chunk-safe: trailing CR + next chunk\'s LF forms a CRLF, not a CR+LF blank line', () => {
  // Simulate a chunk boundary inside CRLF: ["...foo\r", "\ndata: bar..."]
  let buf = '';
  buf = normalizeSseBuffer(buf + 'data: foo\r');           // chunk 1
  assert.equal(buf, 'data: foo\r', 'after chunk 1, the CR is still pending');
  buf = normalizeSseBuffer(buf + '\ndata: bar\r\n\r\n');   // chunk 2
  // The deferred CR + arriving LF = CRLF (single line terminator),
  // so after normalization we have a single LF between foo and data: bar,
  // NOT a "\n\n" event boundary.
  assert.equal(buf, 'data: foo\ndata: bar\n\n');
});

test('F-18 chunk-safe: trailing CR + next chunk starting with NON-LF → CR becomes its own line terminator', () => {
  let buf = '';
  buf = normalizeSseBuffer(buf + 'data: foo\r');
  buf = normalizeSseBuffer(buf + 'data: bar\r\n');
  // The pending CR is followed by 'd', not LF — so it's a bare CR
  // terminator and should normalize to LF.
  assert.equal(buf, 'data: foo\ndata: bar\n');
});

test('F-18 chunk-safe: multi-byte boundary stress — many chunks, mixed terminators', () => {
  // Reconstruct: "data: a\r\nfoo\r\n\r\ndata: b\r\n\r\n" delivered as
  // 1-byte chunks. The final buffer must split into two complete
  // events ("data: a\nfoo" and "data: b") separated by \n\n.
  const stream = 'data: a\r\nfoo\r\n\r\ndata: b\r\n\r\n';
  let buf = '';
  for (const ch of stream) {
    buf = normalizeSseBuffer(buf + ch);
  }
  assert.equal(buf, 'data: a\nfoo\n\ndata: b\n\n');
});

// ── Defensive: ill-formed inputs ───────────────────────────────────────

test('F-18: bare CR followed by content (no LF) → CR becomes LF', () => {
  const buf = 'a\rb\rc';
  // No trailing CR (last char is 'c'), so all bare CRs convert.
  assert.equal(normalizeSseBuffer(buf), 'a\nb\nc');
});

test('F-18: rejection of non-string input is silent (returns input as-is)', () => {
  // The helper is internal — callers always pass strings. But be
  // defensive against accidental misuse.
  assert.equal(normalizeSseBuffer(null), null);
  assert.equal(normalizeSseBuffer(undefined), undefined);
});

// ── Real-world end-to-end: SSE event with CRLF parses correctly ────────

test('F-18 end-to-end: stream.js-style indexOf("\\n\\n") finds CRLF event boundary post-normalize', () => {
  const incoming = 'data: {"type":"tool_use","id":"evt_1"}\r\n\r\n';
  const buf = normalizeSseBuffer(incoming);
  const idx = buf.indexOf('\n\n');
  assert.notEqual(idx, -1, 'event boundary must be findable after normalization');
  const frame = buf.slice(0, idx);
  assert.equal(frame, 'data: {"type":"tool_use","id":"evt_1"}');
});

test('F-18 end-to-end: policy-stream.js-style parse of CRLF event yields correct JSON', () => {
  const incoming = ': keepalive\r\ndata: {"rule_id":"r-7","action":"deny"}\r\n\r\n';
  const buf = normalizeSseBuffer(incoming);
  const eventBoundary = buf.indexOf('\n\n');
  assert.notEqual(eventBoundary, -1);
  const frame = buf.slice(0, eventBoundary);
  // Mirror the field-extraction logic from policy-stream.js _parseAndEmit
  const dataLines = [];
  for (const line of frame.split('\n')) {
    if (line.startsWith(':')) continue;
    if (line.startsWith('data:')) dataLines.push(line.slice(5).replace(/^ /, ''));
  }
  assert.deepEqual(JSON.parse(dataLines.join('\n')), { rule_id: 'r-7', action: 'deny' });
});
