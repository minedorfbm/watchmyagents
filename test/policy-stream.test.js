// PolicyStream — Shield SSE consumer (v1.1.0 Phase 2 instant-loop)
//
// Unit tests for the contract surface + the SSE event parsing logic.
// No real network IO (the connection layer is exercised by integration
// testing against a real /policies-stream endpoint).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PolicyStream } from '../src/shield/policy-stream.js';

const validOpts = () => ({
  url: 'https://x.supabase.co/functions/v1/policies-stream',
  apiKey: 'wma_testkey_0123456789abcdef',
  anthropicAgentId: 'agent_01ABCDEFGHIJKLMNOP',
});

// ── Constructor contract ────────────────────────────────────────────────

test('PolicyStream constructor requires url', () => {
  assert.throws(() => new PolicyStream({ ...validOpts(), url: undefined }), /url/);
});

test('PolicyStream constructor requires apiKey', () => {
  assert.throws(() => new PolicyStream({ ...validOpts(), apiKey: undefined }), /apiKey/);
});

test('PolicyStream constructor requires anthropicAgentId', () => {
  assert.throws(() => new PolicyStream({ ...validOpts(), anthropicAgentId: undefined }), /anthropicAgentId/);
});

test('PolicyStream instantiable with valid opts', () => {
  const ps = new PolicyStream(validOpts());
  assert.ok(ps instanceof PolicyStream);
  ps.close();
});

// ── State surface ───────────────────────────────────────────────────────

test('PolicyStream.isLive() is false before start()', () => {
  const ps = new PolicyStream(validOpts());
  assert.equal(ps.isLive(), false, 'isLive must be false until start() is called');
  ps.close();
});

test('PolicyStream.isLive() is false after close()', () => {
  const ps = new PolicyStream(validOpts());
  ps.close();
  assert.equal(ps.isLive(), false);
});

test('PolicyStream exposes EventEmitter interface', () => {
  const ps = new PolicyStream(validOpts());
  assert.equal(typeof ps.on, 'function');
  assert.equal(typeof ps.emit, 'function');
  assert.equal(typeof ps.removeListener, 'function');
  ps.close();
});

// ── SSE event parsing (via the private _parseAndEmit hook) ──────────────

test('_parseAndEmit emits policy_changed for a simple data event', () => {
  const ps = new PolicyStream(validOpts());
  let received = null;
  ps.on('policy_changed', (data) => { received = data; });
  ps._parseAndEmit('data: {"rule_id":"abc","action":"deny"}');
  assert.deepEqual(received, { rule_id: 'abc', action: 'deny' });
  ps.close();
});

test('_parseAndEmit handles multi-line data: blocks', () => {
  const ps = new PolicyStream(validOpts());
  let received = null;
  ps.on('policy_changed', (data) => { received = data; });
  // SSE spec: multiple data: lines concatenate with \n
  ps._parseAndEmit('data: {"foo":\ndata: "bar"}');
  assert.deepEqual(received, { foo: 'bar' });
  ps.close();
});

test('_parseAndEmit ignores comment lines (starting with :)', () => {
  const ps = new PolicyStream(validOpts());
  let received = null;
  ps.on('policy_changed', (data) => { received = data; });
  ps._parseAndEmit(': heartbeat\ndata: {"action":"allow"}\n: keepalive');
  assert.deepEqual(received, { action: 'allow' });
  ps.close();
});

test('_parseAndEmit emits nothing when no data: line present', () => {
  const ps = new PolicyStream(validOpts());
  let received = null;
  ps.on('policy_changed', (data) => { received = data; });
  ps._parseAndEmit('event: ping\n: just a comment');
  assert.equal(received, null);
  ps.close();
});

test('_parseAndEmit reports invalid JSON via onError instead of crashing', () => {
  const errors = [];
  const ps = new PolicyStream({ ...validOpts(), onError: (e) => errors.push(e.message) });
  let received = null;
  ps.on('policy_changed', (data) => { received = data; });
  ps._parseAndEmit('data: {not json}');
  assert.equal(received, null);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /invalid JSON/);
  ps.close();
});

test('_parseAndEmit strips the optional space after data:', () => {
  const ps = new PolicyStream(validOpts());
  let receivedA = null;
  let receivedB = null;
  ps.on('policy_changed', (data) => { if (!receivedA) receivedA = data; else receivedB = data; });
  // SSE spec: "data:value" and "data: value" both yield "value"
  ps._parseAndEmit('data:{"v":1}');
  ps._parseAndEmit('data: {"v":2}');
  assert.deepEqual(receivedA, { v: 1 });
  assert.deepEqual(receivedB, { v: 2 });
  ps.close();
});

// ── Shutdown ─────────────────────────────────────────────────────────────

test('close() is idempotent', () => {
  const ps = new PolicyStream(validOpts());
  ps.close();
  ps.close(); // must not throw
  assert.equal(ps.isLive(), false);
});
