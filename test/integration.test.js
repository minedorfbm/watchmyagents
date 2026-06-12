// Integration tests — full pipe Watch → Anonymizer → Fortress payload
//
// These exercise the SEAMS between modules, not individual units:
//
//   raw Anthropic events
//      │
//      ▼  transformRawEventsToWMAActions   (src/sources/anthropic-managed.js)
//   WMAAction stream (with composition_pattern, session_thread_id, ...)
//      │
//      ▼  SignalsAggregator                (src/anonymizer.js)
//   signals payload (counts, hashes, sequences, session_ids)
//      │
//      ▼  uploadSignals body construction  (scripts/fetch-anthropic.js)
//   ingest-signals POST body
//
// Phase 1.B (v1.1.3) added the `transformRawEventsToWMAActions` extract
// so this test can feed SYNTHETIC raw Anthropic events into the pipe
// without any HTTP mock — the per-event normalization logic is exercised
// at the same level the production code runs it, just driven by a fixture
// async iterable instead of a live stream.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { transformRawEventsToWMAActions } from '../src/sources/anthropic-managed.js';
import { SignalsAggregator, hashWithSalt } from '../src/anonymizer.js';

const AGENT_ID = 'agent_01TESTABCDEFGHIJK';
const SESSION_ID = 'sesn_01TESTXYZ';
const SALT = 'test-salt-deterministic-0123456789abcdef';

// Helper: turn a synthetic event array into an async iterable.
async function* asyncIter(arr) {
  for (const ev of arr) yield ev;
}

// Helper: drain an async generator into an array.
async function drain(gen) {
  const out = [];
  for await (const x of gen) out.push(x);
  return out;
}

// ── Test A — Happy path: typical agent session ──────────────────────────

test('integration A: happy-path session yields the expected WMAAction sequence', async () => {
  const events = [
    {
      type: 'user.message',
      id: 'evt_1',
      processed_at: '2026-06-01T12:00:00.000Z',
      content: [{ type: 'text', text: 'Search for AI agent security best practices' }],
    },
    {
      type: 'span.model_request_start',
      id: 'span_1',
      processed_at: '2026-06-01T12:00:00.500Z',
    },
    {
      type: 'span.model_request_end',
      id: 'span_1_end',
      processed_at: '2026-06-01T12:00:02.500Z',
      model_request_start_id: 'span_1',
      model_usage: { input_tokens: 100, output_tokens: 50, cache_read_input_tokens: 0, cache_creation_input_tokens: 0 },
      is_error: false,
    },
    {
      type: 'agent.tool_use',
      id: 'tool_1',
      processed_at: '2026-06-01T12:00:03.000Z',
      name: 'web_search',
      input: { query: 'AI agent security best practices' },
    },
    {
      type: 'agent.tool_result',
      id: 'tool_1_res',
      processed_at: '2026-06-01T12:00:04.000Z',
      tool_use_id: 'tool_1',
      is_error: false,
      content: 'search results here',
    },
    {
      type: 'agent.message',
      id: 'msg_1',
      processed_at: '2026-06-01T12:00:05.000Z',
      content: [{ type: 'text', text: 'Here are some best practices...' }],
    },
  ];

  const actions = await drain(transformRawEventsToWMAActions(
    asyncIter(events),
    { agentId: AGENT_ID, sessionId: SESSION_ID, model: 'claude-sonnet-4-6' },
  ));

  // 5 actions emitted (span.model_request_start does NOT yield by itself;
  // it pairs with span.model_request_end to produce 1 llm_call).
  const types = actions.map((a) => a.action_type);
  assert.deepEqual(
    types,
    ['user_message', 'llm_call', 'tool_use', 'message'],
    'expected the canonical action_type sequence for a simple agent run',
  );

  // Every action carries provider + agent_id + session_id (the routing core)
  for (const a of actions) {
    assert.equal(a.provider, 'anthropic-managed');
    assert.equal(a.agent_id, AGENT_ID);
    assert.equal(a.session_id, SESSION_ID);
    assert.equal(a.composition_pattern, 'solo', 'no sub-thread in this fixture → solo');
  }

  // The llm_call carries tokens
  const llmCall = actions.find((a) => a.action_type === 'llm_call');
  assert.equal(llmCall.input_tokens, 100);
  assert.equal(llmCall.output_tokens, 50);

  // The tool_use carries the raw query (local-only)
  const toolUse = actions.find((a) => a.action_type === 'tool_use');
  assert.equal(toolUse.tool_name, 'web_search');
  assert.equal(toolUse.input.query, 'AI agent security best practices');
});

// ── Test B — Containment: raw bytes never reach the signals payload ─────

test('integration B: raw URL + secret prompt do NOT leak into the signals payload', async () => {
  const SECRET_URL = 'https://internal.example.com/secret-xyz';
  const SECRET_PROMPT = 'EXFIL_PROMPT_MARKER_DO_NOT_LEAK';

  const events = [
    {
      type: 'user.message', id: 'evt_1',
      processed_at: '2026-06-01T12:00:00Z',
      content: [{ type: 'text', text: SECRET_PROMPT }],
    },
    {
      type: 'agent.tool_use', id: 'tool_1',
      processed_at: '2026-06-01T12:00:01Z',
      name: 'web_fetch',
      input: { url: SECRET_URL },
    },
    {
      type: 'agent.tool_result', id: 'tool_1_res',
      processed_at: '2026-06-01T12:00:02Z',
      tool_use_id: 'tool_1', is_error: false, content: 'fetched',
    },
  ];

  // Run the FULL pipe: transform → aggregate → finalize
  const aggregator = new SignalsAggregator({ salt: SALT });
  for await (const action of transformRawEventsToWMAActions(
    asyncIter(events),
    { agentId: AGENT_ID, sessionId: SESSION_ID, model: 'claude-sonnet-4-6' },
  )) {
    aggregator.add(action);
  }
  const signals = aggregator.finalize();

  // Containment check: serialize the final payload, assert no leak
  const serialized = JSON.stringify(signals);
  assert.ok(!serialized.includes(SECRET_URL), 'raw URL must not appear in signals payload');
  assert.ok(!serialized.includes(SECRET_PROMPT), 'raw prompt must not appear in signals payload');

  // The hashed URL DOES appear (proof of capture without exposure)
  const expectedHash = hashWithSalt(SECRET_URL, SALT);
  assert.ok(signals.payload.ioc_hashes.includes(expectedHash), 'URL hashed into ioc_hashes');

  // The session_id IS opaquely present (forensic chain)
  assert.ok(signals.payload.session_ids.includes(SESSION_ID), 'session_id carried as opaque token');
});

// ── Test C — Sub-agent hierarchy detection ──────────────────────────────

test('integration C: sub-thread events flag composition_pattern=hierarchy', async () => {
  const events = [
    { type: 'user.message', id: 'evt_1', processed_at: '2026-06-01T12:00:00Z',
      session_thread_id: 'thr_root',
      content: [{ type: 'text', text: 'do research' }] },
    { type: 'agent.tool_use', id: 't1', processed_at: '2026-06-01T12:00:01Z',
      session_thread_id: 'thr_root',
      name: 'task_tool', input: { agent: 'researcher' } },
    { type: 'agent.tool_result', id: 't1_r', processed_at: '2026-06-01T12:00:01.500Z',
      tool_use_id: 't1', is_error: false, content: 'delegated' },
    { type: 'session.thread_created', id: 'tc1', processed_at: '2026-06-01T12:00:02Z',
      session_thread_id: 'thr_sub_1', agent_name: 'Worker Researcher' },
    { type: 'agent.thread_message_sent', id: 'tms1', processed_at: '2026-06-01T12:00:02.500Z',
      session_thread_id: 'thr_sub_1', agent_name: 'Parent CEO' },
    { type: 'agent.tool_use', id: 'ws1', processed_at: '2026-06-01T12:00:03Z',
      session_thread_id: 'thr_sub_1',
      name: 'web_search', input: { query: 'something' } },
    { type: 'agent.tool_result', id: 'ws1_r', processed_at: '2026-06-01T12:00:04Z',
      tool_use_id: 'ws1', is_error: false, content: 'results' },
    { type: 'agent.thread_message_received', id: 'tmr1', processed_at: '2026-06-01T12:00:05Z',
      session_thread_id: 'thr_sub_1', agent_name: 'Parent CEO' },
    { type: 'agent.message', id: 'final', processed_at: '2026-06-01T12:00:06Z',
      session_thread_id: 'thr_root',
      content: [{ type: 'text', text: 'final reply' }] },
  ];

  const actions = await drain(transformRawEventsToWMAActions(
    asyncIter(events),
    { agentId: AGENT_ID, sessionId: SESSION_ID, model: 'claude-sonnet-4-6' },
  ));

  // Find specific actions by their original event id
  const byId = (id) => actions.find((a) => a.id === id);

  // Root-thread events → solo
  assert.equal(byId('evt_1').composition_pattern, 'solo', 'user_message in root → solo');
  assert.equal(byId('tc1').composition_pattern, 'solo',
    'thread_created event itself is yielded as solo (parent\'s act of spawning)');
  assert.equal(byId('final').composition_pattern, 'solo', 'parent final message in root → solo');

  // Sub-thread events (after the thread_created registration) → hierarchy
  assert.equal(byId('tms1').composition_pattern, 'hierarchy',
    'thread_message_sent inside sub-thread → hierarchy');
  assert.equal(byId('ws1_r').composition_pattern, 'hierarchy',
    'tool_use inside sub-thread → hierarchy (paired via tool_result event)');
  assert.equal(byId('tmr1').composition_pattern, 'hierarchy',
    'thread_message_received inside sub-thread → hierarchy');

  // session_thread_id flows through
  assert.equal(byId('ws1_r').session_thread_id, 'thr_sub_1');

  // parent_agent_id stays null for Anthropic (sub-agent shares parent's identity)
  for (const a of actions) {
    assert.equal(a.parent_agent_id, null,
      'Anthropic adapter: sub-agents share parent agent_id, so parent_agent_id stays null');
  }
});

// ── Test D — F-8: incomplete tool calls flushed at end with error ───────

test('integration D: pendingToolUse without a tool_result is flushed at end-of-session', async () => {
  const events = [
    { type: 'agent.tool_use', id: 'blocked_call', processed_at: '2026-06-01T12:00:00Z',
      name: 'web_fetch', input: { url: 'https://blocked.example' } },
    // NO matching agent.tool_result — Shield blocked it, session ended, etc.
    { type: 'session.status_terminated', id: 'term', processed_at: '2026-06-01T12:00:05Z',
      stop_reason: { type: 'session_ended', message: 'normal' } },
  ];

  const actions = await drain(transformRawEventsToWMAActions(
    asyncIter(events),
    { agentId: AGENT_ID, sessionId: SESSION_ID, model: 'claude-sonnet-4-6' },
  ));

  // 2 actions: the state_transition for termination, AND a synthetic
  // tool_use with status=error / error=no_result_observed (the F-8 flush)
  const flushedToolUse = actions.find(
    (a) => a.action_type === 'tool_use' && a.id === 'blocked_call',
  );
  assert.ok(flushedToolUse, 'pending tool_use must be flushed as a tool_use action');
  assert.equal(flushedToolUse.status, 'error', 'flushed entry has status=error');
  assert.equal(flushedToolUse.error, 'no_result_observed', 'and the canonical error string');
  assert.equal(flushedToolUse.tool_name, 'web_fetch');
  assert.equal(flushedToolUse.input.url, 'https://blocked.example',
    'raw input preserved in local NDJSON (Containment: stays local, hashed by anonymizer)');
});

// ── Test E — Fortress payload shape end-to-end ──────────────────────────

test('integration E: aggregated signals payload has the documented shape + only allowed keys', async () => {
  const events = [
    { type: 'agent.tool_use', id: 't1', processed_at: '2026-06-01T12:00:00Z',
      name: 'web_search', input: { query: 'foo' } },
    { type: 'agent.tool_result', id: 't1r', processed_at: '2026-06-01T12:00:01Z',
      tool_use_id: 't1', is_error: false, content: '' },
    { type: 'agent.tool_use', id: 't2', processed_at: '2026-06-01T12:00:02Z',
      name: 'web_fetch', input: { url: 'https://example.com' } },
    { type: 'agent.tool_result', id: 't2r', processed_at: '2026-06-01T12:00:03Z',
      tool_use_id: 't2', is_error: false, content: '' },
  ];

  const agg = new SignalsAggregator({ salt: SALT });
  for await (const action of transformRawEventsToWMAActions(
    asyncIter(events),
    { agentId: AGENT_ID, sessionId: SESSION_ID, model: 'claude-sonnet-4-6' },
  )) {
    agg.add(action);
  }
  const signals = agg.finalize();

  // Top-level shape
  const allowedTopLevel = new Set(['window_start', 'window_end', 'payload', '_meta']);
  for (const k of Object.keys(signals)) {
    assert.ok(allowedTopLevel.has(k), `unexpected top-level key: ${k}`);
  }

  // Payload keys (the v1.0.2 F-6c set, all documented in CONTAINMENT.md)
  const allowedPayloadKeys = new Set([
    'counts', 'tool_counts', 'latencies_p50_ms', 'latencies_p95_ms',
    'error_rate_by_tool', 'ioc_hashes', 'sequences_top10', 'stop_reasons',
    'tokens_total', 'session_ids',
  ]);
  for (const k of Object.keys(signals.payload)) {
    assert.ok(allowedPayloadKeys.has(k), `unexpected payload key: ${k} (needs Containment review)`);
  }

  // Concrete shape sanity
  assert.equal(typeof signals.window_start, 'string');
  assert.equal(typeof signals.window_end, 'string');
  // tool_counts uses Object.create(null) internally (anti-prototype-pollution)
  // so spread to a plain object before comparing.
  assert.deepEqual({ ...signals.payload.tool_counts }, { web_search: 1, web_fetch: 1 });
  assert.ok(signals.payload.ioc_hashes.length > 0, 'ioc_hashes contains the URL hash');
  assert.ok(signals.payload.session_ids.includes(SESSION_ID));
});

// ── Test F — F-41: missing tool name normalizes to null, not literal 'unknown' ──

test('integration F: a tool_use with no name field yields tool_name=null (F-41)', async () => {
  const events = [
    // Tool call with the `name` field ABSENT (shape drift / malformed event).
    { type: 'agent.tool_use', id: 'noname1', processed_at: '2026-06-01T12:00:00Z',
      input: { command: 'rm -rf /' } },
    { type: 'agent.tool_result', id: 'noname1r', processed_at: '2026-06-01T12:00:01Z',
      tool_use_id: 'noname1', is_error: false, content: 'done' },
    // Custom tool, also nameless, never resolved — surfaces via the flush at
    // session termination (F-52: the flush is gated on the terminal state).
    { type: 'agent.custom_tool_use', id: 'noname2', processed_at: '2026-06-01T12:00:02Z',
      input: { foo: 'bar' } },
    { type: 'session.status_terminated', id: 'term', processed_at: '2026-06-01T12:00:05Z',
      stop_reason: { type: 'session_ended' } },
  ];

  const actions = await drain(transformRawEventsToWMAActions(
    asyncIter(events),
    { agentId: AGENT_ID, sessionId: SESSION_ID, model: 'claude-sonnet-4-6' },
  ));

  // A paired tool action carries the RESULT event's id, so match on shape.
  const paired = actions.find((a) => a.action_type === 'tool_use' && a.input?.command === 'rm -rf /');
  assert.ok(paired, 'paired tool_use must be emitted');
  assert.equal(paired.tool_name, null, 'missing name → null, NOT the literal "unknown"');
  assert.notEqual(paired.tool_name, 'unknown');

  const custom = actions.find((a) => a.id === 'noname2');
  assert.equal(custom.tool_name, null, 'nameless custom tool → null');

  // Raw input still preserved locally (Containment unaffected by F-41).
  assert.equal(paired.input.command, 'rm -rf /');
});

test('integration F: a nameless tool denylist does not collide two distinct tools under "unknown"', async () => {
  // Pre-F-41 two different nameless tools both bucketed as "unknown",
  // muddying forensics. With null they are simply excluded from per-tool
  // counts rather than merged into a fake "unknown" tool.
  const events = [
    { type: 'agent.tool_use', id: 'a1', processed_at: '2026-06-01T12:00:00Z', input: { x: 1 } },
    { type: 'agent.tool_result', id: 'a1r', processed_at: '2026-06-01T12:00:01Z', tool_use_id: 'a1', is_error: false, content: '' },
  ];
  const actions = await drain(transformRawEventsToWMAActions(
    asyncIter(events),
    { agentId: AGENT_ID, sessionId: SESSION_ID },
  ));
  const agg = new SignalsAggregator({ salt: SALT });
  for (const a of actions) agg.add(a);
  const payload = agg.finalize().payload;
  // No "unknown" bucket fabricated in tool counts.
  assert.equal(payload.tool_counts?.unknown, undefined,
    'null-named tools must NOT create an "unknown" tool bucket');
});

// ── Test G — F-50: custom tools are paired (real status/error/duration) ──

test('integration G: custom_tool_use + result → ONE paired row with real status + duration (F-50)', async () => {
  const events = [
    { type: 'agent.custom_tool_use', id: 'ct1', processed_at: '2026-06-01T12:00:00.000Z',
      name: 'send_invoice', input: { amount: 100 } },
    { type: 'user.custom_tool_result', id: 'ct1r', processed_at: '2026-06-01T12:00:02.000Z',
      custom_tool_use_id: 'ct1', is_error: false, content: 'sent' },
  ];
  const actions = await drain(transformRawEventsToWMAActions(
    asyncIter(events), { agentId: AGENT_ID, sessionId: SESSION_ID },
  ));
  const customs = actions.filter((a) => a.action_type === 'custom_tool_use');
  assert.equal(customs.length, 1, 'exactly ONE custom_tool_use row (paired, not two)');
  assert.equal(actions.filter((a) => a.action_type === 'custom_tool_result').length, 0,
    'the separate custom_tool_result row is folded into the paired row');
  const c = customs[0];
  assert.equal(c.tool_name, 'send_invoice');
  assert.equal(c.status, 'ok');
  assert.equal(c.duration_ms, 2000, 'duration computed from start→result');
  assert.equal(c.input.amount, 100, 'input preserved from the start');
});

test('integration G: a FAILING custom tool surfaces in error_rate_by_tool (F-50)', async () => {
  const events = [
    { type: 'agent.custom_tool_use', id: 'ct2', processed_at: '2026-06-01T12:00:00Z',
      name: 'risky_tool', input: {} },
    { type: 'user.custom_tool_result', id: 'ct2r', processed_at: '2026-06-01T12:00:01Z',
      custom_tool_use_id: 'ct2', is_error: true, content: 'boom' },
  ];
  const actions = await drain(transformRawEventsToWMAActions(
    asyncIter(events), { agentId: AGENT_ID, sessionId: SESSION_ID },
  ));
  const c = actions.find((a) => a.action_type === 'custom_tool_use');
  assert.equal(c.status, 'error');
  assert.equal(c.error, 'boom', 'error text from the result is captured');

  // The whole point: the aggregator now attributes the error to the tool.
  const agg = new SignalsAggregator({ salt: SALT });
  for (const a of actions) agg.add(a);
  const payload = agg.finalize().payload;
  // The tool is keyed by normalizeToolName (tool_hash:...), so assert on the
  // VALUE: the custom tool errored on its only call → error_rate 1.0.
  const rates = Object.values(payload.error_rate_by_tool || {});
  assert.ok(rates.length === 1 && rates[0] === 1,
    `failing custom tool must appear in error_rate_by_tool at rate 1.0 (got ${JSON.stringify(payload.error_rate_by_tool)})`);
});

test('integration G: a custom tool with NO result is flushed as no_result_observed (F-50)', async () => {
  const events = [
    { type: 'agent.custom_tool_use', id: 'ct3', processed_at: '2026-06-01T12:00:00Z',
      name: 'blocked_custom', input: { x: 1 } },
    { type: 'session.status_terminated', id: 'term', processed_at: '2026-06-01T12:00:05Z',
      stop_reason: { type: 'session_ended' } },
  ];
  const actions = await drain(transformRawEventsToWMAActions(
    asyncIter(events), { agentId: AGENT_ID, sessionId: SESSION_ID },
  ));
  const c = actions.find((a) => a.action_type === 'custom_tool_use' && a.id === 'ct3');
  assert.ok(c, 'unresolved custom tool must still be emitted (trace ALL actions)');
  assert.equal(c.status, 'error');
  assert.equal(c.error, 'no_result_observed');
  assert.equal(c.tool_name, 'blocked_custom');
});

test('integration G: an orphan custom_tool_result (no start) still emits, tool_name null (F-50)', async () => {
  const events = [
    { type: 'user.custom_tool_result', id: 'orphan_r', processed_at: '2026-06-01T12:00:01Z',
      custom_tool_use_id: 'never_seen', is_error: true, content: 'late' },
  ];
  const actions = await drain(transformRawEventsToWMAActions(
    asyncIter(events), { agentId: AGENT_ID, sessionId: SESSION_ID },
  ));
  const c = actions.find((a) => a.action_type === 'custom_tool_use');
  assert.ok(c, 'orphan result still emits an action (never drop)');
  assert.equal(c.tool_name, null);
  assert.equal(c.status, 'error');
});

// ── Test H — F-52: flush is gated on session termination (no double-count) ──

test('integration H: an in-flight tool (no result, session NOT terminated) is NOT flushed (F-52)', async () => {
  // This is the cross-cycle scenario: cycle N sees the start but no result and
  // no terminal state. Pre-F-52 the flush emitted a phantom no_result_observed
  // row here; cycle N+1 would then ALSO emit the real paired row → double-count.
  const cycleN = [
    { type: 'agent.tool_use', id: 't1', processed_at: '2026-06-01T12:00:00Z',
      name: 'web_fetch', input: { url: 'https://x' } },
    { type: 'agent.custom_tool_use', id: 'c1', processed_at: '2026-06-01T12:00:01Z',
      name: 'send', input: {} },
    // session still running — a non-terminal status update, not a terminate.
    { type: 'session.status_idle', id: 'idle', processed_at: '2026-06-01T12:00:02Z' },
  ];
  const actions = await drain(transformRawEventsToWMAActions(
    asyncIter(cycleN), { agentId: AGENT_ID, sessionId: SESSION_ID },
  ));
  assert.equal(actions.filter((a) => a.error === 'no_result_observed').length, 0,
    'no phantom no_result_observed while the session is still running');
  assert.equal(actions.filter((a) => a.action_type === 'tool_use').length, 0,
    'the in-flight tool_use is not emitted yet (will pair next cycle)');
  assert.equal(actions.filter((a) => a.action_type === 'custom_tool_use').length, 0,
    'the in-flight custom tool is not emitted yet either');
});

test('integration H: the SAME tool resolved next cycle yields exactly ONE row (no double-count) (F-52)', async () => {
  // Cycle N+1: the full session is re-fetched (start present again) and now the
  // result has arrived. We must get ONE paired row per tool, not a phantom +
  // a real one.
  const cycleNplus1 = [
    { type: 'agent.tool_use', id: 't1', processed_at: '2026-06-01T12:00:00Z',
      name: 'web_fetch', input: { url: 'https://x' } },
    { type: 'agent.tool_result', id: 't1r', processed_at: '2026-06-01T12:00:03Z',
      tool_use_id: 't1', is_error: false, content: 'ok' },
    { type: 'agent.custom_tool_use', id: 'c1', processed_at: '2026-06-01T12:00:01Z',
      name: 'send', input: {} },
    { type: 'user.custom_tool_result', id: 'c1r', processed_at: '2026-06-01T12:00:04Z',
      custom_tool_use_id: 'c1', is_error: false, content: 'sent' },
  ];
  const actions = await drain(transformRawEventsToWMAActions(
    asyncIter(cycleNplus1), { agentId: AGENT_ID, sessionId: SESSION_ID },
  ));
  assert.equal(actions.filter((a) => a.action_type === 'tool_use').length, 1,
    'exactly one tool_use row');
  assert.equal(actions.filter((a) => a.action_type === 'custom_tool_use').length, 1,
    'exactly one custom_tool_use row');
  assert.equal(actions.filter((a) => a.error === 'no_result_observed').length, 0,
    'no phantom error survived');
});

test('integration H: a genuinely blocked tool DOES flush once the session terminates (F-52)', async () => {
  // The flush still does its job — at session end, an unresolved start is
  // surfaced as no_result_observed (the blocked-exfil signal).
  const events = [
    { type: 'agent.tool_use', id: 't9', processed_at: '2026-06-01T12:00:00Z',
      name: 'bash', input: { command: 'curl evil' } },
    { type: 'session.status_terminated', id: 'term', processed_at: '2026-06-01T12:00:05Z',
      stop_reason: { type: 'blocked' } },
  ];
  const actions = await drain(transformRawEventsToWMAActions(
    asyncIter(events), { agentId: AGENT_ID, sessionId: SESSION_ID },
  ));
  const flushed = actions.find((a) => a.action_type === 'tool_use' && a.id === 't9');
  assert.ok(flushed, 'blocked tool must surface at session termination');
  assert.equal(flushed.error, 'no_result_observed');
});
