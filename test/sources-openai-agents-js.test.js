// OpenAI Agents SDK adapter tests — v1.3.0.
//
// Lock the contract of `src/sources/openai-agents-js.js`:
//   - 5 normalizers produce contract-compatible WMAAction objects
//   - wmaToolInputGuardrail() returns a shape-compatible OpenAI guardrail
//     object and correctly maps Shield decisions to allow/reject/throw
//   - attachWmaWatch() registers 5 listeners and detaches cleanly
//   - team_id propagation works via env var, env-empty bootstrap, and
//     across simulated handoff chain
//   - fail-closed default on Shield internal error, opt-in fail-open
//
// Fixtures: until real captures from a live @openai/agents run land in
// test/fixtures/openai-agents-events/, we use synthetic fixtures that
// match the documented shape from the SDK source. Once real ones exist,
// we swap. See test/fixtures/openai-agents-events/README.md.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EventEmitter } from 'node:events';

import {
  wmaToolInputGuardrail,
  attachWmaWatch,
  attachWmaWatchToAgent,
  normalizeAgentStart,
  normalizeAgentEnd,
  normalizeAgentHandoff,
  normalizeToolStart,
  normalizeToolEnd,
  adapterMeta,
} from '../src/sources/openai-agents-js.js';
import { __testing__ } from '../src/sources/openai-agents-js.js';
import { ACTION_TYPES, PROVIDERS, validateWMAAction } from '../src/sources/contract.js';
import { verifyDecisionChain } from '../src/shield/decision-chain.js';

const { ToolGuardrailFunctionOutputFactory, safeParseToolArgs, createTeamTracker } = __testing__;

// ── Synthetic fixtures (matching SDK shape — see lifecycle.ts in
//    @openai/agents repo). Replace with real captures when available. ──

const FIX_AGENT = { name: 'support_bot', model: 'gpt-5' };
const FIX_AGENT_HANDOFF_TARGET = { name: 'escalation_bot', model: 'gpt-5' };
const FIX_TOOL = { name: 'search_kb' };
const FIX_TOOL_CALL = {
  id: 'call_abc123',
  callId: 'call_abc123',
  name: 'search_kb',
  arguments: '{"query":"how do I reset my password"}',
};

// ── Normalizers — produce contract-compatible WMAAction objects ─────────

test('normalize: agent_start produces a valid WMAAction', () => {
  const evt = normalizeAgentStart({
    agent: FIX_AGENT,
    turnInput: ['hello'],
    sessionId: 'sess-1',
    teamId: 'team-A',
  });
  assert.equal(evt.provider, PROVIDERS.OPENAI_AGENTS);
  assert.equal(evt.agent_id, 'support_bot');
  assert.equal(evt.agent_name, 'support_bot');
  assert.equal(evt.session_id, 'sess-1');
  assert.equal(evt.action_type, ACTION_TYPES.MESSAGE);
  assert.equal(evt.team_id, 'team-A');
  assert.deepEqual(evt.input, { turn_input: ['hello'] });
  assert.equal(evt.output.kind, 'agent_start');
  const { valid, errors } = validateWMAAction(evt);
  assert.equal(valid, true, `expected valid, got: ${errors.join(', ')}`);
});

test('normalize: agent_end produces a valid WMAAction', () => {
  const evt = normalizeAgentEnd({
    agent: FIX_AGENT,
    output: 'final answer',
    sessionId: 'sess-1',
    teamId: 'team-A',
  });
  assert.equal(evt.action_type, ACTION_TYPES.MESSAGE);
  assert.equal(evt.output.kind, 'agent_end');
  assert.equal(evt.output.text, 'final answer');
  assert.equal(validateWMAAction(evt).valid, true);
});

test('normalize: agent_handoff produces HANDOFF action with hierarchy composition', () => {
  const evt = normalizeAgentHandoff({
    fromAgent: FIX_AGENT,
    toAgent: FIX_AGENT_HANDOFF_TARGET,
    sessionId: 'sess-1',
    teamId: 'team-A',
  });
  assert.equal(evt.action_type, ACTION_TYPES.HANDOFF);
  assert.equal(evt.parent_agent_id, 'support_bot');
  assert.equal(evt.agent_id, 'escalation_bot');
  assert.equal(evt.composition_pattern, 'hierarchy');
  assert.equal(evt.team_id, 'team-A');
  assert.equal(evt.output.from, 'support_bot');
  assert.equal(evt.output.to, 'escalation_bot');
  assert.equal(validateWMAAction(evt).valid, true);
});

test('normalize: tool_start parses JSON arguments and emits CUSTOM_TOOL_USE', () => {
  const evt = normalizeToolStart({
    agent: FIX_AGENT,
    tool: FIX_TOOL,
    toolCall: FIX_TOOL_CALL,
    sessionId: 'sess-1',
    teamId: 'team-A',
  });
  assert.equal(evt.action_type, ACTION_TYPES.CUSTOM_TOOL_USE);
  assert.equal(evt.tool_name, 'search_kb');
  assert.deepEqual(evt.input, { query: 'how do I reset my password' });
  assert.equal(evt.id.startsWith('oai-call_abc123'), true);
});

test('normalize: tool_end emits CUSTOM_TOOL_RESULT with output payload', () => {
  const evt = normalizeToolEnd({
    agent: FIX_AGENT,
    tool: FIX_TOOL,
    result: '5 KB articles found',
    toolCall: FIX_TOOL_CALL,
    sessionId: 'sess-1',
    teamId: 'team-A',
  });
  assert.equal(evt.action_type, ACTION_TYPES.CUSTOM_TOOL_RESULT);
  assert.deepEqual(evt.output, { text: '5 KB articles found' });
  assert.equal(evt.id.endsWith('-end'), true);
});

test('normalize: tool_end accepts non-string results (wraps in {value})', () => {
  const evt = normalizeToolEnd({
    agent: FIX_AGENT,
    tool: FIX_TOOL,
    result: { found: 5, items: ['a', 'b'] },
    toolCall: FIX_TOOL_CALL,
    sessionId: 'sess-1',
    teamId: 'team-A',
  });
  assert.deepEqual(evt.output, { value: { found: 5, items: ['a', 'b'] } });
});

test('normalize: tool_start falls back when arguments is not JSON-parseable', () => {
  const evt = normalizeToolStart({
    agent: FIX_AGENT,
    tool: FIX_TOOL,
    toolCall: { ...FIX_TOOL_CALL, arguments: 'not-json{' },
    sessionId: 'sess-1',
    teamId: null,
  });
  assert.equal(evt.input, null);  // fail-closed parse
});

test('normalize: tool_start handles missing agent.name via stable fallback id', () => {
  const evt = normalizeToolStart({
    agent: {},
    tool: { name: 'mystery' },
    toolCall: FIX_TOOL_CALL,
    sessionId: 'sess-1',
    teamId: null,
  });
  assert.match(evt.agent_id, /^oai-agent-/);
  assert.equal(evt.agent_name, null);
});

// ── safeParseToolArgs ──────────────────────────────────────────────────

test('safeParseToolArgs: parses JSON string', () => {
  assert.deepEqual(safeParseToolArgs('{"a":1}'), { a: 1 });
});

test('safeParseToolArgs: returns object passthrough', () => {
  assert.deepEqual(safeParseToolArgs({ a: 1 }), { a: 1 });
});

test('safeParseToolArgs: returns null on malformed JSON', () => {
  assert.equal(safeParseToolArgs('{broken'), null);
});

test('safeParseToolArgs: returns null on non-string/object', () => {
  assert.equal(safeParseToolArgs(42), null);
  assert.equal(safeParseToolArgs(null), null);
  assert.equal(safeParseToolArgs(undefined), null);
});

// ── ToolGuardrailFunctionOutputFactory (shape match @openai/agents) ────

test('factory: allow returns the documented shape', () => {
  const r = ToolGuardrailFunctionOutputFactory.allow();
  assert.deepEqual(r.behavior, { type: 'allow' });
});

test('factory: rejectContent carries the message', () => {
  const r = ToolGuardrailFunctionOutputFactory.rejectContent('nope');
  assert.deepEqual(r.behavior, { type: 'rejectContent', message: 'nope' });
});

test('factory: throwException carries no message field', () => {
  const r = ToolGuardrailFunctionOutputFactory.throwException();
  assert.deepEqual(r.behavior, { type: 'throwException' });
});

test('factory: outputInfo passes through on all three behaviors', () => {
  assert.deepEqual(
    ToolGuardrailFunctionOutputFactory.allow({ wma: 'x' }).outputInfo,
    { wma: 'x' },
  );
  assert.deepEqual(
    ToolGuardrailFunctionOutputFactory.rejectContent('m', { wma: 'y' }).outputInfo,
    { wma: 'y' },
  );
  assert.deepEqual(
    ToolGuardrailFunctionOutputFactory.throwException({ wma: 'z' }).outputInfo,
    { wma: 'z' },
  );
});

// ── wmaToolInputGuardrail — shape + decision mapping ───────────────────

const DENY_RULESET = {
  policies: [
    {
      id: 'block-search',
      name: 'Block search_kb',
      action: 'deny',
      mode: 'enforce',
      message: 'KB search is forbidden',
      match: { tool_name: 'search_kb' },
    },
  ],
  default: { action: 'allow' },
};

const INTERRUPT_RULESET = {
  policies: [
    {
      id: 'kill-on-search',
      name: 'Kill on search',
      action: 'interrupt',
      mode: 'enforce',
      message: 'KB search triggers kill',
      match: { tool_name: 'search_kb' },
    },
  ],
  default: { action: 'allow' },
};

const SHADOW_RULESET = {
  policies: [
    {
      id: 'shadow-search',
      name: 'Shadow search',
      action: 'deny',
      mode: 'shadow',
      message: 'would have blocked',
      match: { tool_name: 'search_kb' },
    },
  ],
  default: { action: 'allow' },
};

const ALLOW_RULESET = {
  policies: [],
  default: { action: 'allow' },
};

async function withTempLogDir(fn) {
  const dir = await mkdtemp(join(tmpdir(), 'wma-oai-test-'));
  try { return await fn(dir); }
  finally { await rm(dir, { recursive: true, force: true }); }
}

test('guardrail: shape is { type: "tool_input", name, run } (matches OpenAI SDK)', () => {
  const g = wmaToolInputGuardrail({ ruleset: ALLOW_RULESET });
  assert.equal(g.type, 'tool_input');
  assert.equal(g.name, 'watchmyagents-shield');
  assert.equal(typeof g.run, 'function');
});

test('guardrail: allow ruleset → behavior.type === "allow"', async () => {
  await withTempLogDir(async (logDir) => {
    const g = wmaToolInputGuardrail({ ruleset: ALLOW_RULESET, logDir });
    const r = await g.run({ agent: FIX_AGENT, toolCall: FIX_TOOL_CALL });
    assert.equal(r.behavior.type, 'allow');
  });
});

test('guardrail: deny ruleset → behavior.type === "rejectContent" + message', async () => {
  await withTempLogDir(async (logDir) => {
    const g = wmaToolInputGuardrail({ ruleset: DENY_RULESET, logDir });
    const r = await g.run({ agent: FIX_AGENT, toolCall: FIX_TOOL_CALL });
    assert.equal(r.behavior.type, 'rejectContent');
    assert.equal(r.behavior.message, 'KB search is forbidden');
    assert.equal(r.outputInfo.wma.rule_id, 'block-search');
  });
});

test('guardrail: interrupt ruleset → behavior.type === "throwException"', async () => {
  await withTempLogDir(async (logDir) => {
    const g = wmaToolInputGuardrail({ ruleset: INTERRUPT_RULESET, logDir });
    const r = await g.run({ agent: FIX_AGENT, toolCall: FIX_TOOL_CALL });
    assert.equal(r.behavior.type, 'throwException');
    assert.equal(r.outputInfo.wma.rule_id, 'kill-on-search');
  });
});

test('guardrail: shadow mode logs but always allows', async () => {
  await withTempLogDir(async (logDir) => {
    const g = wmaToolInputGuardrail({ ruleset: SHADOW_RULESET, logDir });
    const r = await g.run({ agent: FIX_AGENT, toolCall: FIX_TOOL_CALL });
    assert.equal(r.behavior.type, 'allow');
    assert.equal(r.outputInfo.wma.mode, 'shadow');
    assert.equal(r.outputInfo.wma.shadow_decision, 'deny');
  });
});

test('guardrail: writes shield_decision row with audit chain to NDJSON', async () => {
  await withTempLogDir(async (logDir) => {
    const g = wmaToolInputGuardrail({ ruleset: DENY_RULESET, logDir });
    await g.run({ agent: FIX_AGENT, toolCall: FIX_TOOL_CALL });

    const day = new Date().toISOString().slice(0, 10);
    const path = join(logDir, 'openai-agents', `${day}.ndjson`);
    const text = await readFile(path, 'utf8');
    const lines = text.trim().split('\n').map((l) => JSON.parse(l));

    const shieldRows = lines.filter((l) => l.action_type === 'shield_decision');
    assert.ok(shieldRows.length >= 1, 'expected at least 1 shield_decision row');
    assert.ok(shieldRows[0].prev_hash, 'first row must carry prev_hash (chain)');
    assert.ok(shieldRows[0].chain_hash, 'first row must carry chain_hash (chain)');

    const verify = verifyDecisionChain(shieldRows);
    assert.equal(verify.ok, true, `chain must verify clean: ${verify.reason}`);
  });
});

// F-29 (v1.3.1, P1 Codex audit on v1.3.0)
test('guardrail: shield_decision row carries provider="openai-agents" (not "anthropic-managed")', async () => {
  await withTempLogDir(async (logDir) => {
    const g = wmaToolInputGuardrail({ ruleset: DENY_RULESET, logDir });
    await g.run({ agent: FIX_AGENT, toolCall: FIX_TOOL_CALL });

    const day = new Date().toISOString().slice(0, 10);
    const path = join(logDir, 'openai-agents', `${day}.ndjson`);
    const text = await readFile(path, 'utf8');
    const lines = text.trim().split('\n').map((l) => JSON.parse(l));

    const shieldRows = lines.filter((l) => l.action_type === 'shield_decision');
    assert.ok(shieldRows.length >= 1);
    // The whole point of F-29: this MUST be 'openai-agents'. Before the
    // fix it was hardcoded to 'anthropic-managed' in DecisionLogger.
    assert.equal(shieldRows[0].provider, PROVIDERS.OPENAI_AGENTS);
    assert.notEqual(shieldRows[0].provider, PROVIDERS.ANTHROPIC_MANAGED);
  });
});

test('guardrail: also writes the tool_use observation row alongside shield_decision', async () => {
  await withTempLogDir(async (logDir) => {
    const g = wmaToolInputGuardrail({ ruleset: ALLOW_RULESET, logDir });
    await g.run({ agent: FIX_AGENT, toolCall: FIX_TOOL_CALL });

    const day = new Date().toISOString().slice(0, 10);
    const path = join(logDir, 'openai-agents', `${day}.ndjson`);
    const text = await readFile(path, 'utf8');
    const lines = text.trim().split('\n').map((l) => JSON.parse(l));

    const toolRows = lines.filter((l) => l.action_type === ACTION_TYPES.CUSTOM_TOOL_USE);
    assert.equal(toolRows.length, 1);
    assert.equal(toolRows[0].tool_name, 'search_kb');
    assert.deepEqual(toolRows[0].input, { query: 'how do I reset my password' });
  });
});

test('guardrail: fail-closed by default on Shield internal error', async () => {
  await withTempLogDir(async (logDir) => {
    // Force an internal error by passing a bogus ruleset that throws on eval.
    const trapRuleset = {
      get policies() { throw new Error('boom'); },
      default: { action: 'allow' },
    };
    const g = wmaToolInputGuardrail({ ruleset: trapRuleset, logDir });
    const r = await g.run({ agent: FIX_AGENT, toolCall: FIX_TOOL_CALL });
    assert.equal(r.behavior.type, 'rejectContent');
    assert.match(r.behavior.message, /fail-closed/);
    assert.equal(r.outputInfo.wma.failOpenApplied, false);
  });
});

test('guardrail: fail-open when opted in explicitly', async () => {
  await withTempLogDir(async (logDir) => {
    const trapRuleset = {
      get policies() { throw new Error('boom'); },
      default: { action: 'allow' },
    };
    const g = wmaToolInputGuardrail({ ruleset: trapRuleset, logDir, failOpen: true });
    const r = await g.run({ agent: FIX_AGENT, toolCall: FIX_TOOL_CALL });
    assert.equal(r.behavior.type, 'allow');
    assert.equal(r.outputInfo.wma.failOpenApplied, true);
  });
});

// F-31 (v1.4, P2 Codex audit on v1.3.0) — error message must not leak details
test('F-31: fail-closed message hides raw err.message from the model (generic + ref code)', async () => {
  await withTempLogDir(async (logDir) => {
    const SECRET_PATH = '/etc/shadow/super-secret-policy-file.json';
    const trapRuleset = {
      get policies() { throw new Error(`cannot read ${SECRET_PATH}: EACCES`); },
      default: { action: 'allow' },
    };
    const g = wmaToolInputGuardrail({ ruleset: trapRuleset, logDir });
    const r = await g.run({ agent: FIX_AGENT, toolCall: FIX_TOOL_CALL });

    assert.equal(r.behavior.type, 'rejectContent');
    // The agent-visible message is the rejectContent.message.
    // It MUST NOT contain the raw err.message (path + EACCES).
    assert.ok(!r.behavior.message.includes(SECRET_PATH),
      `model-visible message must not leak local path. got: ${r.behavior.message}`);
    assert.ok(!r.behavior.message.includes('EACCES'),
      'model-visible message must not leak permission code');
    // It MUST carry a correlable ref code matching WMA-SHL-<8hex>
    assert.match(r.behavior.message, /Ref:\s+WMA-SHL-[0-9a-f]{8}/i);
    assert.match(r.behavior.message, /fail-closed/);

    // outputInfo is application-side metadata (NOT surfaced to model).
    // It keeps the full err.message + the same ref so the application
    // can correlate to its own logs.
    assert.equal(r.outputInfo.wma.errorRef, r.behavior.message.match(/WMA-SHL-[0-9a-f]{8}/i)[0]);
    assert.ok(r.outputInfo.wma.error.includes(SECRET_PATH),
      'outputInfo still preserves details for the application');
  });
});

test('F-31: fail-open also carries a ref code for correlation', async () => {
  await withTempLogDir(async (logDir) => {
    const trapRuleset = {
      get policies() { throw new Error('boom'); },
      default: { action: 'allow' },
    };
    const g = wmaToolInputGuardrail({ ruleset: trapRuleset, logDir, failOpen: true });
    const r = await g.run({ agent: FIX_AGENT, toolCall: FIX_TOOL_CALL });
    assert.equal(r.behavior.type, 'allow');
    assert.equal(r.outputInfo.wma.failOpenApplied, true);
    assert.match(r.outputInfo.wma.errorRef, /^WMA-SHL-[0-9a-f]{8}$/);
  });
});

test('guardrail: missing ruleset + no path → warning and default-allow', async () => {
  await withTempLogDir(async (logDir) => {
    // Capture stderr to assert the one-time warning fires.
    const orig = process.stderr.write.bind(process.stderr);
    let stderrOut = '';
    process.stderr.write = (chunk) => { stderrOut += String(chunk); return true; };

    try {
      const g = wmaToolInputGuardrail({ logDir });
      const r = await g.run({ agent: FIX_AGENT, toolCall: FIX_TOOL_CALL });
      assert.equal(r.behavior.type, 'allow');
      assert.match(stderrOut, /no policy ruleset configured/);
    } finally {
      process.stderr.write = orig;
    }
  });
});

// ── attachWmaWatch — listener registration + detach ────────────────────

test('attachWmaWatch: throws when runner lacks .on()', () => {
  assert.throws(() => attachWmaWatch({}), /\.on\(/);
  assert.throws(() => attachWmaWatch(null), /\.on\(/);
});

test('attachWmaWatch: registers listeners for all 5 lifecycle events', () => {
  const ee = new EventEmitter();
  attachWmaWatch(ee, { logDir: '/tmp/wma-test-noop' });
  assert.equal(ee.listenerCount('agent_start'), 1);
  assert.equal(ee.listenerCount('agent_end'), 1);
  assert.equal(ee.listenerCount('agent_handoff'), 1);
  assert.equal(ee.listenerCount('agent_tool_start'), 1);
  assert.equal(ee.listenerCount('agent_tool_end'), 1);
});

test('attachWmaWatch: detach() removes the listeners', () => {
  const ee = new EventEmitter();
  const detach = attachWmaWatch(ee, { logDir: '/tmp/wma-test-noop' });
  detach();
  assert.equal(ee.listenerCount('agent_start'), 0);
  assert.equal(ee.listenerCount('agent_tool_end'), 0);
});

test('attachWmaWatch: tool_start event flows through to NDJSON', async () => {
  await withTempLogDir(async (logDir) => {
    const ee = new EventEmitter();
    attachWmaWatch(ee, { logDir, sessionId: 'sess-watch' });
    ee.emit('agent_tool_start', /*ctx*/ null, FIX_AGENT, FIX_TOOL, { toolCall: FIX_TOOL_CALL });

    // The handler is async; let it settle.
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setTimeout(r, 50));

    const day = new Date().toISOString().slice(0, 10);
    const path = join(logDir, 'openai-agents', `${day}.ndjson`);
    const text = await readFile(path, 'utf8');
    const lines = text.trim().split('\n').map((l) => JSON.parse(l));
    const tool = lines.find((l) => l.action_type === ACTION_TYPES.CUSTOM_TOOL_USE);
    assert.ok(tool, 'tool_start observation must land in NDJSON');
    assert.equal(tool.tool_name, 'search_kb');
  });
});

test('attachWmaWatch: a throwing listener body never propagates to runner', async () => {
  await withTempLogDir(async (logDir) => {
    const ee = new EventEmitter();
    // Use a logger that throws on every write to force the inner try/catch.
    const failingLogger = { write: async () => { throw new Error('disk full'); } };
    attachWmaWatch(ee, { logDir, sessionId: 's', logger: failingLogger });

    // Capture stderr.
    const orig = process.stderr.write.bind(process.stderr);
    let stderrOut = '';
    process.stderr.write = (chunk) => { stderrOut += String(chunk); return true; };
    try {
      // emit must NOT throw — even if our handler crashes internally.
      ee.emit('agent_tool_start', null, FIX_AGENT, FIX_TOOL, { toolCall: FIX_TOOL_CALL });
      await new Promise((r) => setImmediate(r));
      await new Promise((r) => setTimeout(r, 50));
      assert.match(stderrOut, /watch agent_tool_start error/);
    } finally {
      process.stderr.write = orig;
    }
  });
});

// ── Team tracker ───────────────────────────────────────────────────────

test('teamTracker: bootstrap mints a stable id and resolve returns it', () => {
  const t = createTeamTracker(null);
  const a = t.bootstrap('sess-1');
  const b = t.bootstrap('sess-1');
  assert.equal(a, b);
  assert.equal(t.resolve('sess-1'), a);
});

test('teamTracker: different sessions get different team ids', () => {
  const t = createTeamTracker(null);
  const a = t.bootstrap('sess-1');
  const b = t.bootstrap('sess-2');
  assert.notEqual(a, b);
});

test('teamTracker: env override wins over per-session id', () => {
  const t = createTeamTracker('customer-explicit-team');
  assert.equal(t.bootstrap('sess-1'), 'customer-explicit-team');
  assert.equal(t.resolve('sess-2'), 'customer-explicit-team');
});

test('teamTracker: recordHandoff returns the existing team id (propagation)', () => {
  const t = createTeamTracker(null);
  const original = t.bootstrap('sess-1');
  const propagated = t.recordHandoff({ name: 'A' }, { name: 'B' }, 'sess-1');
  assert.equal(propagated, original);
});

test('teamTracker: resolve returns null for unknown sessions', () => {
  const t = createTeamTracker(null);
  assert.equal(t.resolve('never-bootstrapped'), null);
});

// ── End-to-end: handoff chain propagates team_id across events ─────────

test('e2e: a handoff chain emitted to watch shares a single team_id', async () => {
  await withTempLogDir(async (logDir) => {
    const ee = new EventEmitter();
    attachWmaWatch(ee, { logDir, sessionId: 'sess-chain' });

    ee.emit('agent_start', null, FIX_AGENT, ['kickoff']);
    ee.emit('agent_tool_start', null, FIX_AGENT, FIX_TOOL, { toolCall: FIX_TOOL_CALL });
    ee.emit('agent_tool_end', null, FIX_AGENT, FIX_TOOL, 'ok', { toolCall: FIX_TOOL_CALL });
    ee.emit('agent_handoff', null, FIX_AGENT, FIX_AGENT_HANDOFF_TARGET);
    ee.emit('agent_tool_start', null, FIX_AGENT_HANDOFF_TARGET, FIX_TOOL, { toolCall: FIX_TOOL_CALL });
    ee.emit('agent_end', null, FIX_AGENT_HANDOFF_TARGET, 'done');

    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setTimeout(r, 100));

    const day = new Date().toISOString().slice(0, 10);
    const path = join(logDir, 'openai-agents', `${day}.ndjson`);
    const text = await readFile(path, 'utf8');
    const lines = text.trim().split('\n').map((l) => JSON.parse(l));

    const teamIds = new Set(lines.map((l) => l.team_id).filter(Boolean));
    assert.equal(teamIds.size, 1, `expected single team_id across handoff chain, got ${teamIds.size}: ${[...teamIds]}`);
  });
});

// ── Adapter metadata ───────────────────────────────────────────────────

test('adapterMeta: provider + capabilities are frozen', () => {
  assert.equal(adapterMeta.provider, 'openai-agents');
  assert.equal(adapterMeta.customerInstrumented, true);
  assert.equal(adapterMeta.capabilities.preToolDeny, true);
  assert.equal(adapterMeta.capabilities.teamIdAutoDetect, true);
  // Object.isFrozen check
  assert.throws(() => { adapterMeta.displayName = 'mutated'; }, TypeError);
});

// ── AgentHooks pattern (attachWmaWatchToAgent) ─────────────────────────
//
// When the customer uses the convenience `run(agent, ...)` function from
// @openai/agents (vs. an explicit `new Runner()`), events fire via the
// AgentHooks EventEmitter on the agent itself, with DIFFERENT signatures
// for agent_end / agent_handoff / agent_tool_start / agent_tool_end
// (the agent is implicit — it's the one we registered on). See the
// inline doc above `attachWmaWatchToAgent` in src/sources/openai-agents-js.js.

test('attachWmaWatchToAgent: throws when agent lacks .on()', () => {
  assert.throws(() => attachWmaWatchToAgent({}), /\.on\(/);
  assert.throws(() => attachWmaWatchToAgent(null), /\.on\(/);
});

test('attachWmaWatchToAgent: registers listeners for all 5 lifecycle events', () => {
  const ee = new EventEmitter();
  ee.name = 'guardian_bot';
  attachWmaWatchToAgent(ee, { logDir: '/tmp/wma-test-noop' });
  assert.equal(ee.listenerCount('agent_start'), 1);
  assert.equal(ee.listenerCount('agent_end'), 1);
  assert.equal(ee.listenerCount('agent_handoff'), 1);
  assert.equal(ee.listenerCount('agent_tool_start'), 1);
  assert.equal(ee.listenerCount('agent_tool_end'), 1);
});

test('attachWmaWatchToAgent: detach() removes all 5 listeners', () => {
  const ee = new EventEmitter();
  ee.name = 'guardian_bot';
  const detach = attachWmaWatchToAgent(ee, { logDir: '/tmp/wma-test-noop' });
  detach();
  assert.equal(ee.listenerCount('agent_start'), 0);
  assert.equal(ee.listenerCount('agent_end'), 0);
  assert.equal(ee.listenerCount('agent_handoff'), 0);
  assert.equal(ee.listenerCount('agent_tool_start'), 0);
  assert.equal(ee.listenerCount('agent_tool_end'), 0);
});

test('attachWmaWatchToAgent: agent_end fires with 2 args (no agent in args) and still logs', async () => {
  await withTempLogDir(async (logDir) => {
    // The closure-captured agent provides agent_id when the args don't.
    const ee = new EventEmitter();
    ee.name = 'guardian_bot';
    attachWmaWatchToAgent(ee, { logDir, sessionId: 'sess-ah-end' });

    // AgentHooks signature: (context, output) — only 2 args, NO agent.
    ee.emit('agent_end', /* ctx */ {}, 'final answer text');

    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setTimeout(r, 50));

    const day = new Date().toISOString().slice(0, 10);
    const path = join(logDir, 'openai-agents', `${day}.ndjson`);
    const text = await readFile(path, 'utf8');
    const lines = text.trim().split('\n').map((l) => JSON.parse(l));
    const endRow = lines.find((l) => l.output?.kind === 'agent_end');
    assert.ok(endRow, 'agent_end must reach NDJSON');
    assert.equal(endRow.agent_id, 'guardian_bot', 'agent_id must come from closure-captured agent');
    assert.equal(endRow.output.text, 'final answer text');
  });
});

test('attachWmaWatchToAgent: agent_handoff fires with (ctx, toAgent) and uses closure agent as fromAgent', async () => {
  await withTempLogDir(async (logDir) => {
    const ee = new EventEmitter();
    ee.name = 'triage_bot';
    attachWmaWatchToAgent(ee, { logDir, sessionId: 'sess-ah-handoff' });

    // AgentHooks signature: (context, toAgent) — NO fromAgent in args.
    const toAgent = { name: 'escalation_bot', model: 'gpt-5' };
    ee.emit('agent_handoff', /* ctx */ {}, toAgent);

    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setTimeout(r, 50));

    const day = new Date().toISOString().slice(0, 10);
    const path = join(logDir, 'openai-agents', `${day}.ndjson`);
    const text = await readFile(path, 'utf8');
    const lines = text.trim().split('\n').map((l) => JSON.parse(l));
    const handoffRow = lines.find((l) => l.action_type === ACTION_TYPES.HANDOFF);
    assert.ok(handoffRow, 'handoff must reach NDJSON');
    // fromAgent = the closure-captured agent (triage_bot)
    assert.equal(handoffRow.parent_agent_id, 'triage_bot');
    // toAgent = the one passed in args
    assert.equal(handoffRow.agent_id, 'escalation_bot');
    assert.equal(handoffRow.output.from, 'triage_bot');
    assert.equal(handoffRow.output.to, 'escalation_bot');
  });
});

test('attachWmaWatchToAgent: agent_tool_start fires with (ctx, tool, details) and uses closure agent', async () => {
  await withTempLogDir(async (logDir) => {
    const ee = new EventEmitter();
    ee.name = 'guardian_bot';
    attachWmaWatchToAgent(ee, { logDir, sessionId: 'sess-ah-tool' });

    // AgentHooks signature: (context, tool, details) — NO agent in args.
    const tool = { name: 'analyze_export_file' };
    const toolCall = {
      id: 'fc_abc',
      callId: 'call_xyz',
      name: 'analyze_export_file',
      arguments: '{"path":"/tmp/export.json"}',
    };
    ee.emit('agent_tool_start', /* ctx */ {}, tool, { toolCall });

    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setTimeout(r, 50));

    const day = new Date().toISOString().slice(0, 10);
    const path = join(logDir, 'openai-agents', `${day}.ndjson`);
    const text = await readFile(path, 'utf8');
    const lines = text.trim().split('\n').map((l) => JSON.parse(l));
    const toolRow = lines.find((l) => l.action_type === ACTION_TYPES.CUSTOM_TOOL_USE);
    assert.ok(toolRow);
    assert.equal(toolRow.agent_id, 'guardian_bot', 'agent_id must come from closure');
    assert.equal(toolRow.tool_name, 'analyze_export_file');
    assert.deepEqual(toolRow.input, { path: '/tmp/export.json' });
  });
});

test('attachWmaWatchToAgent: agent_tool_end fires with (ctx, tool, result, details)', async () => {
  await withTempLogDir(async (logDir) => {
    const ee = new EventEmitter();
    ee.name = 'guardian_bot';
    attachWmaWatchToAgent(ee, { logDir, sessionId: 'sess-ah-tend' });

    const tool = { name: 'analyze_export_file' };
    const toolCall = { id: 'fc_abc', callId: 'call_xyz', name: 'analyze_export_file', arguments: '{}' };
    // AgentHooks signature: (context, tool, result, details) — 4 args, NO agent.
    ee.emit('agent_tool_end', /* ctx */ {}, tool, '{"findings":2}', { toolCall });

    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setTimeout(r, 50));

    const day = new Date().toISOString().slice(0, 10);
    const path = join(logDir, 'openai-agents', `${day}.ndjson`);
    const text = await readFile(path, 'utf8');
    const lines = text.trim().split('\n').map((l) => JSON.parse(l));
    const endRow = lines.find((l) => l.action_type === ACTION_TYPES.CUSTOM_TOOL_RESULT);
    assert.ok(endRow);
    assert.equal(endRow.agent_id, 'guardian_bot');
    assert.equal(endRow.output.text, '{"findings":2}');
  });
});

// ── Real fixtures: verify our normalizers handle the actual SDK shapes ─
//
// These fixtures were captured 2026-06-10 from a live @openai/agents
// ^0.2.0 run via the capture-fixtures.ts script in the sister test repo
// minedorfbm/openai-agent-sdk-test. They lock the contract between our
// normalizers and the SDK's actual runtime output.

const realFixturesDir = join(import.meta.dirname, 'fixtures', 'openai-agents-events');

async function loadFixture(name) {
  const text = await readFile(join(realFixturesDir, `${name}.json`), 'utf8');
  return JSON.parse(text);
}

test('real fixtures: agent_start args[1] is the agent — normalizer extracts name + tools', async () => {
  const fix = await loadFixture('agent_start');
  // AgentHooks signature: args = [context, agent, turnInput?]
  const [, agent] = fix.args;
  const evt = normalizeAgentStart({
    agent,
    turnInput: undefined,
    sessionId: 'sess-real',
    teamId: 'team-real',
  });
  assert.equal(evt.agent_id, 'Guardian Analyst (WGS)');
  assert.equal(evt.agent_name, 'Guardian Analyst (WGS)');
  assert.equal(evt.team_id, 'team-real');
  assert.equal(validateWMAAction(evt).valid, true);
});

test('real fixtures: agent_end args[1] is the output string (AgentHooks omits agent)', async () => {
  const fix = await loadFixture('agent_end');
  // AgentHooks: args = [context, output] — no agent
  const [, output] = fix.args;
  assert.equal(typeof output, 'string');
  assert.ok(output.startsWith('# Rapport Guardian'), 'real output is markdown');

  // Closure-captured agent supplies agent_id
  const closureAgent = { name: 'Guardian Analyst (WGS)' };
  const evt = normalizeAgentEnd({
    agent: closureAgent,
    output,
    sessionId: 'sess-real',
    teamId: 'team-real',
  });
  assert.equal(evt.agent_id, 'Guardian Analyst (WGS)');
  assert.equal(evt.output.kind, 'agent_end');
  assert.equal(evt.output.text, output);
});

test('real fixtures: agent_handoff args[1] is the toAgent (AgentHooks omits fromAgent)', async () => {
  const fix = await loadFixture('agent_handoff');
  // AgentHooks: args = [context, nextAgent] — only the "to" side
  const [, toAgent] = fix.args;
  assert.equal(toAgent.name, 'fixture_capture_escalation');

  // The fromAgent is the closure-captured one (triage_bot in real run)
  const fromAgent = { name: 'fixture_capture_triage', model: 'gpt-5' };
  const evt = normalizeAgentHandoff({
    fromAgent,
    toAgent,
    sessionId: 'sess-real',
    teamId: 'team-real',
  });
  assert.equal(evt.action_type, ACTION_TYPES.HANDOFF);
  assert.equal(evt.parent_agent_id, 'fixture_capture_triage');
  assert.equal(evt.agent_id, 'fixture_capture_escalation');
});

test('real fixtures: agent_tool_start args[1] is the tool object, args[2] is details.toolCall', async () => {
  const fix = await loadFixture('agent_tool_start');
  // AgentHooks: args = [context, tool, details] — no agent
  const [, tool, details] = fix.args;
  assert.equal(tool.name, 'analyze_export_file');
  assert.ok(details.toolCall);
  // Real SDK uses callId AND id (separate fields)
  assert.equal(details.toolCall.callId, 'call_6M6Yae797VWVSeFwyxlyHA6T');
  assert.equal(details.toolCall.name, 'analyze_export_file');
  assert.equal(typeof details.toolCall.arguments, 'string'); // SDK serializes as JSON string

  const closureAgent = { name: 'Guardian Analyst (WGS)' };
  const evt = normalizeToolStart({
    agent: closureAgent,
    tool,
    toolCall: details.toolCall,
    sessionId: 'sess-real',
    teamId: 'team-real',
  });
  assert.equal(evt.tool_name, 'analyze_export_file');
  assert.equal(evt.agent_id, 'Guardian Analyst (WGS)');
  // Our normalizer parses the JSON-string arguments into an object
  assert.deepEqual(evt.input, {
    path: '/home/runner/work/openai-agent-sdk-test/openai-agent-sdk-test/fixtures/example-export.json',
  });
});

test('real fixtures: agent_tool_end args[1]=tool, args[2]=result string, args[3]=details.toolCall', async () => {
  const fix = await loadFixture('agent_tool_end');
  // AgentHooks: args = [context, tool, result, details] — no agent
  const [, tool, result, details] = fix.args;
  assert.equal(tool.name, 'analyze_export_file');
  assert.equal(typeof result, 'string');
  // The tool returns JSON-serialized findings — confirm it parses
  const parsed = JSON.parse(result);
  assert.ok(parsed.summary);
  assert.ok(details.toolCall);

  const closureAgent = { name: 'Guardian Analyst (WGS)' };
  const evt = normalizeToolEnd({
    agent: closureAgent,
    tool,
    result,
    toolCall: details.toolCall,
    sessionId: 'sess-real',
    teamId: 'team-real',
  });
  assert.equal(evt.tool_name, 'analyze_export_file');
  // Normalizer wraps string results in {text}
  assert.equal(evt.output.text, result);
});

test('real fixtures: end-to-end emit of all 5 events on an EventEmitter mirrors AgentHooks', async () => {
  await withTempLogDir(async (logDir) => {
    const fixStart = await loadFixture('agent_start');
    const fixEnd = await loadFixture('agent_end');
    const fixToolStart = await loadFixture('agent_tool_start');
    const fixToolEnd = await loadFixture('agent_tool_end');
    const fixHandoff = await loadFixture('agent_handoff');

    const ee = new EventEmitter();
    ee.name = 'Guardian Analyst (WGS)';
    attachWmaWatchToAgent(ee, { logDir, sessionId: 'sess-real-e2e' });

    // Replay the captures with their EXACT argument layouts
    ee.emit('agent_start', ...fixStart.args);
    ee.emit('agent_tool_start', ...fixToolStart.args);
    ee.emit('agent_tool_end', ...fixToolEnd.args);
    ee.emit('agent_handoff', ...fixHandoff.args);
    ee.emit('agent_end', ...fixEnd.args);

    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setTimeout(r, 100));

    const day = new Date().toISOString().slice(0, 10);
    const path = join(logDir, 'openai-agents', `${day}.ndjson`);
    const text = await readFile(path, 'utf8');
    const lines = text.trim().split('\n').map((l) => JSON.parse(l));

    // All 5 distinct action_types should be represented
    const seenTypes = new Set(lines.map((l) => l.action_type));
    assert.ok(seenTypes.has(ACTION_TYPES.MESSAGE), 'agent_start + agent_end → MESSAGE');
    assert.ok(seenTypes.has(ACTION_TYPES.HANDOFF), 'agent_handoff → HANDOFF');
    assert.ok(seenTypes.has(ACTION_TYPES.CUSTOM_TOOL_USE), 'agent_tool_start');
    assert.ok(seenTypes.has(ACTION_TYPES.CUSTOM_TOOL_RESULT), 'agent_tool_end');

    // Single team_id across the run
    const teamIds = new Set(lines.map((l) => l.team_id).filter(Boolean));
    assert.equal(teamIds.size, 1, 'single team_id across the simulated run');
  });
});
