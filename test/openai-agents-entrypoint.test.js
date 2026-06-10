// Stable entrypoint tests — v1.4 Codex #1 + #2 + #7 + #10.
//
// Locks the public surface exposed by `watchmyagents/openai-agents`:
//   - openaiAgents({ ... }) factory
//   - explicit mode 'observe' vs 'enforce' with fail-loud refusal in
//     enforce when no policy is configured
//   - wma.shield() returns the OpenAI guardrail
//   - wma.watch(target) auto-detects Runner vs Agent
//   - back-compat re-exports for advanced consumers

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';

import {
  openaiAgents,
  wmaToolInputGuardrail,
  attachWmaWatch,
  attachWmaWatchToAgent,
  adapterMeta,
} from '../src/openai-agents.js';

const NOOP_RULESET = { policies: [], default: { action: 'allow' } };

// ── Factory + mode validation (Codex #2) ────────────────────────────

test('openaiAgents: enforce mode requires a policy source', () => {
  assert.throws(
    () => openaiAgents({ mode: 'enforce' }),
    /requires policiesPath or ruleset/,
  );
});

test('openaiAgents: enforce mode accepts ruleset and constructs OK', () => {
  const wma = openaiAgents({ mode: 'enforce', ruleset: NOOP_RULESET, logDir: '/tmp/wma-test' });
  assert.equal(wma.mode, 'enforce');
});

test('openaiAgents: observe mode constructs without a policy source', () => {
  const wma = openaiAgents({ mode: 'observe', logDir: '/tmp/wma-test' });
  assert.equal(wma.mode, 'observe');
});

test('openaiAgents: defaults to enforce mode (requires policy)', () => {
  // Default mode is `enforce`; calling without policy must throw.
  assert.throws(() => openaiAgents({}), /requires policiesPath or ruleset/);
});

test('openaiAgents: invalid mode throws TypeError', () => {
  assert.throws(
    () => openaiAgents({ mode: 'verybad' }),
    /options.mode must be 'observe' or 'enforce'/,
  );
});

test('openaiAgents: observe mode forbids shield() — explicit failure beats silent allow-all', () => {
  const wma = openaiAgents({ mode: 'observe', logDir: '/tmp/wma-test' });
  assert.throws(() => wma.shield(), /Observe mode does not produce Shield enforcement/);
});

// ── shield() and watch() functionality ───────────────────────────────

test('openaiAgents: shield() returns a guardrail shape compatible with @openai/agents', () => {
  const wma = openaiAgents({ ruleset: NOOP_RULESET, logDir: '/tmp/wma-test' });
  const g = wma.shield();
  assert.equal(g.type, 'tool_input');
  assert.equal(g.name, 'watchmyagents-shield');
  assert.equal(typeof g.run, 'function');
});

test('openaiAgents: watch() returns a detach function', () => {
  const wma = openaiAgents({ ruleset: NOOP_RULESET, logDir: '/tmp/wma-test' });
  // Use an Agent-shaped emitter (has .name + .tools[]).
  const ee = new EventEmitter();
  ee.name = 'support_bot';
  ee.tools = [];
  const detach = wma.watch(ee);
  assert.equal(typeof detach, 'function');
  detach();
});

// ── Auto-detection (Codex #7) ────────────────────────────────────────

test('autoAttach: Runner detection — runner has .run() and no .tools/.name', () => {
  const wma = openaiAgents({ ruleset: NOOP_RULESET, logDir: '/tmp/wma-test' });
  // Build a Runner-shaped EventEmitter.
  const runner = new EventEmitter();
  runner.run = async () => null; // Runner has .run as a method
  // No .tools, no .name on the runner side.
  const detach = wma.watch(runner);
  // Runner uses RunHooks → registered listeners on 5 events.
  assert.equal(runner.listenerCount('agent_start'), 1);
  assert.equal(runner.listenerCount('agent_tool_start'), 1);
  detach();
});

test('autoAttach: Agent detection — agent has .name + .tools[]', () => {
  const wma = openaiAgents({ ruleset: NOOP_RULESET, logDir: '/tmp/wma-test' });
  const agent = new EventEmitter();
  agent.name = 'support_bot';
  agent.tools = [{ name: 'echo' }];
  const detach = wma.watch(agent);
  // AgentHooks variant → same 5 events, but the agent is closure-captured.
  assert.equal(agent.listenerCount('agent_handoff'), 1);
  detach();
});

test('autoAttach: ambiguous target with BOTH .run() and .tools throws clearly', () => {
  const wma = openaiAgents({ ruleset: NOOP_RULESET, logDir: '/tmp/wma-test' });
  const weird = new EventEmitter();
  weird.run = async () => null;
  weird.name = 'looks_like_agent';
  weird.tools = []; // and .tools — ambiguous
  assert.throws(() => wma.watch(weird), /looks like both Agent and Runner/);
});

test('autoAttach: target without .on() throws TypeError', () => {
  const wma = openaiAgents({ ruleset: NOOP_RULESET, logDir: '/tmp/wma-test' });
  assert.throws(() => wma.watch({}), /target must expose \.on/);
  assert.throws(() => wma.watch(null), /target must expose \.on/);
});

// ── Re-exports (escape hatch for advanced consumers) ─────────────────

test('openai-agents: re-exports the lower-level functions for advanced consumers', () => {
  assert.equal(typeof wmaToolInputGuardrail, 'function');
  assert.equal(typeof attachWmaWatch, 'function');
  assert.equal(typeof attachWmaWatchToAgent, 'function');
  assert.equal(typeof adapterMeta, 'object');
  assert.equal(adapterMeta.provider, 'openai-agents');
});

// ── Metadata surface ─────────────────────────────────────────────────

test('openaiAgents: exposes adapter metadata + configured mode', () => {
  const wma = openaiAgents({ ruleset: NOOP_RULESET, logDir: '/tmp/wma-test', mode: 'enforce' });
  assert.equal(wma.meta.provider, 'openai-agents');
  assert.equal(wma.meta.peerPackage, '@openai/agents');
  assert.equal(wma.mode, 'enforce');
});

test('openaiAgents: returned object is frozen — no mutation', () => {
  const wma = openaiAgents({ ruleset: NOOP_RULESET, logDir: '/tmp/wma-test' });
  assert.throws(() => { wma.mode = 'mutated'; }, TypeError);
});
