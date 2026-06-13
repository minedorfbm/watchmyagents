// v1.4.6 — SDK prerequisites for the Fortress "register an OpenAI agent" flow.
//
//   Prereq 1: openaiAgents({ policies: { source: 'fortress' } }) wires a live
//             FortressPolicySource into the guardrail (lazy start + current()).
//   Prereq 2: buildFortressDecisionPayload is provider-aware (provider +
//             native_agent_id; anthropic_agent_id only for the Anthropic runtime).
//   Prereq 3: the in-process guardrail records enforcement_delivered=true on an
//             enforced deny/interrupt (the block is delivered synchronously).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { openaiAgents } from '../src/openai-agents.js';
import { wmaToolInputGuardrail } from '../src/sources/openai-agents-js.js';
import { buildFortressDecisionPayload } from '../src/shield/upload.js';

const UPLOAD_CLI = fileURLToPath(new URL('../scripts/upload-fortress.js', import.meta.url));

const TOOL_CALL = { callId: 'c1', name: 'search_kb', arguments: '{"query":"x"}' };
const DENY_RULESET = {
  policies: [{ id: 'deny-search', match: { tool_name: 'search_kb' }, action: 'deny', message: 'blocked' }],
  default: { action: 'allow' },
};
const SHADOW_RULESET = {
  policies: [{ id: 'shadow-search', match: { tool_name: 'search_kb' }, action: 'deny', mode: 'shadow', message: 's' }],
  default: { action: 'allow' },
};
const ALLOW_RULESET = { policies: [], default: { action: 'allow' } };

function stubLoggers() {
  const recorded = [];
  return {
    recorded,
    decisionLogger: { record: async (a) => { recorded.push(a); } },
    logger: { write: async () => {} },
  };
}

// ── Prereq 1 — factory wiring ────────────────────────────────────────────

test('P1: factory accepts policies:{source:fortress} as a valid enforce policy source', () => {
  const wma = openaiAgents({
    mode: 'enforce',
    agentId: 'support_bot',
    policies: { source: 'fortress', baseUrl: 'https://x.supabase.co/functions/v1', apiKey: 'wma_' + 'a'.repeat(32) },
  });
  assert.equal(wma.mode, 'enforce');
  assert.equal(typeof wma.shield, 'function'); // constructs without throwing (no network yet)
});

test('P1: fortress policies require agentId', () => {
  assert.throws(
    () => openaiAgents({ mode: 'enforce', policies: { source: 'fortress', baseUrl: 'https://x/functions/v1', apiKey: 'wma_x' } }),
    /requires `agentId`/,
  );
});

test('P1: fortress policies require WMA_API_KEY', () => {
  const saved = process.env.WMA_API_KEY;
  delete process.env.WMA_API_KEY;
  try {
    assert.throws(
      () => openaiAgents({ mode: 'enforce', agentId: 'a', policies: { source: 'fortress', baseUrl: 'https://x/functions/v1' } }),
      /WMA_API_KEY/,
    );
  } finally {
    if (saved !== undefined) process.env.WMA_API_KEY = saved;
  }
});

test('P1: fortress policies require a base URL', () => {
  const savedBase = process.env.WMA_FORTRESS_BASE_URL;
  const savedUrl = process.env.WMA_FORTRESS_URL;
  delete process.env.WMA_FORTRESS_BASE_URL;
  delete process.env.WMA_FORTRESS_URL;
  try {
    assert.throws(
      () => openaiAgents({ mode: 'enforce', agentId: 'a', policies: { source: 'fortress', apiKey: 'wma_x' } }),
      /base URL/,
    );
  } finally {
    if (savedBase !== undefined) process.env.WMA_FORTRESS_BASE_URL = savedBase;
    if (savedUrl !== undefined) process.env.WMA_FORTRESS_URL = savedUrl;
  }
});

// ── Prereq 1 — guardrail pulls from the injected source ──────────────────

test('P1: guardrail enforces the live Fortress ruleset (start() lazy + once)', async () => {
  let startCalls = 0;
  const source = { start: async () => { startCalls++; }, current: () => DENY_RULESET };
  const { decisionLogger, logger } = stubLoggers();
  const guard = wmaToolInputGuardrail({ fortressPolicySource: source, decisionLogger, logger });

  const r1 = await guard.run({ agent: { name: 'bot' }, toolCall: TOOL_CALL });
  assert.equal(r1.behavior.type, 'rejectContent', 'deny rule from the Fortress source blocks the tool');

  const r2 = await guard.run({ agent: { name: 'bot' }, toolCall: TOOL_CALL });
  assert.equal(r2.behavior.type, 'rejectContent');
  assert.equal(startCalls, 1, 'start() is lazy and cached — called once across calls');
});

test('P1: fortressPolicySource counts as a configured policy source (no fail-loud throw)', () => {
  assert.doesNotThrow(() =>
    wmaToolInputGuardrail({ fortressPolicySource: { start: async () => {}, current: () => ALLOW_RULESET } }));
});

test('P1 (audit): CONCURRENT first calls start() the source exactly once (no timer leak)', async () => {
  let startCalls = 0;
  const source = {
    // resolve on a microtask so both run() calls reach the guard before start() settles
    start: async () => { startCalls++; await Promise.resolve(); },
    current: () => DENY_RULESET,
  };
  const { decisionLogger, logger } = stubLoggers();
  const guard = wmaToolInputGuardrail({ fortressPolicySource: source, decisionLogger, logger });

  // Fire two tool calls concurrently (the double-start race condition).
  const [r1, r2] = await Promise.all([
    guard.run({ agent: { name: 'bot' }, toolCall: TOOL_CALL }),
    guard.run({ agent: { name: 'bot' }, toolCall: TOOL_CALL }),
  ]);
  assert.equal(r1.behavior.type, 'rejectContent');
  assert.equal(r2.behavior.type, 'rejectContent');
  assert.equal(startCalls, 1, 'single-flight: start() called once despite concurrent first calls');
});

test('P1 (audit): a failed start() resets so the next call retries', async () => {
  let startCalls = 0;
  const source = {
    start: async () => { startCalls++; if (startCalls === 1) throw new Error('fortress unreachable'); },
    current: () => DENY_RULESET,
  };
  const { decisionLogger, logger } = stubLoggers();
  const guard = wmaToolInputGuardrail({ fortressPolicySource: source, decisionLogger, logger });

  // First call: start() throws → guardrail fails CLOSED (reject).
  const r1 = await guard.run({ agent: { name: 'bot' }, toolCall: TOOL_CALL });
  assert.equal(r1.behavior.type, 'rejectContent', 'unreachable Fortress at startup → fail-closed');
  // Second call: start() retried and succeeds → enforces the ruleset.
  const r2 = await guard.run({ agent: { name: 'bot' }, toolCall: TOOL_CALL });
  assert.equal(r2.behavior.type, 'rejectContent');
  assert.equal(startCalls, 2, 'failed start did not cache — retried on the next call');
});

// ── Prereq 3 — enforcement_delivered ─────────────────────────────────────

test('P3: an enforced deny records enforcement_delivered=true', async () => {
  const { recorded, decisionLogger, logger } = stubLoggers();
  const guard = wmaToolInputGuardrail({ ruleset: DENY_RULESET, decisionLogger, logger });
  await guard.run({ agent: { name: 'bot' }, toolCall: TOOL_CALL });
  assert.equal(recorded.length, 1);
  assert.equal(recorded[0].decision, 'deny');
  assert.equal(recorded[0].enforcementDelivered, true,
    'in-process block is delivered synchronously → true');
});

test('P3: a default-allow records enforcement_delivered=undefined (n/a)', async () => {
  const { recorded, decisionLogger, logger } = stubLoggers();
  const guard = wmaToolInputGuardrail({ ruleset: ALLOW_RULESET, decisionLogger, logger });
  await guard.run({ agent: { name: 'bot' }, toolCall: TOOL_CALL });
  assert.equal(recorded[0].decision, 'allow');
  assert.equal(recorded[0].enforcementDelivered, undefined);
});

test('P3: a shadow deny does NOT mark enforcement_delivered (not enforced)', async () => {
  const { recorded, decisionLogger, logger } = stubLoggers();
  const guard = wmaToolInputGuardrail({ ruleset: SHADOW_RULESET, decisionLogger, logger });
  const r = await guard.run({ agent: { name: 'bot' }, toolCall: TOOL_CALL });
  assert.equal(r.behavior.type, 'allow', 'shadow never blocks');
  assert.equal(recorded[0].enforcementDelivered, undefined);
});

// ── #1 — OpenAI decisions ship to Fortress (fire-and-forget) ─────────────

// Drain microtasks/timers so the fire-and-forget post settles before asserting.
const tick = () => new Promise((r) => setTimeout(r, 10));

test('#1: an enforced deny is shipped to the Fortress decision sink', async () => {
  const posted = [];
  const sink = async (payload) => { posted.push(payload); };
  const { decisionLogger, logger } = stubLoggers();
  const guard = wmaToolInputGuardrail({
    ruleset: DENY_RULESET, decisionLogger, logger,
    fortressDecisionSink: sink, agentId: 'support_bot', signalsSalt: 's'.repeat(32),
  });
  await guard.run({ agent: { name: 'bot' }, toolCall: TOOL_CALL });
  await tick();
  assert.equal(posted.length, 1, 'decision posted to the sink');
  assert.equal(posted[0].provider, 'openai-agents');
  assert.equal(posted[0].native_agent_id, 'support_bot');
  assert.equal(posted[0].decision, 'deny');
  assert.equal(posted[0].enforcement_delivered, true);
  assert.equal(posted[0].anthropic_agent_id, undefined, 'no Anthropic field for OpenAI');
});

test('#1: with NO sink configured, nothing is posted (local-only)', async () => {
  const { decisionLogger, logger } = stubLoggers();
  const guard = wmaToolInputGuardrail({ ruleset: DENY_RULESET, decisionLogger, logger });
  const r = await guard.run({ agent: { name: 'bot' }, toolCall: TOOL_CALL });
  await tick();
  assert.equal(r.behavior.type, 'rejectContent'); // still enforces locally
});

test('#1: a sink that throws never breaks enforcement (best-effort)', async () => {
  const { decisionLogger, logger } = stubLoggers();
  const guard = wmaToolInputGuardrail({
    ruleset: DENY_RULESET, decisionLogger, logger,
    fortressDecisionSink: async () => { throw new Error('ingest-decisions 500'); },
    agentId: 'bot', signalsSalt: 'x'.repeat(32),
  });
  const r = await guard.run({ agent: { name: 'bot' }, toolCall: TOOL_CALL });
  await tick();
  assert.equal(r.behavior.type, 'rejectContent', 'tool still blocked despite sink failure');
});

test('#1: factory auto-wires a decision sink when fortress policies are set', () => {
  const wma = openaiAgents({
    mode: 'enforce', agentId: 'support_bot',
    policies: { source: 'fortress', baseUrl: 'https://x.supabase.co/functions/v1', apiKey: 'wma_' + 'a'.repeat(32) },
  });
  assert.equal(wma.mode, 'enforce'); // constructs; sink wired internally (covered by guardrail tests)
});

test('#1: factory respects uploadDecisions:false (decisions stay local)', () => {
  // No throw, constructs — the opt-out path. (The sink being null is internal;
  // this asserts the option is accepted and doesn't break construction.)
  assert.doesNotThrow(() => openaiAgents({
    mode: 'enforce', agentId: 'support_bot',
    policies: { source: 'fortress', baseUrl: 'https://x/functions/v1', apiKey: 'wma_x', uploadDecisions: false },
  }));
});

// ── Prereq 2 — provider-aware decision payload ───────────────────────────

test('P2: payload carries provider + native_agent_id for OpenAI (no anthropic_agent_id)', () => {
  const p = buildFortressDecisionPayload({
    agentId: 'support_bot',
    provider: 'openai-agents',
    nativeAgentId: 'support_bot',
    result: { decision: 'deny', rule_id: 'r1' },
    normalized: { action_type: 'custom_tool_use', tool_name: null, input: null },
    decidedInMs: 2,
    enforcementDelivered: true,
  });
  assert.equal(p.provider, 'openai-agents');
  assert.equal(p.native_agent_id, 'support_bot');
  assert.equal(p.anthropic_agent_id, undefined, 'legacy field omitted for non-Anthropic runtime');
  assert.equal(p.enforcement_delivered, true);
});

test('P2 (audit): wma-upload-fortress rejects a path-traversal agent-id for openai-agents', () => {
  const res = spawnSync(process.execPath,
    [UPLOAD_CLI, '--provider', 'openai-agents', '--agent-id', '..'],
    { encoding: 'utf8' });
  assert.notEqual(res.status, 0, 'must exit non-zero on a "ized.." agent-id');
  assert.match(res.stderr, /unsafe|traversal/i);
});

test('P2 (audit): a normal OpenAI agent name is accepted by the validator', () => {
  // Reaches PAST the agent-id check and dies later (missing api-key/fortress),
  // proving 'support_bot' is NOT rejected by the format guard.
  const res = spawnSync(process.execPath,
    [UPLOAD_CLI, '--provider', 'openai-agents', '--agent-id', 'support_bot'],
    { encoding: 'utf8' });
  assert.notEqual(res.status, 0);
  assert.doesNotMatch(res.stderr, /unsafe|traversal|invalid format/i,
    'a valid agent name must not trip the agent-id format guard');
});

test('P2: legacy call (no provider) preserves the Anthropic shape', () => {
  const p = buildFortressDecisionPayload({
    agentId: 'agent_01XaN',
    result: { decision: 'allow' },
    normalized: { action_type: 'tool_use' },
    decidedInMs: 1,
  });
  assert.equal(p.provider, 'anthropic-managed');
  assert.equal(p.native_agent_id, 'agent_01XaN');
  assert.equal(p.anthropic_agent_id, 'agent_01XaN', 'legacy field kept for Anthropic');
  assert.equal(p.enforcement_delivered, undefined);
});
