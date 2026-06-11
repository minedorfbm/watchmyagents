// v1.4.2 F-38 (P0 audit) — action_type tool-family equivalence.
//
// THE BUG (confirmed against source pre-fix):
//   Adapters emit three tool-invocation action_types — `tool_use` (provider
//   built-ins), `mcp_tool_use` (MCP servers), `custom_tool_use` (custom).
//   The matcher did EXACT equality, so a deny/allowlist policy keyed on the
//   generic `tool_use` silently MISSED mcp/custom tool calls. On the OpenAI
//   adapter (which emits custom_tool_use for EVERY tool) a tool_use-keyed
//   rule matched nothing at all. On the Anthropic adapter built-ins matched
//   but mcp/custom slipped through — passing tests while leaving a hole.
//
// THE FIX:
//   matchesPolicy expands a GENERIC `tool_use` target to the whole family.
//   A SPECIFIC member (mcp_tool_use / custom_tool_use) stays exact.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { matchesPolicy, evaluate } from '../src/shield/policy.js';
import { TOOL_USE_FAMILY } from '../src/sources/contract.js';

const denyRule = (match) => ({ id: 'r', action: 'deny', match });

// ── core: generic tool_use catches the whole family ──────────────────────

test('F-38: literal action_type "tool_use" matches all three family members', () => {
  const rule = denyRule({ action_type: 'tool_use' });
  for (const at of ['tool_use', 'mcp_tool_use', 'custom_tool_use']) {
    assert.equal(matchesPolicy({ action_type: at }, rule), true,
      `generic tool_use should match ${at}`);
  }
});

test('F-38: the family constant is exactly the three tool-invocation types', () => {
  assert.deepEqual([...TOOL_USE_FAMILY].sort(),
    ['custom_tool_use', 'mcp_tool_use', 'tool_use']);
});

test('F-38: generic tool_use does NOT match non-tool action types', () => {
  const rule = denyRule({ action_type: 'tool_use' });
  for (const at of ['llm_call', 'message', 'thinking', 'user_message', 'custom_tool_result']) {
    assert.equal(matchesPolicy({ action_type: at }, rule), false,
      `tool_use should not match ${at}`);
  }
});

// ── specific members stay exact (escape hatch preserved) ──────────────────

test('F-38: a SPECIFIC member (mcp_tool_use) stays an exact match — no reverse expansion', () => {
  const rule = denyRule({ action_type: 'mcp_tool_use' });
  assert.equal(matchesPolicy({ action_type: 'mcp_tool_use' }, rule), true);
  // A built-in tool_use must NOT match a rule that deliberately targets MCP only.
  assert.equal(matchesPolicy({ action_type: 'tool_use' }, rule), false);
  assert.equal(matchesPolicy({ action_type: 'custom_tool_use' }, rule), false);
});

// ── in / not_in lists expand too ──────────────────────────────────────────

test('F-38: { in: ["tool_use"] } expands to the family', () => {
  const rule = denyRule({ action_type: { in: ['tool_use'] } });
  assert.equal(matchesPolicy({ action_type: 'mcp_tool_use' }, rule), true);
  assert.equal(matchesPolicy({ action_type: 'custom_tool_use' }, rule), true);
  assert.equal(matchesPolicy({ action_type: 'llm_call' }, rule), false);
});

test('F-38: { not_in: ["tool_use"] } treats the whole family as "is a tool use"', () => {
  // "action_type NOT a tool use" must be false for every family member.
  const rule = denyRule({ action_type: { not_in: ['tool_use'] } });
  assert.equal(matchesPolicy({ action_type: 'tool_use' }, rule), false);
  assert.equal(matchesPolicy({ action_type: 'mcp_tool_use' }, rule), false);
  assert.equal(matchesPolicy({ action_type: 'custom_tool_use' }, rule), false);
  // A non-tool action IS "not a tool use".
  assert.equal(matchesPolicy({ action_type: 'llm_call' }, rule), true);
});

// ── the real-world regression: the Deep Researcher containment rule ───────

test('F-38: Deep Researcher p1 containment rule now catches an MCP tool call', () => {
  // p1: "only web_search/web_fetch allowed, anything else = deny".
  const p1 = denyRule({
    action_type: 'tool_use',
    tool_name: { not_in: ['web_search', 'web_fetch'] },
  });
  const ruleset = { policies: [p1], default: { action: 'allow' } };

  // An MCP tool the agent should NOT be using — pre-fix this fell through
  // to default-allow because action_type was mcp_tool_use, not tool_use.
  const mcpExfil = { action_type: 'mcp_tool_use', tool_name: 'http_post' };
  assert.equal(evaluate(mcpExfil, ruleset).decision, 'deny',
    'MCP tool outside baseline must now be denied by the containment rule');

  // A custom tool, likewise.
  const customExfil = { action_type: 'custom_tool_use', tool_name: 'send_email' };
  assert.equal(evaluate(customExfil, ruleset).decision, 'deny');

  // The allowed built-ins still pass (no false positive).
  assert.equal(evaluate({ action_type: 'tool_use', tool_name: 'web_search' }, ruleset).decision, 'allow');
  assert.equal(evaluate({ action_type: 'tool_use', tool_name: 'web_fetch' }, ruleset).decision, 'allow');

  // A non-allowlisted BUILT-IN is still denied (the case that worked pre-fix).
  assert.equal(evaluate({ action_type: 'tool_use', tool_name: 'bash' }, ruleset).decision, 'deny');
});

test('F-38: a tool_name deny rule keyed with action_type:tool_use catches a custom tool of that name', () => {
  // mitre-style: deny bash regardless of which surface it came through.
  const rule = denyRule({ action_type: 'tool_use', tool_name: 'bash' });
  const ruleset = { policies: [rule], default: { action: 'allow' } };
  assert.equal(evaluate({ action_type: 'custom_tool_use', tool_name: 'bash' }, ruleset).decision, 'deny');
  assert.equal(evaluate({ action_type: 'mcp_tool_use', tool_name: 'bash' }, ruleset).decision, 'deny');
});
