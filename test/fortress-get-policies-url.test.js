// v1.4.9 — get-policies URL carries `provider` so a provider-aware Fortress can
// scope by (provider, native_agent_id). Without it, an OpenAI agent (id not in
// the `agent_…` shape) can't pull policies → guardrail fails closed → blocks
// everything. (Fixes the SDK half of the coupled get-policies finding.)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildGetPoliciesUrl } from '../src/shield/sources/fortress.js';

const BASE = 'https://x.supabase.co/functions/v1';

test('v1.4.10: OpenAI agent id goes under native_agent_id (NOT agent_id)', () => {
  // The contract with Fortress: useLegacyLookup = (native absent && agent_id
  // present) → anthropic_agent_id lookup. Sending an OpenAI id as agent_id would
  // trigger that legacy lookup → not found → empty policies → silent fail-open.
  const url = buildGetPoliciesUrl(BASE, { anthropicAgentId: 'support_bot', provider: 'openai-agents' });
  assert.match(url, /\/get-policies\?/);
  assert.match(url, /native_agent_id=support_bot/);
  assert.doesNotMatch(url, /(?<![a-z_])agent_id=/, 'must NOT send the legacy agent_id for OpenAI');
  assert.match(url, /provider=openai-agents/);
});

test('v1.4.10: Anthropic agent id stays under agent_id (legacy, resolves all incl. un-backfilled)', () => {
  const url = buildGetPoliciesUrl(BASE, { anthropicAgentId: 'agent_01XaN' });
  assert.match(url, /(?<![a-z_])agent_id=agent_01XaN/);
  assert.doesNotMatch(url, /native_agent_id=/, 'Anthropic uses the legacy param, not native');
  assert.match(url, /provider=anthropic-managed/);
});

test('get-policies URL encodes the id + always carries provider', () => {
  const url = buildGetPoliciesUrl(BASE, { anthropicAgentId: 'a b', provider: 'openai-agents' });
  assert.match(url, /native_agent_id=a%20b/);
  assert.match(url, /provider=openai-agents/);
  // no agent id → still sends provider
  const noId = buildGetPoliciesUrl(BASE, { provider: 'openai-agents' });
  assert.match(noId, /provider=openai-agents/);
  assert.doesNotMatch(noId, /agent_id=/);
});
