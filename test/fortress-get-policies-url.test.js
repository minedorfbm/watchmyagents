// v1.4.9 — get-policies URL carries `provider` so a provider-aware Fortress can
// scope by (provider, native_agent_id). Without it, an OpenAI agent (id not in
// the `agent_…` shape) can't pull policies → guardrail fails closed → blocks
// everything. (Fixes the SDK half of the coupled get-policies finding.)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildGetPoliciesUrl } from '../src/shield/sources/fortress.js';

const BASE = 'https://x.supabase.co/functions/v1';

test('get-policies URL includes provider + agent_id for an OpenAI agent', () => {
  const url = buildGetPoliciesUrl(BASE, { anthropicAgentId: 'support_bot', provider: 'openai-agents' });
  assert.match(url, /\/get-policies\?/);
  assert.match(url, /agent_id=support_bot/);
  assert.match(url, /provider=openai-agents/);
});

test('get-policies URL defaults provider to anthropic-managed (back-compat)', () => {
  const url = buildGetPoliciesUrl(BASE, { anthropicAgentId: 'agent_01XaN' });
  assert.match(url, /agent_id=agent_01XaN/);
  assert.match(url, /provider=anthropic-managed/);
});

test('get-policies URL encodes the params + always carries provider', () => {
  const url = buildGetPoliciesUrl(BASE, { anthropicAgentId: 'a b', provider: 'openai-agents' });
  assert.match(url, /agent_id=a%20b/);
  assert.match(url, /provider=openai-agents/);
  // no agent id → still sends provider
  const noId = buildGetPoliciesUrl(BASE, { provider: 'openai-agents' });
  assert.match(noId, /provider=openai-agents/);
  assert.doesNotMatch(noId, /agent_id=/);
});
