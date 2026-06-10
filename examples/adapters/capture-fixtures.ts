// Fixture capture script — runs a real @openai/agents flow and writes
// each lifecycle event's raw arguments to test/fixtures/openai-agents-events/.
//
// Goal: replace the synthetic fixtures in test/sources-openai-agents-js.test.js
// with REAL captures from a live SDK version, so the adapter is verified
// against the actual shape the SDK emits — not against our reading of the
// source code.
//
// Run:
//   npm install @openai/agents zod
//   export OPENAI_API_KEY=sk-proj-...
//   npx tsx examples/adapters/capture-fixtures.ts
//
// Output: one JSON per event type at
//   test/fixtures/openai-agents-events/agent_start.json
//   test/fixtures/openai-agents-events/agent_end.json
//   test/fixtures/openai-agents-events/agent_handoff.json
//   test/fixtures/openai-agents-events/agent_tool_start.json
//   test/fixtures/openai-agents-events/agent_tool_end.json
//
// Each file contains the raw listener arguments + meta (SDK version,
// Node version, capture timestamp).

import { Agent, Runner, handoff, tool } from '@openai/agents';
import { z } from 'zod';
import { writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const FIXTURES_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  'test',
  'fixtures',
  'openai-agents-events',
);

// Capture meta — Node + SDK versions are baked into each fixture so future
// readers know what runtime emitted these shapes.
async function getSdkVersion(): Promise<string> {
  try {
    const pkg = await import('@openai/agents/package.json', { assert: { type: 'json' } });
    return (pkg as any).default?.version || (pkg as any).version || 'unknown';
  } catch {
    return 'unknown';
  }
}

// One capture per event type. We overwrite if the file already exists so
// re-running the script always reflects the LATEST SDK version observed.
const captured: Record<string, boolean> = {};

async function saveFixture(eventName: string, rawArgs: unknown[], sdkVersion: string) {
  if (captured[eventName]) return; // first occurrence wins — keep deterministic
  captured[eventName] = true;
  const payload = {
    event: eventName,
    args: rawArgs.map((a) => safeSerialize(a)),
    meta: {
      sdk_version: sdkVersion,
      node_version: process.version,
      captured_at: new Date().toISOString(),
      capture_script: 'examples/adapters/capture-fixtures.ts',
    },
  };
  const path = join(FIXTURES_DIR, `${eventName}.json`);
  await writeFile(path, JSON.stringify(payload, null, 2) + '\n', 'utf8');
  console.log(`[capture] wrote ${eventName}.json (${rawArgs.length} args)`);
}

// JSON-serialize while gracefully handling cyclic refs + class instances.
function safeSerialize(v: unknown): unknown {
  if (v === null || v === undefined) return v;
  if (typeof v === 'function') return `[function ${v.name || '<anon>'}]`;
  if (typeof v !== 'object') return v;
  try {
    return JSON.parse(JSON.stringify(v, (_k, val) => {
      if (typeof val === 'function') return `[function ${val.name || '<anon>'}]`;
      if (val instanceof Error) return { name: val.name, message: val.message };
      return val;
    }));
  } catch {
    return `[unserializable ${Object.prototype.toString.call(v)}]`;
  }
}

// Two tools so we can capture tool_start + tool_end with realistic data.
const searchKB = tool({
  name: 'search_kb',
  description: 'Search the support knowledge base.',
  parameters: z.object({ query: z.string() }),
  async execute({ query }: { query: string }) {
    return `Found 3 articles for "${query}".`;
  },
});

const escalate = tool({
  name: 'escalate',
  description: 'Escalate this ticket to a human supervisor.',
  parameters: z.object({ reason: z.string() }),
  async execute({ reason }: { reason: string }) {
    return `Escalated. Reason: ${reason}`;
  },
});

// Two agents wired by handoff so we capture the handoff event.
const escalationBot = new Agent({
  name: 'escalation_bot',
  instructions: 'You handle escalated support tickets that the first-tier bot cannot resolve. Call escalate() with the reason.',
  model: 'gpt-5',
  tools: [escalate],
});

const supportBot = new Agent({
  name: 'support_bot',
  instructions: [
    'You are tier-1 support. Try search_kb first.',
    'If the customer is angry, hand off to escalation_bot.',
  ].join('\n'),
  model: 'gpt-5',
  tools: [searchKB],
  handoffs: [handoff(escalationBot)],
});

async function main() {
  await mkdir(FIXTURES_DIR, { recursive: true });
  const sdkVersion = await getSdkVersion();
  console.log(`[capture] target dir: ${FIXTURES_DIR}`);
  console.log(`[capture] @openai/agents version: ${sdkVersion}`);
  console.log(`[capture] Node version: ${process.version}`);

  const runner = new Runner();

  // Attach raw listeners to all 5 lifecycle events. Each handler:
  //   1. saves the first occurrence to its dedicated fixture file
  //   2. logs a short note to stdout
  // We do NOT attach the WMA guardrail here — this script captures the
  // RAW SDK shapes, not the WMA-normalized ones.
  runner.on('agent_start', async (...args) => {
    await saveFixture('agent_start', args, sdkVersion);
    console.log('[capture]   agent_start fired');
  });
  runner.on('agent_end', async (...args) => {
    await saveFixture('agent_end', args, sdkVersion);
    console.log('[capture]   agent_end fired');
  });
  runner.on('agent_handoff', async (...args) => {
    await saveFixture('agent_handoff', args, sdkVersion);
    console.log('[capture]   agent_handoff fired');
  });
  runner.on('agent_tool_start', async (...args) => {
    await saveFixture('agent_tool_start', args, sdkVersion);
    console.log('[capture]   agent_tool_start fired');
  });
  runner.on('agent_tool_end', async (...args) => {
    await saveFixture('agent_tool_end', args, sdkVersion);
    console.log('[capture]   agent_tool_end fired');
  });

  console.log('\n[capture] running support flow that should fire all 5 events…');
  // The prompt is designed to (a) get search_kb to fire and (b) be angry
  // enough that the bot hands off to escalation_bot, which then fires
  // escalate(). That covers all 5 lifecycle events in a single run.
  const result = await runner.run(
    supportBot,
    'Your KB has been useless for 30 minutes. I demand to speak to a supervisor. ' +
    'My account number is X-9999. This is my third ticket about the same issue.',
  );

  console.log('\n[capture] final output:', result.finalOutput);
  console.log('\n[capture] DONE. Files written:');
  for (const evt of ['agent_start', 'agent_end', 'agent_handoff', 'agent_tool_start', 'agent_tool_end']) {
    console.log(`  - ${join(FIXTURES_DIR, `${evt}.json`)} ${captured[evt] ? '✓' : '✗ MISSING'}`);
  }

  const missing = ['agent_start', 'agent_end', 'agent_handoff', 'agent_tool_start', 'agent_tool_end']
    .filter((e) => !captured[e]);
  if (missing.length > 0) {
    console.warn(`\n[capture] WARNING: ${missing.length} event(s) didn't fire: ${missing.join(', ')}`);
    console.warn('[capture] You may need to adjust the prompt to provoke those events.');
    console.warn('[capture] Most common cause: the model didn\'t choose to hand off → re-run with a more escalation-heavy prompt.');
    process.exit(1);
  }

  console.log('\n[capture] ALL 5 fixtures captured. Ship to WMA repo.');
}

main().catch((e) => {
  console.error('[capture] fatal:', e);
  process.exit(1);
});
