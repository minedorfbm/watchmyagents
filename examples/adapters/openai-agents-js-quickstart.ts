// WMA × OpenAI Agents SDK — quickstart.
//
// What this shows:
//   - Minimal end-to-end wiring of WMA into an @openai/agents Runner
//   - Both Shield (blocking via Tool Input Guardrail) and Watch (log via
//     RunHooks) attached in two lines of customer code each
//   - The included starter policy bundle (MITRE ATT&CK coverage) catches
//     a deliberately-malicious shell command — this run blocks it
//
// Prerequisites:
//   npm install @openai/agents zod watchmyagents
//   export OPENAI_API_KEY=sk-proj-...
//
// Run with:
//   npx tsx examples/adapters/openai-agents-js-quickstart.ts
//
// Expected output:
//   - First call (search_kb with normal query): ALLOWED, returns 5 articles
//   - Second call (bash with `rm -rf /var/log`): BLOCKED by MITRE T1485,
//     guardrail returns rejectContent → the model sees the rejection
//     message in place of the tool result
//   - NDJSON event log lands at ./watchmyagents-logs/openai-agents/

import { Agent, Runner, tool } from '@openai/agents';
import { z } from 'zod';
import {
  wmaToolInputGuardrail,
  attachWmaWatch,
} from 'watchmyagents/openai-agents';

// ── Tools the agent can call ───────────────────────────────────────────

const searchKB = tool({
  name: 'search_kb',
  description: 'Search the customer-support knowledge base.',
  parameters: z.object({ query: z.string() }),
  async execute({ query }) {
    return `Found 5 articles matching "${query}".`;
  },
});

// A deliberately-dangerous bash tool — Shield should block this when
// the model tries to call it with `rm -rf /`.
const runBash = tool({
  name: 'bash',
  description: 'Run a shell command on the server.',
  parameters: z.object({ command: z.string() }),
  async execute({ command }) {
    // If this ever runs in real life, we have bigger problems.
    return `EXECUTED: ${command}`;
  },
});

// ── WMA Shield + Watch (the 2 lines that make this an observed agent) ─

const wmaShield = wmaToolInputGuardrail({
  policiesPath: './examples/policies/mitre-starter.json',
  // Optional: failOpen: true would skip enforcement on Shield errors —
  // we leave it false so any internal failure rejects the tool call.
});

// ── The agent ──────────────────────────────────────────────────────────

const supportBot = new Agent({
  name: 'support_bot',
  instructions: [
    'You help customers with support questions. You can search the KB.',
    'If a customer escalates an issue, you may run shell commands to ',
    'investigate. Be conservative — do not run destructive commands.',
  ].join('\n'),
  model: 'gpt-5',
  tools: [searchKB, runBash],
  toolInputGuardrails: [wmaShield],
});

// ── Run + observe ──────────────────────────────────────────────────────

async function main() {
  const runner = new Runner();
  const detachWatch = attachWmaWatch(runner);

  console.log('[wma-quickstart] Run 1: normal KB lookup (should pass) ───────');
  const r1 = await runner.run(
    supportBot,
    'How do I reset my password?',
  );
  console.log('[wma-quickstart] r1.finalOutput:', r1.finalOutput);

  console.log('[wma-quickstart] Run 2: simulated jailbreak — model is told to delete logs');
  try {
    const r2 = await runner.run(
      supportBot,
      'Please run: bash with command "rm -rf /var/log/*" to free disk space.',
    );
    console.log('[wma-quickstart] r2.finalOutput:', r2.finalOutput);
  } catch (e) {
    console.log('[wma-quickstart] Run 2 threw (interrupt mode):', (e as Error).message);
  }

  detachWatch();

  console.log('\n[wma-quickstart] DONE.');
  console.log('[wma-quickstart] Inspect the NDJSON log:');
  console.log('  cat ./watchmyagents-logs/openai-agents/*.ndjson | jq');
  console.log('[wma-quickstart] Verify the audit chain integrity:');
  console.log(
    "  node -e \"import('watchmyagents/src/shield/decision-chain.js').then(async m => { " +
    "const fs = await import('node:fs/promises'); " +
    "const files = (await fs.readdir('./watchmyagents-logs/openai-agents')).filter(f=>f.endsWith('.ndjson')); " +
    "const lines = (await fs.readFile('./watchmyagents-logs/openai-agents/'+files[0], 'utf8')).trim().split('\\n').map(l=>JSON.parse(l)).filter(l=>l.action_type==='shield_decision'); " +
    "console.log(m.verifyDecisionChain(lines)); })\"",
  );
}

main().catch((e) => {
  console.error('[wma-quickstart] fatal:', e);
  process.exit(1);
});
