import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import Anthropic from '@anthropic-ai/sdk';
import WatchMyAgents from '../../src/index.js';
import { createClaudeMonitor } from '../../src/adapters/claude.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

async function loadEnv() {
  try {
    const txt = await readFile(join(__dirname, '..', '..', '.env'), 'utf8');
    for (const line of txt.split('\n')) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
      if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
    }
  } catch {}
}

const TOOLS = [
  { name: 'get_weather', description: 'Get the weather for a city',
    input_schema: { type: 'object', properties: { city: { type: 'string' } }, required: ['city'] } },
  { name: 'search_web', description: 'Search the web',
    input_schema: { type: 'object', properties: { query: { type: 'string' } }, required: ['query'] } },
  { name: 'calculate', description: 'Evaluate a math expression',
    input_schema: { type: 'object', properties: { expression: { type: 'string' } }, required: ['expression'] } },
];

const HANDLERS = {
  get_weather: ({ city }) => ({ city, temp_c: 21, condition: 'sunny' }),
  search_web: ({ query }) => ({ query, results: [
    { title: `About ${query}`, snippet: 'fictitious result #1' },
    { title: `More on ${query}`, snippet: 'fictitious result #2' },
  ]}),
  calculate: ({ expression }) => {
    if (!/^[\d\s+\-*/().]+$/.test(expression)) throw new Error('invalid expression');
    return { expression, result: Function(`"use strict"; return (${expression});`)() };
  },
};

async function runTurn(claude, monitor, history) {
  const response = await claude.messages.create({
    model: 'claude-3-5-sonnet-20241022',
    max_tokens: 1024,
    tools: TOOLS,
    messages: history,
  });
  history.push({ role: 'assistant', content: response.content });

  const toolUses = response.content.filter(b => b.type === 'tool_use');
  if (toolUses.length === 0) return { done: true, response };

  const toolResults = [];
  for (const t of toolUses) {
    const start = Date.now();
    let output, status = 'ok', error = null;
    try { output = HANDLERS[t.name](t.input); }
    catch (e) { status = 'error'; error = e.message; output = { error: e.message }; }
    await monitor.wma.logAction({
      framework: 'claude',
      action_type: 'tool_use',
      tool_name: t.name,
      duration_ms: Date.now() - start,
      status, error,
      input: t.input,
      output,
    });
    toolResults.push({ type: 'tool_result', tool_use_id: t.id, content: JSON.stringify(output) });
  }
  history.push({ role: 'user', content: toolResults });
  return { done: false, response };
}

async function main() {
  await loadEnv();
  if (!process.env.ANTHROPIC_API_KEY) {
    process.stderr.write('Missing ANTHROPIC_API_KEY in environment or .env\n');
    process.exit(1);
  }

  const wma = new WatchMyAgents({
    apiKey: process.env.WMA_API_KEY || 'wma_demo_key',
    agentId: 'claude-example-agent',
    logDir: './watchmyagents-logs',
    exportUrl: process.env.WMA_EXPORT_URL || null,
    silent: true,
    batchInterval: 30000,
  });

  const monitor = createClaudeMonitor();
  const claude = monitor.wrap(new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY }));

  const history = [{
    role: 'user',
    content: 'Use your tools to answer: what is the weather in Paris, then search the web for "AI agent security", then compute 17 * 23. Give a brief final summary.',
  }];

  for (let i = 0; i < 6; i++) {
    const { done } = await runTurn(claude, monitor, history);
    if (done) break;
  }

  await wma.shutdown();

  process.stdout.write(`\n[WatchMyAgents] actions captured: ${wma.actionCount}\n`);
  process.stdout.write(`[WatchMyAgents] log file: ${wma.logPath}\n`);
}

main().catch(e => { process.stderr.write(`error: ${e.stack || e.message}\n`); process.exit(1); });
