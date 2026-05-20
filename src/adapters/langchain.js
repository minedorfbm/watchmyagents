import { WatchMyAgents } from '../collector.js';

export function createLangChainHandler(opts = {}) {
  const wma = WatchMyAgents.current() || new WatchMyAgents({ ...opts, framework: 'langchain' });
  const starts = new Map();
  const begin = id => starts.set(id, Date.now());
  const elapsed = id => { const t = starts.get(id); starts.delete(id); return t ? Date.now() - t : null; };
  const log = (action_type, runId, status = 'ok', error = null, tokens = null, tool_name = action_type) =>
    wma.logAction({ framework: 'langchain', action_type, tool_name, duration_ms: elapsed(runId), tokens_used: tokens, status, error });

  return {
    name: 'WatchMyAgentsHandler',
    handleLLMStart: async (_l, _p, runId) => begin(runId),
    handleLLMEnd: async (out, runId) => {
      const u = out?.llmOutput?.tokenUsage || {};
      return log('llm_call', runId, 'ok', null, (u.promptTokens || 0) + (u.completionTokens || 0) || null, 'llm');
    },
    handleLLMError: async (err, runId) => log('llm_call', runId, 'error', err?.message || String(err), null, 'llm'),
    handleToolStart: async (_t, _i, runId) => begin(runId),
    handleToolEnd: async (_o, runId) => log('tool_call', runId, 'ok', null, null, 'tool'),
    handleToolError: async (err, runId) => log('tool_call', runId, 'error', err?.message || String(err), null, 'tool'),
    handleChainStart: async (_c, _i, runId) => begin(runId),
    handleChainEnd: async (_o, runId) => log('chain', runId, 'ok', null, null, 'chain'),
  };
}
