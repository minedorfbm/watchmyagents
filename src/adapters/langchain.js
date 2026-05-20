import { WatchMyAgents } from '../collector.js';

export function createLangChainHandler(opts = {}) {
  const wma = WatchMyAgents.current() || new WatchMyAgents({ ...opts, framework: 'langchain' });
  const starts = new Map();
  const begin = id => starts.set(id, Date.now());
  const elapsed = id => { const t = starts.get(id); starts.delete(id); return t ? Date.now() - t : null; };

  return {
    name: 'WatchMyAgentsHandler',
    handleLLMStart: async (_l, _p, runId) => begin(runId),
    handleLLMEnd: async (out, runId) => {
      const u = out?.llmOutput?.tokenUsage || {};
      const inT = u.promptTokens || 0, outT = u.completionTokens || 0;
      return wma.logAction({
        framework: 'langchain', action_type: 'llm_call', tool_name: 'llm',
        model: out?.llmOutput?.modelName || null,
        duration_ms: elapsed(runId),
        input_tokens: inT || null, output_tokens: outT || null,
        tokens_used: (inT + outT) || null, status: 'ok',
      });
    },
    handleLLMError: async (err, runId) => wma.logAction({
      framework: 'langchain', action_type: 'llm_call', tool_name: 'llm',
      duration_ms: elapsed(runId), status: 'error', error: err?.message || String(err),
    }),
    handleToolStart: async (_t, _i, runId) => begin(runId),
    handleToolEnd: async (_o, runId) => wma.logAction({
      framework: 'langchain', action_type: 'tool_call', tool_name: 'tool',
      duration_ms: elapsed(runId), status: 'ok',
    }),
    handleToolError: async (err, runId) => wma.logAction({
      framework: 'langchain', action_type: 'tool_call', tool_name: 'tool',
      duration_ms: elapsed(runId), status: 'error', error: err?.message || String(err),
    }),
    handleChainStart: async (_c, _i, runId) => begin(runId),
    handleChainEnd: async (_o, runId) => wma.logAction({
      framework: 'langchain', action_type: 'chain', tool_name: 'chain',
      duration_ms: elapsed(runId), status: 'ok',
    }),
  };
}
