import { WatchMyAgents } from '../collector.js';

export function createOpenAIMonitor(opts = {}) {
  const wma = WatchMyAgents.current() || new WatchMyAgents({ ...opts, framework: 'openai' });

  function wrapMethod(obj, method, action_type) {
    if (!obj || typeof obj[method] !== 'function') return;
    const orig = obj[method].bind(obj);
    obj[method] = async (params) => {
      const start = Date.now();
      let status = 'ok', error = null, res;
      try {
        res = await orig(params);
        return res;
      } catch (e) {
        status = 'error'; error = e?.message || String(e); throw e;
      } finally {
        const usage = res?.usage || {};
        const tokens = (usage.prompt_tokens || usage.input_tokens || 0) +
                       (usage.completion_tokens || usage.output_tokens || 0);
        await wma.logAction({
          framework: 'openai',
          action_type,
          tool_name: params?.model || params?.assistant_id || method,
          duration_ms: Date.now() - start,
          tokens_used: tokens || null,
          status, error,
          input: { model: params?.model, assistant_id: params?.assistant_id },
          output: { id: res?.id, status: res?.status },
        });
      }
    };
  }

  return {
    wma,
    wrap(client) {
      wrapMethod(client?.chat?.completions, 'create', 'llm_call');
      wrapMethod(client?.completions, 'create', 'llm_call');
      wrapMethod(client?.beta?.threads?.runs, 'create', 'assistant_run');
      wrapMethod(client?.beta?.threads?.runs, 'createAndPoll', 'assistant_run');
      wrapMethod(client?.responses, 'create', 'llm_call');
      return client;
    },
  };
}
