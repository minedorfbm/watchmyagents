import { WatchMyAgents } from '../collector.js';

export function createClaudeMonitor(opts = {}) {
  const wma = WatchMyAgents.current() || new WatchMyAgents({ ...opts, framework: 'claude' });

  return {
    wma,
    wrap(client) {
      const m = client?.messages;
      if (!m?.create) return client;
      const orig = m.create.bind(m);
      m.create = async (params) => {
        const start = Date.now();
        let status = 'ok', error = null, res;
        try { res = await orig(params); return res; }
        catch (e) { status = 'error'; error = e?.message || String(e); throw e; }
        finally {
          const u = res?.usage || {};
          const toolUses = Array.isArray(res?.content)
            ? res.content.filter(b => b?.type === 'tool_use').map(b => b.name) : [];
          await wma.logAction({
            framework: 'claude', action_type: 'llm_call',
            tool_name: params?.model || 'messages.create',
            duration_ms: Date.now() - start,
            tokens_used: (u.input_tokens || 0) + (u.output_tokens || 0) || null,
            status, error,
            input: { model: params?.model, message_count: params?.messages?.length, tool_count: params?.tools?.length || 0 },
            output: { stop_reason: res?.stop_reason || null, input_tokens: u.input_tokens || null, output_tokens: u.output_tokens || null, tool_uses: toolUses },
          });
        }
      };
      return client;
    },
    logToolUse: (name, input, output, duration_ms) =>
      wma.logAction({ framework: 'claude', action_type: 'tool_use', tool_name: name, duration_ms: duration_ms ?? null, status: 'ok', input, output }),
  };
}
