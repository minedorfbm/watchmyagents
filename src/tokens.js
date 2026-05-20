// Built-in pricing table ($ per 1M tokens). Override via WatchMyAgents({ tokenPricing }).
export const DEFAULT_PRICING = {
  'claude-3-5-sonnet-20241022': { input: 3,    output: 15,   cache_read: 0.30, cache_write: 3.75 },
  'claude-3-5-sonnet-latest':   { input: 3,    output: 15,   cache_read: 0.30, cache_write: 3.75 },
  'claude-3-5-haiku-20241022':  { input: 0.80, output: 4,    cache_read: 0.08, cache_write: 1 },
  'claude-3-opus-20240229':     { input: 15,   output: 75,   cache_read: 1.50, cache_write: 18.75 },
  'claude-3-sonnet-20240229':   { input: 3,    output: 15 },
  'claude-3-haiku-20240307':    { input: 0.25, output: 1.25 },
  'gpt-4o':                     { input: 2.50, output: 10 },
  'gpt-4o-mini':                { input: 0.15, output: 0.60 },
  'gpt-4-turbo':                { input: 10,   output: 30 },
  'gpt-3.5-turbo':              { input: 0.50, output: 1.50 },
};

export function estimateCost(model, t, pricing) {
  if (!model) return null;
  const p = (pricing && pricing[model]) || DEFAULT_PRICING[model];
  if (!p) return null;
  const inT = t.input_tokens || 0;
  const outT = t.output_tokens || 0;
  const cr = t.cache_read_tokens || 0;
  const cw = t.cache_creation_tokens || 0;
  const cost = ((inT * (p.input || 0)) + (outT * (p.output || 0)) +
                (cr * (p.cache_read || 0)) + (cw * (p.cache_write || 0))) / 1_000_000;
  return Math.round(cost * 1_000_000) / 1_000_000;
}

export class TokenTracker {
  constructor() {
    this.total = { input: 0, output: 0, cache_read: 0, cache_creation: 0, sum: 0, cost_usd: 0 };
    this.byTool = new Map();
    this.byAction = new Map();
    this.byModel = new Map();
  }

  _bucket(map, key) {
    let b = map.get(key);
    if (!b) { b = { input: 0, output: 0, cache_read: 0, cache_creation: 0, sum: 0, cost_usd: 0, calls: 0 }; map.set(key, b); }
    return b;
  }

  record(entry) {
    const t = {
      input: entry.input_tokens || 0,
      output: entry.output_tokens || 0,
      cache_read: entry.cache_read_tokens || 0,
      cache_creation: entry.cache_creation_tokens || 0,
    };
    const sum = entry.tokens_used || (t.input + t.output + t.cache_read + t.cache_creation);
    const cost = entry.cost_usd || 0;
    if (sum === 0 && cost === 0) return;

    this.total.input += t.input;
    this.total.output += t.output;
    this.total.cache_read += t.cache_read;
    this.total.cache_creation += t.cache_creation;
    this.total.sum += sum;
    this.total.cost_usd += cost;

    for (const [map, key] of [[this.byTool, entry.tool_name], [this.byAction, entry.action_type], [this.byModel, entry.model]]) {
      if (!key) continue;
      const b = this._bucket(map, key);
      b.input += t.input; b.output += t.output;
      b.cache_read += t.cache_read; b.cache_creation += t.cache_creation;
      b.sum += sum; b.cost_usd += cost; b.calls += 1;
    }
  }

  stats() {
    const toObj = m => Object.fromEntries([...m.entries()].map(([k, v]) => [k, { ...v, cost_usd: round6(v.cost_usd) }]));
    return {
      total: { ...this.total, cost_usd: round6(this.total.cost_usd) },
      by_tool: toObj(this.byTool),
      by_action: toObj(this.byAction),
      by_model: toObj(this.byModel),
    };
  }
}

function round6(n) { return Math.round(n * 1_000_000) / 1_000_000; }
