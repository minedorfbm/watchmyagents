// Pricing is intentionally NOT bundled in the SDK: per-customer plans evolve.
// Supply your own table via WatchMyAgents({ tokenPricing: { 'model-id': { input, output, cache_read, cache_write } } })
// to get cost_usd populated on entries; otherwise cost stays null and only
// token counts (split + by-model) are tracked.
export const DEFAULT_PRICING = {};

// v1.4.2 F-49 (P2 audit): coerce a token/usage value to a safe non-negative
// integer. The old `x || 0` is a FALSY guard, not a numeric one — it lets
// negatives through (`-5 || 0` === -5) and a NaN propagates through later
// arithmetic to poison totals (`NaN + n` → NaN → `|| null` → null), silently
// ZEROING a real LLM call's tokens. A malformed or adversarial usage payload
// could thus under-report the security-relevant consumption signal (a runaway
// / abused agent) or drive aggregate token/cost negative. Anything not a
// finite non-negative number becomes 0.
export function safeNonNegInt(x) {
  return Number.isFinite(x) && x >= 0 ? Math.trunc(x) : 0;
}

export function estimateCost(model, t, pricing) {
  if (!model) return null;
  const p = (pricing && pricing[model]) || DEFAULT_PRICING[model];
  if (!p) return null;
  const inT = safeNonNegInt(t.input_tokens);
  const outT = safeNonNegInt(t.output_tokens);
  const cr = safeNonNegInt(t.cache_read_tokens);
  const cw = safeNonNegInt(t.cache_creation_tokens);
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
    // Security-audit principle: count EVERY action, including zero-token ones
    // (tool_use, message, thinking, user_message, errors…). Only skip meta-
    // entries that are not actions themselves.
    if (entry.action_type === 'session_end') return;

    const t = {
      input: safeNonNegInt(entry.input_tokens),
      output: safeNonNegInt(entry.output_tokens),
      cache_read: safeNonNegInt(entry.cache_read_tokens),
      cache_creation: safeNonNegInt(entry.cache_creation_tokens),
    };
    // F-49: a provided tokens_used is sanitized too; 0/missing falls back to
    // the (sanitized) component sum.
    const provided = safeNonNegInt(entry.tokens_used);
    const sum = provided || (t.input + t.output + t.cache_read + t.cache_creation);
    const cost = Number.isFinite(entry.cost_usd) && entry.cost_usd >= 0 ? entry.cost_usd : 0;

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
