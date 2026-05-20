import { randomUUID } from 'node:crypto';
import { Logger } from './logger.js';
import { Exporter } from './exporter.js';
import { TokenTracker, estimateCost } from './tokens.js';

let _instance = null;

export class WatchMyAgents {
  constructor(opts = {}) {
    this.apiKey = opts.apiKey || process.env.WMA_API_KEY || null;
    this.agentId = opts.agentId || 'default-agent';
    this.logDir = opts.logDir || process.env.WMA_LOG_DIR || './watchmyagents-logs';
    this.exportUrl = opts.exportUrl || process.env.WMA_EXPORT_URL || null;
    this.silent = opts.silent !== false;
    this.sessionId = opts.sessionId || randomUUID();
    this.framework = opts.framework || 'generic';
    this.tokenPricing = opts.tokenPricing || null;
    this.tracker = new TokenTracker();
    this.logger = new Logger({ logDir: this.logDir, agentId: this.agentId, sessionId: this.sessionId, silent: this.silent });
    this.exporter = new Exporter({
      apiKey: this.apiKey, exportUrl: this.exportUrl, agentId: this.agentId,
      batchInterval: opts.batchInterval ?? 30000, silent: this.silent,
    });
    this.exporter.start();
    _instance = this;
  }

  static current() { return _instance; }
  static getOrCreate(opts) { return _instance || new WatchMyAgents(opts); }

  summarize(v) {
    if (v == null) return null;
    const t = typeof v;
    if (t === 'string') return { type: 'string', length: v.length };
    if (t === 'number' || t === 'boolean') return { type: t };
    if (Array.isArray(v)) return { type: 'array', length: v.length };
    if (t === 'object') return { type: 'object', keys: Object.keys(v).length };
    return { type: t };
  }

  _enrichTokens(entry) {
    const i = entry.input_tokens, o = entry.output_tokens;
    const cr = entry.cache_read_tokens || 0, cw = entry.cache_creation_tokens || 0;
    if (entry.tokens_used == null && (i != null || o != null)) {
      entry.tokens_used = (i || 0) + (o || 0) + cr + cw;
    }
    if (entry.cost_usd == null && entry.model) {
      entry.cost_usd = estimateCost(entry.model, {
        input_tokens: i, output_tokens: o,
        cache_read_tokens: cr, cache_creation_tokens: cw,
      }, this.tokenPricing);
    }
    return entry;
  }

  async watch(toolName, params, fn, meta = {}) {
    const start = Date.now();
    const id = randomUUID();
    let status = 'ok', error = null, result;
    try { result = await fn(); return result; }
    catch (e) { status = 'error'; error = e?.message || String(e); throw e; }
    finally {
      const entry = await this.logger.write(this._enrichTokens({
        id, framework: meta.framework || this.framework,
        action_type: meta.action_type || 'tool_call',
        tool_name: toolName, duration_ms: Date.now() - start,
        model: meta.model ?? null,
        tokens_used: meta.tokens_used ?? null,
        input_tokens: meta.input_tokens ?? null,
        output_tokens: meta.output_tokens ?? null,
        cache_read_tokens: meta.cache_read_tokens ?? null,
        cache_creation_tokens: meta.cache_creation_tokens ?? null,
        status, error, input: params, output: this.summarize(result),
      }));
      this.tracker.record(entry);
      this.exporter.enqueue(this.logger.toExportRecord(entry));
    }
  }

  async logAction(entry) {
    const written = await this.logger.write(this._enrichTokens({ ...entry }));
    this.tracker.record(written);
    this.exporter.enqueue(this.logger.toExportRecord(written));
    return written;
  }

  tokenStats() { return this.tracker.stats(); }

  async flush() { await this.exporter.flush(); }
  async shutdown() { this.exporter.stop(); await this.exporter.flush(); }
  get logPath() { return this.logger._pathForToday(); }
  get actionCount() { return this.logger.count; }
}
