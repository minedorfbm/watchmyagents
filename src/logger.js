import { mkdir, appendFile } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { assertSafePathSegment } from './validate.js';

const EXPORT_FIELDS = [
  'id', 'agent_id', 'framework', 'timestamp', 'action_type',
  'tool_name', 'duration_ms', 'tokens_used',
  'input_tokens', 'output_tokens', 'cache_read_tokens', 'cache_creation_tokens',
  'cost_usd', 'model',
  'session_tokens', 'session_cost_usd',
  'status', 'error', 'sequence_number', 'session_id',
];

export class Logger {
  // `silent`     : don't print log errors to stderr (default: true — quiet operation)
  // `bestEffort` : SWALLOW write failures (default: false — fail loud).
  //                Audit-grade default: refuse to silently lose events. Disk
  //                full / EACCES / EINVAL must propagate so callers know.
  //                Opt into bestEffort=true only for non-critical paths.
  constructor({ logDir, agentId, sessionId, silent, bestEffort } = {}) {
    // agentId becomes a filesystem path segment (logDir/<agentId>/…). Reject
    // anything that could traverse out of logDir before we ever build a path.
    assertSafePathSegment(agentId, 'agentId');
    this.logDir = logDir;
    this.agentId = agentId;
    this.sessionId = sessionId || randomUUID();
    this.silent = silent !== false;
    this.bestEffort = bestEffort === true;
    this.sequence = 0;
    this.currentDay = null;
    this.currentPath = null;
    this.count = 0;
  }

  _pathForToday() {
    const day = new Date().toISOString().slice(0, 10);
    if (day !== this.currentDay) {
      this.currentDay = day;
      this.currentPath = join(this.logDir, this.agentId, `${day}.ndjson`);
    }
    return this.currentPath;
  }

  async write(e) {
    const path = this._pathForToday();
    const full = {
      id: e.id || randomUUID(),
      agent_id: this.agentId,
      framework: e.framework || 'generic',
      timestamp: e.timestamp || new Date().toISOString(),
      action_type: e.action_type || 'tool_call',
      tool_name: e.tool_name || null,
      duration_ms: e.duration_ms ?? null,
      model: e.model ?? null,
      tokens_used: e.tokens_used ?? null,
      input_tokens: e.input_tokens ?? null,
      output_tokens: e.output_tokens ?? null,
      cache_read_tokens: e.cache_read_tokens ?? null,
      cache_creation_tokens: e.cache_creation_tokens ?? null,
      cost_usd: e.cost_usd ?? null,
      status: e.status || 'ok',
      error: e.error || null,
      sequence_number: ++this.sequence,
      session_id: this.sessionId,
      session_tokens: e.session_tokens ?? null,
      session_cost_usd: e.session_cost_usd ?? null,
      input: e.input ?? null,
      output: e.output ?? null,
    };
    try {
      await mkdir(join(this.logDir, this.agentId), { recursive: true, mode: 0o700 });
      await appendFile(path, JSON.stringify(full) + '\n', { encoding: 'utf8', mode: 0o600 });
      this.count++;
    } catch (err) {
      if (!this.silent) process.stderr.write(`[wma] log write error: ${err.message}\n`);
      // Audit-grade default: fail loud so callers know events are being lost.
      // Disk full, EACCES, EINVAL etc. should NOT be silently swallowed.
      if (!this.bestEffort) throw err;
    }
    return full;
  }

  toExportRecord(entry) {
    const out = {};
    for (const k of EXPORT_FIELDS) out[k] = entry[k];
    return out;
  }
}
