import { mkdir, appendFile } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

const EXPORT_FIELDS = [
  'id', 'agent_id', 'framework', 'timestamp', 'action_type',
  'tool_name', 'duration_ms', 'tokens_used', 'status', 'error',
  'sequence_number', 'session_id',
];

export class Logger {
  constructor({ logDir, agentId, sessionId, silent }) {
    this.logDir = logDir;
    this.agentId = agentId;
    this.sessionId = sessionId || randomUUID();
    this.silent = silent !== false;
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
      tokens_used: e.tokens_used ?? null,
      status: e.status || 'ok',
      error: e.error || null,
      sequence_number: ++this.sequence,
      session_id: this.sessionId,
      input: e.input ?? null,
      output: e.output ?? null,
    };
    try {
      await mkdir(join(this.logDir, this.agentId), { recursive: true });
      await appendFile(path, JSON.stringify(full) + '\n', 'utf8');
      this.count++;
    } catch (err) {
      if (!this.silent) process.stderr.write(`[wma] log error: ${err.message}\n`);
    }
    return full;
  }

  toExportRecord(entry) {
    const out = {};
    for (const k of EXPORT_FIELDS) out[k] = entry[k];
    return out;
  }
}
