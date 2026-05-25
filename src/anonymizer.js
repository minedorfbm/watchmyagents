// ─────────────────────────────────────────────────────────────────────────
// Anonymizer — strip raw payloads, produce signals safe for Fortress
// ─────────────────────────────────────────────────────────────────────────
// Reads a Watch NDJSON file (the full local log) and produces an
// anonymized signals payload — the shape Fortress's `signals` table
// expects. The output contains ONLY:
//
//   - counts (action_type, tool_name)
//   - latencies (p50, p95, max) per tool
//   - error rates per tool
//   - salted SHA-256 hashes of IoCs (URLs, commands, queries)
//   - top action_type sequences (Markov pairs)
//   - stop_reason type counts (NOT the message text)
//   - tokens_total
//
// What it NEVER outputs:
//   - input.content (prompts)
//   - output.content (agent text)
//   - raw URLs / commands / queries
//   - error messages
//   - readable session_id (hashed)
//   - readable agent_id (hashed)
//   - PII of any kind
//
// This is the single bottleneck between Watch (local) and Fortress (cloud).
// Every byte that crosses to the cloud passes through this module.

import { createHash, randomBytes } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';

// ── Configuration ────────────────────────────────────────────────────────

// Fields that may contain raw data — we extract a hash, never the raw value.
const HASHABLE_INPUT_FIELDS = ['url', 'query', 'command', 'path', 'file_path'];

// Tool types whose inputs we want to hash for IoC tracking
const TOOL_ACTIONS = new Set(['tool_use', 'mcp_tool_use', 'custom_tool_use']);

// ── Hash helpers ─────────────────────────────────────────────────────────

/**
 * Salted SHA-256 hash. The salt is per-customer (passed in) so the same URL
 * at customer A produces a different hash than at customer B by default —
 * but if a global salt is used, identical IoCs across customers produce
 * identical hashes (the antivirus model for L4 cross-customer intel).
 */
export function hashWithSalt(value, salt) {
  if (value == null) return null;
  const s = typeof value === 'string' ? value : JSON.stringify(value);
  return 'sha256:' + createHash('sha256').update(salt).update(s).digest('hex').slice(0, 32);
}

// Generate a customer salt (if none provided)
export function generateSalt() {
  return randomBytes(16).toString('hex');
}

// ── Single-entry extractor: what hashable IoCs are in this entry? ────────

function extractIocs(entry, salt) {
  const out = [];
  if (!entry.input || typeof entry.input !== 'object') return out;
  for (const field of HASHABLE_INPUT_FIELDS) {
    const v = entry.input[field];
    if (typeof v === 'string' && v.length > 0) {
      out.push(hashWithSalt(v, salt));
    }
  }
  return out;
}

// ── Aggregator: walks the NDJSON stream and builds the signals payload ──

export class SignalsAggregator {
  constructor({ salt } = {}) {
    if (!salt) throw new Error('SignalsAggregator requires a salt');
    this.salt = salt;
    this.counts = Object.create(null);          // action_type → count
    this.toolCounts = Object.create(null);      // tool_name → count
    this.toolErrors = Object.create(null);      // tool_name → error count
    this.toolLatencies = Object.create(null);   // tool_name → number[]
    this.iocHashes = new Set();                 // unique IoC hashes
    this.sequences = Object.create(null);       // "A → B" → count
    this.stopReasons = Object.create(null);     // stop_reason.type → count
    this.tokensTotal = 0;
    this.windowStart = null;
    this.windowEnd = null;
    this.entryCount = 0;
    this._prevActionType = null;
    this._prevSessionId = null;
  }

  add(entry) {
    if (!entry) return;
    this.entryCount++;

    // Track window bounds
    const ts = entry.timestamp || '';
    if (ts) {
      if (!this.windowStart || ts < this.windowStart) this.windowStart = ts;
      if (!this.windowEnd || ts > this.windowEnd) this.windowEnd = ts;
    }

    // Counts
    const at = entry.action_type || 'unknown';
    this.counts[at] = (this.counts[at] || 0) + 1;

    // Sequence tracking (only within the same session)
    if (this._prevActionType && entry.session_id === this._prevSessionId
        && at !== 'session_end' && this._prevActionType !== 'session_end') {
      const seqKey = `${this._prevActionType} → ${at}`;
      this.sequences[seqKey] = (this.sequences[seqKey] || 0) + 1;
    }
    this._prevActionType = at;
    this._prevSessionId = entry.session_id || null;

    // Tools
    if (entry.tool_name && TOOL_ACTIONS.has(at)) {
      this.toolCounts[entry.tool_name] = (this.toolCounts[entry.tool_name] || 0) + 1;
      if (entry.status === 'error') {
        this.toolErrors[entry.tool_name] = (this.toolErrors[entry.tool_name] || 0) + 1;
      }
      if (typeof entry.duration_ms === 'number') {
        if (!this.toolLatencies[entry.tool_name]) this.toolLatencies[entry.tool_name] = [];
        this.toolLatencies[entry.tool_name].push(entry.duration_ms);
      }
      // Extract & hash IoCs from this tool's input
      for (const h of extractIocs(entry, this.salt)) this.iocHashes.add(h);
    }

    // Tokens
    if (typeof entry.tokens_used === 'number') this.tokensTotal += entry.tokens_used;

    // Stop reasons (state_transition entries carry these)
    const stopType = entry.output?.stop_reason?.type;
    if (typeof stopType === 'string') {
      this.stopReasons[stopType] = (this.stopReasons[stopType] || 0) + 1;
    }
  }

  // Compute p50/p95/max for an array of durations
  _percentiles(arr) {
    if (arr.length === 0) return null;
    const sorted = [...arr].sort((a, b) => a - b);
    const at = (p) => sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
    return { p50: at(50), p95: at(95), max: sorted[sorted.length - 1], n: sorted.length };
  }

  finalize() {
    // Latencies aggregated
    const latencies_p50_ms = {};
    const latencies_p95_ms = {};
    const error_rate_by_tool = {};
    for (const [tool, durations] of Object.entries(this.toolLatencies)) {
      const p = this._percentiles(durations);
      if (p) {
        latencies_p50_ms[tool] = p.p50;
        latencies_p95_ms[tool] = p.p95;
      }
    }
    for (const tool of Object.keys(this.toolCounts)) {
      const errs = this.toolErrors[tool] || 0;
      error_rate_by_tool[tool] = +(errs / this.toolCounts[tool]).toFixed(4);
    }
    // Top-10 sequences
    const sequencesTop = Object.entries(this.sequences)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([pattern, count]) => ({ pattern, count }));

    return {
      window_start: this.windowStart,
      window_end: this.windowEnd,
      payload: {
        counts: this.counts,
        tool_counts: this.toolCounts,
        latencies_p50_ms,
        latencies_p95_ms,
        error_rate_by_tool,
        ioc_hashes: [...this.iocHashes],
        sequences_top10: sequencesTop,
        stop_reasons: this.stopReasons,
        tokens_total: this.tokensTotal,
      },
      _meta: {
        entries_processed: this.entryCount,
      },
    };
  }
}

// ── Streaming convenience: anonymize a whole NDJSON file/dir ────────────

export async function anonymizeFile(filePath, { salt } = {}) {
  if (!salt) throw new Error('anonymizeFile requires a salt');
  const agg = new SignalsAggregator({ salt });
  const stream = createReadStream(filePath, { encoding: 'utf8' });
  const rl = createInterface({ input: stream, crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let e; try { e = JSON.parse(line); } catch { continue; }
    agg.add(e);
  }
  return agg.finalize();
}
