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
//   - PII of any kind
//
// Forensic routing metadata that DOES cross to Fortress (opaque tokens,
// no semantic content, same sensitivity class as agent_id):
//   - session_ids[]  — opaque vendor session ids (e.g. Anthropic
//                      `sess_01XaNB…`). Sent so the operator looking
//                      at a Shield decision in Fortress can grep the
//                      LOCAL NDJSON for full raw context.
//                      → see docs/CONTAINMENT.md "Routing & forensic
//                        metadata" + the Fortress-side guardrails
//                        (RBAC, UI masking, audit log, retention).
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

// Well-known vendor built-in tool names that are SAFE to keep in clear in the
// signals payload. They are documented by the vendor, common across customers,
// and the operator NEEDS them legible in the dashboard ("3 web_search calls
// in 10 minutes" is the actionable signal). Anything not on this list is
// considered customer-controlled (custom tool, MCP tool with a customer-chosen
// name like "client_acme_export") and gets hashed before egress.
//
// To add a built-in: only confirmed-public-by-vendor names — never speculative
// matches. When in doubt, hash.
const WELL_KNOWN_TOOLS = new Set([
  // Anthropic Managed Agents
  'web_search', 'web_fetch', 'bash', 'code_execution',
  'str_replace_editor', 'str_replace_based_edit_tool',
  'computer', 'computer_use_20250124', 'computer_use_20241022',
  'text_editor', 'text_editor_20250124', 'text_editor_20241022',
  // OpenAI Agents / Responses
  'web_search_preview', 'file_search', 'computer_use_preview', 'code_interpreter',
  // Common framework primitives
  'function', 'retrieval',
]);

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

// ── Tool name normalization (Containment hardening, v1.0.1 F-3) ────────

/**
 * Return the canonical tool-name token that's safe to ship to Fortress.
 *
 * - For documented vendor built-ins (WELL_KNOWN_TOOLS) the name is kept
 *   in clear so dashboards and Guardian policies can reason about the
 *   tool by its public identifier.
 * - For anything else (customer-defined functions, MCP tools whose name
 *   is set by the customer's MCP server, e.g. "client_acme_export"),
 *   the name is salted-SHA256-hashed with a `tool_hash:` prefix so it
 *   cannot leak project/client identifiers.
 *
 * Empty / null tool names return null.
 */
export function normalizeToolName(toolName, salt) {
  if (toolName == null) return null;
  const s = String(toolName);
  if (s.length === 0) return null;
  if (WELL_KNOWN_TOOLS.has(s)) return s;
  if (!salt) throw new Error('normalizeToolName requires a salt to hash custom tool names');
  return 'tool_hash:' + createHash('sha256').update(salt).update(s).digest('hex').slice(0, 32);
}

// ── Tool input field normalization (Phase 1.A L-2, v1.1.3) ──────────────
//
// HASHABLE_INPUT_FIELDS is the canonical set of input field names the
// anonymizer knows how to hash. These names came from the Anthropic tool
// shape (`web_fetch.url`, `web_search.query`, `bash.command`, file tools).
// Other frameworks use different native names — OpenAI function tools
// have arbitrary user-defined argument names, LangGraph tools use the
// `tools[].args` shape, CrewAI uses `task.context`, etc.
//
// To avoid silent IoC loss when a new adapter lands, adapters can call
// `normalizeToolInput()` BEFORE yielding their WMAAction to map their
// native tool argument names to the canonical set. The function takes
// the raw input object and an alias map `{nativeName: canonicalName}`
// and returns a new object where canonical names are populated from
// the corresponding native fields (without losing the originals — both
// are kept so the local NDJSON preserves full fidelity).
//
// Example for a future OpenAI function tool that exposes `endpoint_url`:
//   yield {
//     ...,
//     action_type: 'custom_tool_use',
//     tool_name: 'fetch_remote',
//     input: normalizeToolInput(rawInput, { endpoint_url: 'url' }),
//   };
// Now `entry.input.url` is populated → the anonymizer's IoC hashing
// fires → Fortress receives a hashed signal as expected.
//
// Adapters that already use canonical names (Anthropic) can skip the
// helper — it's a no-op when no aliases match.
export function normalizeToolInput(rawInput, aliases = {}) {
  if (rawInput == null || typeof rawInput !== 'object') return rawInput;
  const out = { ...rawInput };
  for (const [nativeName, canonicalName] of Object.entries(aliases)) {
    if (!HASHABLE_INPUT_FIELDS.includes(canonicalName)) {
      throw new Error(`normalizeToolInput: "${canonicalName}" is not a canonical hashable field (must be one of: ${HASHABLE_INPUT_FIELDS.join(', ')})`);
    }
    if (out[canonicalName] == null && rawInput[nativeName] != null) {
      out[canonicalName] = rawInput[nativeName];
    }
  }
  return out;
}

// Re-export the canonical hashable-fields list so adapter authors can
// programmatically reference the contract.
export { HASHABLE_INPUT_FIELDS };

// ── Heuristic field-name patterns (v1.3.1 F-30 Codex audit on v1.3.0) ───
//
// HASHABLE_INPUT_FIELDS is the canonical set; adapter authors are also
// encouraged to call `normalizeToolInput()` to map their native names.
// But OpenAI Agents SDK customers define their own tool argument names
// (`endpoint_url`, `shell_cmd`, `requestUrl`, …) and rarely think to
// register aliases. The result before v1.3.1: those fields silently
// disappeared from Fortress signals — not a leak (the raw payload stays
// LOCAL), but a detection blind spot.
//
// This heuristic catches the long tail. For each non-canonical input
// field, if its NAME matches a common suffix/word pattern, hash its
// value as if it were the corresponding canonical field. Conservative
// by design: regex anchored to word/suffix boundaries (`_url` matches,
// `urlsafe` does NOT) so we err toward false positives (hashing a
// harmless field is fine) over false negatives (missing a sensitive
// field is the bug we're fixing).
//
// Add new patterns here when adapters surface new common names.
const HEURISTIC_FIELD_PATTERNS = Object.freeze({
  url:     /(?:^|[_-])(?:url|uri|endpoint|webhook|address)$/i,
  command: /(?:^|[_-])(?:cmd|command|shell|exec|script)$/i,
  path:    /(?:^|[_-])(?:path|file|filename|filepath|dir|folder)$/i,
  query:   /(?:^|[_-])(?:query|search|q|prompt|term)$/i,
});

function fieldMatchesCanonicalByHeuristic(fieldName, canonical) {
  const pat = HEURISTIC_FIELD_PATTERNS[canonical];
  return pat ? pat.test(fieldName) : false;
}

// ── Single-entry extractor: what hashable IoCs are in this entry? ────────

function extractIocs(entry, salt) {
  const out = [];
  if (!entry.input || typeof entry.input !== 'object') return out;

  // Exact canonical match (original v1.0+ behavior — backwards compat).
  for (const field of HASHABLE_INPUT_FIELDS) {
    const v = entry.input[field];
    if (typeof v === 'string' && v.length > 0) {
      out.push(hashWithSalt(v, salt));
    }
  }

  // v1.3.1 F-30 — heuristic suffix matching for non-canonical field
  // names common to OpenAI Agents SDK / LangGraph / CrewAI tools. Skip
  // fields already handled above so we never double-hash.
  for (const [key, v] of Object.entries(entry.input)) {
    if (HASHABLE_INPUT_FIELDS.includes(key)) continue;
    if (typeof v !== 'string' || v.length === 0) continue;
    for (const canonical of HASHABLE_INPUT_FIELDS) {
      if (fieldMatchesCanonicalByHeuristic(key, canonical)) {
        out.push(hashWithSalt(v, salt));
        break; // one canonical bucket per field — first match wins
      }
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
    // v1.0.2 F-6b — opaque session ids active in this window. Shipped to
    // Fortress in the payload as `session_ids[]` so an operator looking at
    // a Shield decision in the dashboard can grep their LOCAL NDJSON by
    // session_id immediately (forensics short-circuit). The Anthropic
    // session_id is a non-semantic token like `sess_01XaNB…` — same
    // sensitivity class as `agent_id`, which we already transmit.
    this.seenSessions = new Set();              // unique session_ids
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

    // F-6b — collect every distinct session_id encountered in the window.
    // Stays opaque (no string transformation), bounded by the natural
    // number of sessions in the window.
    if (typeof entry.session_id === 'string' && entry.session_id.length > 0) {
      this.seenSessions.add(entry.session_id);
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

    // Tools — Containment (v1.0.1 F-3): well-known vendor built-ins keep
    // their public name; customer-defined / MCP tool names get hashed so
    // no client-identifying string ("client_acme_export") leaks via the
    // tool_counts / tool_latencies / error_rate maps.
    if (entry.tool_name && TOOL_ACTIONS.has(at)) {
      const toolKey = normalizeToolName(entry.tool_name, this.salt);
      if (toolKey) {
        this.toolCounts[toolKey] = (this.toolCounts[toolKey] || 0) + 1;
        if (entry.status === 'error') {
          this.toolErrors[toolKey] = (this.toolErrors[toolKey] || 0) + 1;
        }
        if (typeof entry.duration_ms === 'number') {
          if (!this.toolLatencies[toolKey]) this.toolLatencies[toolKey] = [];
          this.toolLatencies[toolKey].push(entry.duration_ms);
        }
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
        // F-6c — opaque session ids active in this window, sorted for
        // determinism. Operator forensic chain:
        //   Fortress decision → window_start/end + session_ids → grep
        //   the local NDJSON of the affected agent → full raw context.
        session_ids: [...this.seenSessions].sort(),
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
