import { mkdir, appendFile, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { assertSafePathSegment } from './validate.js';

// v1.1.6 F-24 (P3 Codex audit): the `mode` option on mkdir() and
// appendFile() is only honored when the directory or file is CREATED.
// If a previous wma-fetch run, a different user, or a hand-rolled mkdir
// already left those paths around with the system umask (typically
// 0755 / 0644), the original constructor would silently keep the loose
// perms even though SECURITY.md promises 0700 / 0600. tightenMode runs
// after every mkdir / append to bring the existing inode in line with
// the docs. Errors are swallowed (best-effort): the chmod is a hardening
// pass, not a precondition — failing it shouldn't break logging.
async function tightenMode(path, mode) {
  try { await chmod(path, mode); } catch { /* not fatal */ }
}

// PR-B: `framework` → `provider` (canonical name per src/sources/contract.js).
// PR-C: adds `parent_agent_id` + `composition_pattern` so any future
// adapter that knows the hierarchy (OpenAI Agents handoffs, CrewAI
// manager, Hermes Agent spawn_subagent, LangGraph sub-graphs) can
// thread the relationship through to Fortress without rework.
// NDJSON written before PR-B may carry `framework`; readers that need the
// provider tag should read `provider` first and fall back to `framework`.
const EXPORT_FIELDS = [
  'id', 'agent_id', 'parent_agent_id', 'composition_pattern',
  'provider', 'timestamp', 'action_type',
  // v1.0.2 F-6a — Anthropic-style sub-agent discriminators preserved locally
  'session_thread_id', 'agent_name',
  'tool_name', 'duration_ms', 'tokens_used',
  'input_tokens', 'output_tokens', 'cache_read_tokens', 'cache_creation_tokens',
  'cost_usd', 'model',
  'session_tokens', 'session_cost_usd',
  'status', 'error', 'sequence_number', 'session_id',
  // v1.3.0 — team correlation across cooperating agents. Populated by
  // adapters that observe handoffs (OpenAI Agents SDK, future Claude
  // Code workflow runId). Null when unknown / no team scope.
  'team_id',
];

export class Logger {
  // `silent`     : don't print log errors to stderr (default: true — quiet operation)
  // `bestEffort` : SWALLOW write failures (default: false — fail loud).
  //                Audit-grade default: refuse to silently lose events. Disk
  //                full / EACCES / EINVAL must propagate so callers know.
  //                Opt into bestEffort=true only for non-critical paths.
  // `chain`      : v1.2.0 — optional decision-chain instance (see
  //                src/shield/decision-chain.js). When set, every record
  //                written through this logger gets prev_hash + chain_hash
  //                appended, building a tamper-evident audit chain. Today
  //                this is only enabled by DecisionLogger (shield_decision
  //                rows). Watch's Loggers leave it null so Watch rows have
  //                no chain fields — verifyDecisionChain() filters by
  //                action_type, so both kinds of rows coexist cleanly.
  constructor({ logDir, agentId, sessionId, silent, bestEffort, chain } = {}) {
    // agentId becomes a filesystem path segment (logDir/<agentId>/…). Reject
    // anything that could traverse out of logDir before we ever build a path.
    assertSafePathSegment(agentId, 'agentId');
    this.logDir = logDir;
    this.agentId = agentId;
    this.sessionId = sessionId || randomUUID();
    this.silent = silent !== false;
    this.bestEffort = bestEffort === true;
    this.chain = chain || null;
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
      // v1.3.0 — prefer the event's agent_id when present so multi-agent
      // adapters (OpenAI Agents SDK handoffs, future LangGraph subgraphs)
      // can attribute each event to its actual emitter. Falls back to
      // the Logger's constructor agentId for single-agent adapters
      // (Anthropic Managed) where every event from this logger belongs
      // to the same agent. Backwards compatible: existing Anthropic
      // adapter doesn't populate e.agent_id on every yield, so the
      // fallback path keeps its behavior intact.
      agent_id: e.agent_id || this.agentId,
      // PR-C: sub-agent fields. Defaults are honest for solo / root agents.
      // An adapter that detects hierarchy (e.g. OpenAI Agents handoffs)
      // populates these on the event, and the Logger threads them through.
      parent_agent_id: e.parent_agent_id ?? null,
      composition_pattern: e.composition_pattern || 'solo',
      // v1.0.2 F-6a: Anthropic-style discriminators preserved LOCAL ONLY
      // (never sent raw to Fortress — SignalsAggregator derives the
      // aggregated session_ids list from these at finalize time).
      session_thread_id: e.session_thread_id ?? null,
      agent_name: e.agent_name ?? null,
      provider: e.provider || e.framework || 'generic',
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
      // v1.3.0 — team correlation. Adapters that observe multi-agent
      // groupings (OpenAI Agents SDK handoffs, future Claude Code
      // workflow runId) populate this. Null when unknown.
      team_id: e.team_id ?? null,
      input: e.input ?? null,
      output: e.output ?? null,
    };
    // v1.2.0 — if a decision chain is attached, wrap the composed record
    // so it carries prev_hash + chain_hash. The wrap is computed over the
    // canonical body that ends up on disk; the verifier reproduces the
    // same hash by reading the file. See src/shield/decision-chain.js.
    const toWrite = this.chain ? this.chain.wrap(full) : full;
    try {
      const dir = join(this.logDir, this.agentId);
      await mkdir(dir, { recursive: true, mode: 0o700 });
      // v1.1.6 F-24: tighten existing perms — `mode` is creation-only.
      await tightenMode(dir, 0o700);
      await appendFile(path, JSON.stringify(toWrite) + '\n', { encoding: 'utf8', mode: 0o600 });
      await tightenMode(path, 0o600);
      this.count++;
    } catch (err) {
      if (!this.silent) process.stderr.write(`[wma] log write error: ${err.message}\n`);
      // Audit-grade default: fail loud so callers know events are being lost.
      // Disk full, EACCES, EINVAL etc. should NOT be silently swallowed.
      if (!this.bestEffort) throw err;
    }
    return toWrite;
  }

  toExportRecord(entry) {
    const out = {};
    for (const k of EXPORT_FIELDS) out[k] = entry[k];
    return out;
  }
}
