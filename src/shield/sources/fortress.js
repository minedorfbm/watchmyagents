// ─────────────────────────────────────────────────────────────────────────
// Shield → Fortress integration (v0.6.0)
// ─────────────────────────────────────────────────────────────────────────
// Two pieces:
//   1. fetchPolicies()  — Shield pulls active policies from Fortress
//   2. postDecision()   — Shield pushes each enforcement decision to Fortress
//
// Both authenticate with the customer's `wma_xxx` API key (Bearer header),
// against the Edge Functions get-policies and ingest-decisions deployed in
// the Fortress repo.

import { request as httpsRequest } from 'node:https';
import { URL } from 'node:url';
import { fortressEndpoint } from '../../fortress/url.js';

const DEFAULT_TIMEOUT_MS = 15_000;
// v1.1.2 F-17 (P3 Codex audit): cap on the total bytes we'll accumulate
// for a Fortress JSON response before aborting the request. A misconfigured
// or compromised endpoint streaming an unbounded body would otherwise
// exhaust Shield's memory, despite the HTTPS-only + timeout guards.
// 8 MB is far above the realistic ceiling for a customer's policy ruleset
// (hundreds of policies × ~1 KB each → ~hundreds of KB). On overflow we
// destroy the request, which propagates to onError + cached-ruleset
// fallback.
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

function httpsJson(method, url, headers, body, timeoutMs = DEFAULT_TIMEOUT_MS) {
  return new Promise((resolveReq, rejectReq) => {
    const u = new URL(url);
    if (u.protocol !== 'https:') {
      return rejectReq(new Error(`refusing non-https Fortress URL: ${url}`));
    }
    const data = body ? Buffer.from(JSON.stringify(body)) : null;
    const opts = {
      method,
      hostname: u.hostname,
      port: u.port || 443,
      path: u.pathname + (u.search || ''),
      headers: {
        ...headers,
        ...(data ? { 'content-type': 'application/json', 'content-length': data.length } : {}),
      },
      rejectUnauthorized: true,
    };
    const req = httpsRequest(opts, (res) => {
      const chunks = [];
      let receivedBytes = 0;
      let aborted = false;
      res.on('data', (c) => {
        if (aborted) return;
        receivedBytes += c.length;
        if (receivedBytes > MAX_RESPONSE_BYTES) {
          aborted = true;
          // Free anything we already buffered, then tear down the request.
          chunks.length = 0;
          try { req.destroy(); } catch { /* already destroyed */ }
          rejectReq(new Error(`Fortress response exceeded ${MAX_RESPONSE_BYTES} bytes — aborting (received ${receivedBytes} so far)`));
          return;
        }
        chunks.push(c);
      });
      res.on('end', () => {
        if (aborted) return;
        const raw = Buffer.concat(chunks).toString('utf8');
        let parsed = null;
        try { parsed = raw ? JSON.parse(raw) : null; } catch { /* keep raw */ }
        resolveReq({ status: res.statusCode || 0, body: parsed ?? raw });
      });
    });
    req.on('error', rejectReq);
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`Fortress request timed out after ${timeoutMs}ms`));
    });
    if (data) req.write(data);
    req.end();
  });
}

/**
 * GET /functions/v1/get-policies?agent_id=<anthropicAgentId>
 * Returns the array of enabled policies for this customer + agent.
 *
 * @param {object} opts
 * @param {string} opts.apiKey - wma_xxx
 * @param {string} opts.base - Fortress base URL (https://x.supabase.co/functions/v1)
 * @param {string} [opts.anthropicAgentId] - optional filter
 * @returns {Promise<{ ok: true, policies: array, fetched_at: string }>}
 */
export async function fetchPolicies({ apiKey, base, anthropicAgentId }) {
  let url = fortressEndpoint(base, 'get-policies');
  if (anthropicAgentId) {
    const sep = url.includes('?') ? '&' : '?';
    url += `${sep}agent_id=${encodeURIComponent(anthropicAgentId)}`;
  }
  const { status, body } = await httpsJson('GET', url, {
    authorization: `Bearer ${apiKey}`,
    accept: 'application/json',
  });
  if (status === 200 && body && body.ok) {
    return { ok: true, policies: body.policies || [], fetched_at: body.fetched_at };
  }
  const err = body?.error || (typeof body === 'string' ? body.slice(0, 200) : 'unknown');
  throw new Error(`get-policies failed (HTTP ${status}): ${err}`);
}

/**
 * POST /functions/v1/ingest-decisions
 * Push a single enforcement decision to Fortress.
 *
 * @param {object} opts
 * @param {string} opts.apiKey - wma_xxx
 * @param {string} opts.base - Fortress base URL
 * @param {object} opts.decision - the body to POST. See ingest-decisions docs.
 *   {
 *     anthropic_agent_id, decision,
 *     rule_id?, session_hash?, event_id_hash?, input_hash?,
 *     action_type?, tool_name?, message?, decided_at?, decided_in_ms?
 *   }
 * @returns {Promise<{ ok: true, decision_id: string, agent_id: string }>}
 */
export async function postDecision({ apiKey, base, decision }) {
  const url = fortressEndpoint(base, 'ingest-decisions');
  const { status, body } = await httpsJson('POST', url, {
    authorization: `Bearer ${apiKey}`,
  }, decision);
  if (status === 200 && body && body.ok) {
    return { ok: true, decision_id: body.decision_id, agent_id: body.agent_id };
  }
  const err = body?.error || (typeof body === 'string' ? body.slice(0, 200) : 'unknown');
  throw new Error(`ingest-decisions failed (HTTP ${status}): ${err}`);
}

// ────────────────────────────────────────────────────────────────────────
// FortressPolicySource — drop-in replacement for the local JSON loader.
// Periodically refreshes the policy ruleset from Fortress.
// ────────────────────────────────────────────────────────────────────────

import { matchesPolicy, compileMatchRegexes } from '../policy.js';

const VALID_ACTIONS = new Set(['allow', 'deny', 'interrupt']);

export class FortressPolicySource {
  constructor({ apiKey, base, anthropicAgentId, refreshIntervalMs = 5 * 60_000, onError, onRefresh }) {
    if (!apiKey) throw new Error('FortressPolicySource: apiKey required');
    if (!base) throw new Error('FortressPolicySource: base URL required');
    this.apiKey = apiKey;
    this.base = base;
    this.anthropicAgentId = anthropicAgentId;
    this.refreshIntervalMs = refreshIntervalMs;
    this.onError = onError || (() => {});
    this.onRefresh = onRefresh || (() => {});
    this.ruleset = { version: 1, policies: [], default: { action: 'allow' } };
    this.lastFetchedAt = null;
    this._timer = null;
    this._aborted = false;
  }

  /** Initial fetch — fails loud if it can't reach Fortress at startup. */
  async start() {
    await this._refresh({ initial: true });
    this._timer = setInterval(() => this._refresh().catch(this.onError), this.refreshIntervalMs);
    if (this._timer.unref) this._timer.unref();
  }

  stop() {
    this._aborted = true;
    if (this._timer) { clearInterval(this._timer); this._timer = null; }
  }

  /** Returns the current ruleset (used by the policy evaluator). */
  current() {
    return this.ruleset;
  }

  /**
   * Public refresh hook for out-of-band triggers — e.g. the v1.1.0 SSE
   * PolicyStream fires this when Fortress pushes a policy_changed event,
   * collapsing the up-to-60s polling latency to ~100ms.
   * Safe to call concurrently with the internal interval timer: each
   * call only performs a single network round-trip.
   */
  async refresh() {
    return this._refresh();
  }

  async _refresh({ initial = false } = {}) {
    if (this._aborted) return;
    try {
      const { policies, fetched_at } = await fetchPolicies({
        apiKey: this.apiKey,
        base: this.base,
        anthropicAgentId: this.anthropicAgentId,
      });
      // Compile + validate each policy. A single malformed/dangerous policy
      // (bad action, ReDoS-prone regex) must NOT take down the whole ruleset:
      // skip it, report it, keep the rest. This matters because policies come
      // from the cloud (Guardian-generated) — they're not fully trusted input.
      const compiled = [];
      for (const p of policies) {
        try {
          compiled.push(compilePolicyFromFortress(p));
        } catch (e) {
          this.onError(new Error(`skipping invalid Fortress policy "${p?.rule_id || p?.name || '?'}": ${e.message}`));
        }
      }
      // v1.1.2 F-15 (P2 Codex audit): the policy evaluator is "first match
      // wins" (src/shield/policy.js evaluate()), so policy order matters.
      // Fortress validates `priority` server-side, but the API does not
      // contractually guarantee that the returned array is sorted by
      // priority. If a wide "allow" rule sat before a higher-priority
      // "deny" rule in the response, the deny would never fire. Sort
      // client-side by descending priority (higher priority first) before
      // assigning to ruleset. Policies without `priority` (or with equal
      // priorities) keep their relative order via the stable sort
      // guarantee in V8 — predictable behavior.
      compiled.sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0));
      this.ruleset = {
        version: 1,
        policies: compiled,
        default: { action: 'allow' },
      };
      this.lastFetchedAt = fetched_at;
      this.onRefresh({ policies: compiled, fetched_at, initial });
    } catch (e) {
      // On initial failure, propagate so the operator notices a config issue.
      // On subsequent failures, log and keep the previous cached ruleset.
      if (initial) throw e;
      this.onError(e);
    }
  }
}

// Convert a Fortress DB policy row to the local Shield format.
// Throws on anything invalid so _refresh can skip it (policies from the cloud
// are NOT fully trusted — apply the same hardening as the local JSON loader).
function compilePolicyFromFortress(p) {
  if (!p || typeof p !== 'object') throw new Error('policy is not an object');
  if (!VALID_ACTIONS.has(p.action)) {
    throw new Error(`unsupported action "${p.action}" (expected allow|deny|interrupt)`);
  }
  if (p.match != null && typeof p.match !== 'object') {
    throw new Error('match must be an object');
  }
  if (p.priority != null && (typeof p.priority !== 'number' || !Number.isFinite(p.priority))) {
    throw new Error(`priority must be a finite number (got ${p.priority})`);
  }
  const out = {
    id: p.rule_id,
    name: p.name,
    rationale: p.rationale,
    match: p.match || {},
    action: p.action,
    message: p.message,
    priority: p.priority ?? 100,
  };
  // Reuse the SAME ReDoS-safe compiler as the local JSON loader (rejects
  // catastrophic-backtracking patterns + over-long regexes). Previously this
  // path used a bare new RegExp(), bypassing those guards — a dangerous remote
  // regex could pin Shield's CPU.
  compileMatchRegexes(out.match);
  return out;
}

// Re-export matchesPolicy for convenience (callers can use the FortressPolicySource
// + the standard evaluate() from policy.js).
export { matchesPolicy };
