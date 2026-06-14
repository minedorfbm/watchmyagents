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
import { fortressEndpoint, guardedLookup } from '../../fortress/url.js';

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
      // v1.4.11 (Codex P1/P2): per-request DNS guard — reject a hostname that
      // resolves to a private/loopback/link-local IP (DNS rebinding), and pin
      // the connection to the checked address.
      lookup: guardedLookup,
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
 * @param {string} [opts.anthropicAgentId] - optional native agent id filter
 * @param {string} [opts.provider] - runtime provider (default 'anthropic-managed')
 * @returns {Promise<{ ok: true, policies: array, signing_keys: array, fetched_at: string }>}
 */
// v1.4.10: pure, testable get-policies URL builder. Always carries `provider`.
// The AGENT-ID PARAM NAME is provider-dependent and this matters:
//   - anthropic-managed → `agent_id` (legacy). Fortress resolves by
//     anthropic_agent_id, which works for ALL Anthropic agents including legacy
//     rows whose native_agent_id was never backfilled.
//   - other providers (openai-agents) → `native_agent_id` (canonical). Fortress
//     resolves by (provider, native_agent_id). This is REQUIRED: an OpenAI id is
//     not in the `agent_…` shape and its anthropic_agent_id is null. If we sent
//     it as `agent_id`, Fortress's `useLegacyLookup` (native absent + agent_id
//     present) forces the anthropic_agent_id lookup → the OpenAI agent isn't
//     found → empty policies → default-allow → enforcement SILENTLY OFF (a
//     fail-OPEN, worse than fail-closed). v1.4.9 had this bug.
export function buildGetPoliciesUrl(base, { anthropicAgentId, provider = 'anthropic-managed' } = {}) {
  let url = fortressEndpoint(base, 'get-policies');
  const params = [];
  if (anthropicAgentId) {
    const key = provider === 'anthropic-managed' ? 'agent_id' : 'native_agent_id';
    params.push(`${key}=${encodeURIComponent(anthropicAgentId)}`);
  }
  params.push(`provider=${encodeURIComponent(provider)}`);
  url += (url.includes('?') ? '&' : '?') + params.join('&');
  return url;
}

export async function fetchPolicies({ apiKey, base, anthropicAgentId, provider = 'anthropic-managed' }) {
  const url = buildGetPoliciesUrl(base, { anthropicAgentId, provider });
  const { status, body } = await httpsJson('GET', url, {
    authorization: `Bearer ${apiKey}`,
    accept: 'application/json',
  });
  if (status === 200 && body && body.ok) {
    return {
      ok: true,
      policies: body.policies || [],
      // v1.1.5 Phase 1.5 — the chain-of-trust: signing keys travel
      // with the response, each signed by the embedded root pubkey.
      // Older Fortress deployments that haven't shipped the signing
      // pipeline yet just won't include this field — the verifier
      // then drops every policy as "unknown signing_key_id" and
      // operators see the gap immediately.
      signing_keys: body.signing_keys || [],
      fetched_at: body.fetched_at,
    };
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
// v1.1.5 Phase 1.5 — signature verification on the cloud path.
import { verifyPolicyBundle, importEd25519PublicKey } from '../signature.js';
import { WMA_FORTRESS_ROOT_PUBKEY_B64, WMA_FORTRESS_ROOT_IS_PLACEHOLDER } from '../root-key.js';

const VALID_ACTIONS = new Set(['allow', 'deny', 'interrupt']);

// v1.1.5 Phase 1.5 — strict-by-default signature verification.
// Set WMA_REQUIRE_SIGNED_POLICIES=false to accept unsigned policies
// from Fortress with a loud warning at each refresh. This is an escape
// hatch for ops emergencies (e.g. Fortress signing pipeline temporarily
// down) and dev/CI workflows where a staging Fortress hasn't been
// upgraded yet. Default is strict to honour the security stance chosen
// for v1.1.5.
function strictModeFromEnv() {
  const v = process.env.WMA_REQUIRE_SIGNED_POLICIES;
  if (v == null) return true;        // unset → strict by default
  if (v === 'false' || v === '0') return false;
  return true;
}

// v1.4.2 F-48 (P2 audit) — what to do when a SUCCESSFUL refresh yields zero
// usable policies even though Fortress SENT some (i.e. every policy was
// dropped by signature verification or compile validation). 'closed' (the
// default, the right stance for a security control) refuses to install an
// empty allow-everything ruleset; 'open' preserves the pre-F-48 behavior
// (install default-allow) as an explicit opt-out.
function failModeFromEnv() {
  const v = process.env.WMA_SHIELD_FAIL_MODE;
  if (v === 'open') return 'open';
  return 'closed';                   // unset / anything else → fail-closed
}

// Parse the embedded root pubkey ONCE at module load. If the file still
// carries the placeholder, we DO NOT throw — but every refresh logs a
// loud reminder so an unattended deploy can't silently trust a key whose
// private counterpart is in the git history.
const ROOT_PUBLIC_KEY = (() => {
  try {
    return importEd25519PublicKey(WMA_FORTRESS_ROOT_PUBKEY_B64);
  } catch (e) {
    // The placeholder string isn't valid base64 of 32 bytes, so import
    // will throw. That's the desired behaviour during development —
    // verification will fail-closed until the real key is embedded.
    return null;
  }
})();

export class FortressPolicySource {
  constructor({ apiKey, base, anthropicAgentId, provider = 'anthropic-managed', refreshIntervalMs = 5 * 60_000, onError, onRefresh, requireSignedPolicies, failMode }) {
    if (!apiKey) throw new Error('FortressPolicySource: apiKey required');
    if (!base) throw new Error('FortressPolicySource: base URL required');
    this.apiKey = apiKey;
    this.base = base;
    this.anthropicAgentId = anthropicAgentId;
    // v1.4.9: runtime provider, sent to get-policies so Fortress scopes by
    // (provider, native_agent_id). Defaults to anthropic-managed (the Anthropic
    // shield path doesn't pass it); the OpenAI factory passes 'openai-agents'.
    this.provider = provider;
    this.refreshIntervalMs = refreshIntervalMs;
    this.onError = onError || (() => {});
    this.onRefresh = onRefresh || (() => {});
    this.ruleset = { version: 1, policies: [], default: { action: 'allow' } };
    this.lastFetchedAt = null;
    this._timer = null;
    this._aborted = false;
    // v1.4.2 F-48: tracks whether this.ruleset came from a non-degraded
    // refresh (so a later all-dropped refresh can retain last-known-good
    // instead of wiping it) vs. is still the constructor's default-allow.
    this._installedFromRefresh = false;
    // v1.1.5: per-instance override of the env var. Tests use this to
    // exercise both modes without touching process.env. If neither the
    // constructor option nor the env var is set, strict mode wins.
    this.requireSignedPolicies = requireSignedPolicies != null
      ? !!requireSignedPolicies
      : strictModeFromEnv();
    // v1.4.2 F-48: 'closed' (default) | 'open'. Per-instance override for tests.
    this.failMode = failMode != null ? failMode : failModeFromEnv();
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

  // v1.4.2 F-48: injectable fetch seam (tests override this to drive _refresh
  // hermetically). Production hits the real Fortress endpoint.
  async _fetchPolicies() {
    return fetchPolicies({
      apiKey: this.apiKey,
      base: this.base,
      anthropicAgentId: this.anthropicAgentId,
      provider: this.provider,
    });
  }

  async _refresh({ initial = false } = {}) {
    if (this._aborted) return;
    try {
      const { policies, signing_keys, fetched_at } = await this._fetchPolicies();

      // v1.1.5 Phase 1.5 — verify the chain-of-trust BEFORE any other
      // processing. We must verify on the raw JSON shape sent by Fortress,
      // not on the post-compile form, because compileMatchRegexes mutates
      // `match` in place (adds _regex / _not_regex KeyObjects) and the
      // signed canonical payload would no longer match.
      const verifiedPolicies = this._verifyAndFilter(policies, signing_keys);

      // Compile + validate each VERIFIED policy. A single malformed/dangerous
      // policy (bad action, ReDoS-prone regex) must NOT take down the whole
      // ruleset: skip it, report it, keep the rest. This matters because
      // even after signature verification the rule shape can be wrong
      // (server-side signing happened on a payload the SDK doesn't accept).
      const compiled = [];
      for (const p of verifiedPolicies) {
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

      // v1.4.2 F-48 (P2 audit): FAIL-CLOSED on a "successful" refresh that
      // dropped EVERYTHING. If Fortress SENT policies (policies.length > 0)
      // but none survived verification/compile (compiled.length === 0), an
      // on-path attacker or a broken signing pipeline has effectively
      // disarmed Shield — installing the empty { default: allow } ruleset
      // here would silently allow every action while the daemon looks
      // healthy. We distinguish this from a LEGITIMATELY empty response
      // (operator cleared all policies → policies.length === 0 → install
      // allow as intended).
      const allDropped = policies.length > 0 && compiled.length === 0;
      if (allDropped && this.failMode === 'closed') {
        this.lastFetchedAt = fetched_at;
        if (this._installedFromRefresh) {
          // We have a last-known-good ruleset → KEEP it; do not overwrite
          // with allow-everything. Protection continues on the prior rules.
          this.onError(new Error(
            `Fortress refresh: all ${policies.length} policies failed verification/compile — ` +
            'FAIL-CLOSED, retaining last-known-good ruleset (set WMA_SHIELD_FAIL_MODE=open to override).',
          ));
          this.onRefresh({ policies: this.ruleset.policies, fetched_at, initial, failClosed: true });
        } else {
          // No prior good ruleset (e.g. initial load) → cannot fall back to
          // allow-everything for a security control. Install deny-by-default
          // so unmatched actions are denied rather than waved through.
          this.ruleset = { version: 1, policies: [], default: { action: 'deny' } };
          this.onError(new Error(
            `Fortress refresh: all ${policies.length} policies failed verification/compile and there is no ` +
            'prior ruleset — FAIL-CLOSED to deny-by-default (set WMA_SHIELD_FAIL_MODE=open to override).',
          ));
          this.onRefresh({ policies: [], fetched_at, initial, failClosed: true });
        }
        return;
      }

      this.ruleset = {
        version: 1,
        policies: compiled,
        default: { action: 'allow' },
      };
      this._installedFromRefresh = true;
      this.lastFetchedAt = fetched_at;
      this.onRefresh({ policies: compiled, fetched_at, initial });
    } catch (e) {
      // On initial failure, propagate so the operator notices a config issue.
      // On subsequent failures, log and keep the previous cached ruleset.
      if (initial) throw e;
      this.onError(e);
    }
  }

  // v1.1.5 Phase 1.5 — verify the Fortress chain of trust on a refresh
  // response. Returns the array of policies that pass the gate (verified
  // signatures in strict mode, OR all policies in lax mode with a warning
  // per unsigned one).
  //
  // FAIL MODES:
  //   - ROOT key is the placeholder (release wasn't ceremony-completed):
  //     emit a one-line WARNING at each refresh and skip verification
  //     entirely — better than silently trusting a known-compromised key.
  //   - Strict (default): drop every policy that doesn't verify; log each
  //     drop reason via onError so the operator sees the gap.
  //   - Lax (WMA_REQUIRE_SIGNED_POLICIES=false): keep every policy but
  //     emit a WARNING per unsigned one — gives migration slack while
  //     making the audit trail visible.
  _verifyAndFilter(rawPolicies, rawSigningKeys) {
    if (WMA_FORTRESS_ROOT_IS_PLACEHOLDER || ROOT_PUBLIC_KEY == null) {
      this.onError(new Error(
        'FortressPolicySource: ROOT_PUBLIC_KEY is the placeholder (not a real Fortress root). ' +
        'Signature verification SKIPPED. This is the expected state during development; ' +
        'NEVER ship this configuration to production.'
      ));
      return rawPolicies || [];
    }
    const bundle = verifyPolicyBundle({
      policies: rawPolicies || [],
      signingKeys: rawSigningKeys || [],
      rootPublicKey: ROOT_PUBLIC_KEY,
    });
    for (const ke of bundle.signingKeyErrors) {
      this.onError(new Error(`FortressPolicySource: rejected signing key "${ke.kid}": ${ke.reason}`));
    }
    for (const dp of bundle.droppedPolicies) {
      const verb = this.requireSignedPolicies ? 'DROPPING' : 'WARNING (lax mode)';
      this.onError(new Error(`FortressPolicySource: ${verb} policy "${dp.rule_id}": ${dp.reason}`));
    }
    if (this.requireSignedPolicies) {
      return bundle.validPolicies;
    }
    // Lax mode: keep every raw policy but the loud warnings above let
    // ops see what would be dropped in strict mode.
    return rawPolicies || [];
  }
}

// Convert a Fortress DB policy row to the local Shield format.
// Throws on anything invalid so _refresh can skip it (policies from the cloud
// are NOT fully trusted — apply the same hardening as the local JSON loader).
// v1.1.3 Phase 1.D — same modes as the local JSON loader.
const VALID_MODES = new Set(['enforce', 'shadow']);

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
  // v1.1.3 Phase 1.D — accept `mode` from Fortress rows (added by Lovable
  // when the companion prompt deploys the schema column). Default to
  // 'enforce' for backwards compat: existing Fortress instances without
  // the `mode` column yield policies that enforce, as they always have.
  const mode = p.mode ?? 'enforce';
  if (!VALID_MODES.has(mode)) {
    throw new Error(`unsupported mode "${mode}" (expected enforce|shadow)`);
  }
  const out = {
    id: p.rule_id,
    name: p.name,
    rationale: p.rationale,
    match: p.match || {},
    action: p.action,
    message: p.message,
    priority: p.priority ?? 100,
    mode,
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
