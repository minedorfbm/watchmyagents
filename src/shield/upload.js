// Shield → Fortress decision payload builder.
// v1.1.4 F-19 (P1 Codex audit): pure helper extracted from scripts/shield.js
// so the egress-side containment can be unit-tested in isolation. The
// security invariant under test:
//
//   nothing on this payload may carry raw customer identifiers — tool
//   names, session ids, event ids, input values must either be in the
//   documented allowlist (vendor built-ins) or salted-hashed.
//
// Anything that can't be safely normalized is DROPPED (set to undefined)
// rather than passed through. Decision still ships so Fortress can count
// it — only the leak-y field is omitted.

import { createHash } from 'node:crypto';
import { normalizeToolName } from '../anonymizer.js';

// Salted SHA-256 hash with the same 32-char truncation as the anonymizer
// and the rest of Shield's decision flow. Returns null for nullish input
// or when no salt is configured (fail-safe omission).
function hashWithSaltOpt(value, salt) {
  if (value == null || !salt) return null;
  const s = typeof value === 'string' ? value : JSON.stringify(value);
  return 'sha256:' + createHash('sha256').update(salt).update(s).digest('hex').slice(0, 32);
}

// Extract the most relevant input value to fingerprint (URL > command >
// query > path > file_path). The actual hashing is done downstream by
// hashIoc — this function only picks the IoC field.
function pickInputForHash(input) {
  if (!input || typeof input !== 'object') return null;
  return input.url || input.command || input.query || input.path || input.file_path || null;
}

/**
 * Build the body POSTed to Fortress's ingest-decisions endpoint.
 *
 * Containment guarantees:
 *   - tool_name: vendor allowlist returned in clear; custom/MCP names
 *     return as "tool_hash:<32hex>" when a salt is configured; dropped
 *     entirely otherwise.
 *   - session_hash / event_id_hash / input_hash: salted SHA-256, omitted
 *     when no salt is configured.
 *   - Raw payload values (rawEvent.input, normalized.input) never
 *     appear on the wire — only their hashes do.
 *
 * @param {object} opts
 * @param {string} opts.agentId - Anthropic agent id (already an opaque token)
 * @param {string} opts.sessionId - Anthropic session id (hashed before egress)
 * @param {object} opts.rawEvent  - raw upstream event (id field is hashed)
 * @param {object} opts.normalized - normalized event from normalizeForPolicy()
 * @param {object} opts.result    - policy evaluator output
 * @param {number} opts.decidedInMs
 * @param {string|null|undefined} opts.signalsSalt
 * @param {string} [opts.decidedAtIso] - ISO 8601 timestamp; defaults to now()
 * @returns {object} payload ready to POST to ingest-decisions
 */
export function buildFortressDecisionPayload({
  agentId, sessionId, rawEvent, normalized, result, decidedInMs,
  signalsSalt, decidedAtIso,
  // v1.4.2 F-44 (P1 audit): the real enforcement outcome (true delivered /
  // false failed / undefined n/a). Lets the Fortress dashboard distinguish a
  // confirmed block from one whose API call failed — i.e. surface degraded
  // enforcement instead of trusting the computed verdict. Boolean only; no
  // raw content, so Containment is unaffected.
  enforcementDelivered,
}) {
  // F-19: vendor built-ins survive even without a salt (allowlist short-circuit);
  // custom tool names throw without a salt — we catch and drop the field.
  let safeToolName;
  const rawToolName = normalized?.tool_name;
  if (rawToolName) {
    try {
      safeToolName = normalizeToolName(rawToolName, signalsSalt);
    } catch {
      safeToolName = undefined;
    }
  }

  return {
    anthropic_agent_id: agentId,
    decision: result.decision,
    rule_id: result.rule_id || undefined,
    session_hash: hashWithSaltOpt(sessionId, signalsSalt) || undefined,
    event_id_hash: hashWithSaltOpt(rawEvent?.id, signalsSalt) || undefined,
    input_hash: hashWithSaltOpt(pickInputForHash(normalized?.input), signalsSalt) || undefined,
    action_type: normalized?.action_type || undefined,
    tool_name: safeToolName,
    message: result.message || result.rule_name || undefined,
    decided_at: decidedAtIso || new Date().toISOString(),
    decided_in_ms: decidedInMs,
    // v1.1.3 Phase 1.D: mode threading so Fortress can store and surface
    // shadow-vs-enforce in the Reports timeline.
    mode: result.mode || undefined,
    // v1.4.2 F-44: real enforcement outcome (omitted when not applicable).
    enforcement_delivered: enforcementDelivered === undefined ? undefined : enforcementDelivered,
  };
}
