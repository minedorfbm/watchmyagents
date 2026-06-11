// Shield decisions logger.
//
// Writes one NDJSON line per Shield decision into the same daily-rotated
// file as Watch, with action_type: "shield_decision". This closes the
// recursive loop trivially — the next wma-fetch / wma-inspect run will
// surface Shield's actions alongside the agent's actions.
//
// v1.2.0 — every shield_decision row carries a SHA-256 audit chain
// (prev_hash + chain_hash). Watch rows in the same file carry no chain
// fields, so verifyDecisionChain() must be given the filtered subset
// `records.filter(r => r.action_type === 'shield_decision')`. See
// src/shield/decision-chain.js for the chain format + verifier.

import { Logger } from '../logger.js';
import { createDecisionChain, buildGenesisMarker, newChainId } from './decision-chain.js';

export class DecisionLogger {
  // v1.3.1 F-29 (P1 Codex audit on v1.3.0): `provider` is now an
  // explicit constructor option. Before v1.3.1 the provider was
  // hard-coded to `anthropic-managed` in record() — when the OpenAI
  // Agents SDK adapter (shipped v1.3.0) wrote shield_decision rows
  // through this logger, those rows were mis-attributed to Anthropic.
  // Fortress / Guardian forensic surfaces saw OpenAI blocks as
  // Anthropic blocks. Default is preserved at `anthropic-managed` so
  // existing v1.2.x callers behave unchanged; the OpenAI adapter
  // explicitly passes `provider: PROVIDERS.OPENAI_AGENTS`.
  constructor({ logDir, agentId, sessionId, provider }) {
    this._provider = provider || 'anthropic-managed';
    // Each DecisionLogger instance owns a single chain segment. A Shield
    // restart creates a fresh DecisionLogger → fresh genesis. The
    // genesis marker is self-describing (agent + session + start time +
    // chain id) so forensics can attribute segments to processes.
    const chain = createDecisionChain({
      genesis: buildGenesisMarker({
        agentId,
        sessionId,
        startedAtIso: new Date().toISOString(),
        chainId: newChainId(),
      }),
    });
    this._logger = new Logger({ logDir, agentId, sessionId, silent: true, chain });
  }

  // Record a decision Shield made about an upstream event. Shield's own
  // action_type is 'shield_decision' — this lets aggregations (wma-inspect)
  // distinguish them from the agent's own actions.
  async record({
    sourceEvent,      // the original Anthropic event we decided on (for context)
    decision,         // 'allow' | 'deny' | 'interrupt'
    ruleId,
    ruleName,
    message,
    decidedInMs,
    mode,             // v1.1.3 Phase 1.D: 'enforce' | 'shadow' (default 'enforce' if absent)
    // v1.4.2 F-44 (P1 audit): the ACTUAL outcome of the enforcement API call,
    // captured by the caller AFTER it attempts confirmDeny / interruptSession.
    //   true      → the block/interrupt landed (confirmed delivered)
    //   false     → the call FAILED after retries; the violating action was
    //               NOT blocked on the wire (silent fail-open if we lied here)
    //   undefined → not applicable (allow / shadow / non-enforcing caller).
    // Pre-F-44 the row claimed "enforced" purely from mode+decision, before
    // (and regardless of) the API call — so the tamper-evident audit chain
    // could assert a block that never happened.
    enforcementDelivered,
  }) {
    // In shadow mode the decision is computed and logged but NOT enforced.
    // status must reflect what actually happened on the wire: shadow + deny
    // didn't actually block, so status='ok' keeps Watch's aggregations honest.
    // output.mode is what calibration reads to compare would-have-blocked vs
    // did-block.
    const effectiveMode = mode || 'enforce';
    const enforced = effectiveMode === 'enforce'
      && (decision === 'deny' || decision === 'interrupt');
    // F-44: enforcement was ATTEMPTED but FAILED → the action was NOT blocked.
    // Surface that honestly instead of recording a clean block.
    const failedDelivery = enforced && enforcementDelivered === false;

    const output = {
      decision,
      rule_id: ruleId,
      rule_name: ruleName,
      message,
      mode: effectiveMode,
    };
    // Only add the field when enforcement was actually attempted, so allow /
    // shadow / pre-F-44 callers keep their exact record shape.
    if (enforcementDelivered !== undefined) {
      output.enforcement_delivered = enforcementDelivered;
    }

    return this._logger.write({
      action_type: 'shield_decision',
      provider: this._provider,
      tool_name: sourceEvent?.name || sourceEvent?.tool_name || null,
      status: enforced ? 'error' : 'ok',
      error: failedDelivery
        ? `ENFORCEMENT FAILED (action NOT blocked): ${message || ruleName || 'policy violation'}`
        : (enforced ? message : null),
      duration_ms: decidedInMs ?? null,
      input: {
        source_event_id: sourceEvent?.id || null,
        source_event_type: sourceEvent?.type || null,
        tool_input: sourceEvent?.input ?? null,
      },
      output,
    });
  }
}
