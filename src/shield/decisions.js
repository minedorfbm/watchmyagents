// Shield decisions logger.
//
// Writes one NDJSON line per Shield decision into the same daily-rotated
// file as Watch, with action_type: "shield_decision". This closes the
// recursive loop trivially — the next wma-fetch / wma-inspect run will
// surface Shield's actions alongside the agent's actions.

import { Logger } from '../logger.js';

export class DecisionLogger {
  constructor({ logDir, agentId, sessionId }) {
    this._logger = new Logger({ logDir, agentId, sessionId, silent: true });
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
  }) {
    return this._logger.write({
      action_type: 'shield_decision',
      framework: 'anthropic-managed',
      tool_name: sourceEvent?.name || sourceEvent?.tool_name || null,
      status: decision === 'deny' || decision === 'interrupt' ? 'error' : 'ok',
      error: decision === 'deny' || decision === 'interrupt' ? message : null,
      duration_ms: decidedInMs ?? null,
      input: {
        source_event_id: sourceEvent?.id || null,
        source_event_type: sourceEvent?.type || null,
        tool_input: sourceEvent?.input ?? null,
      },
      output: {
        decision,
        rule_id: ruleId,
        rule_name: ruleName,
        message,
      },
    });
  }
}
