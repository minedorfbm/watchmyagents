// Shield context tracker — v1.2.0.
//
// Computes runtime attributes that policy rules can evaluate alongside
// the event payload itself. This closes the "context-aware authorization"
// gap called out in Anthropic's May 2026 agentic security framework
// (Part IV §Phase 4): a policy isn't just "what is the agent doing right
// now" but also "what hour is it, how long has this agent been running,
// has it been throwing a lot of errors lately".
//
// The tracker is stateful per session and lives in the Shield process. It
// holds only short summaries — no payloads. Containment is preserved:
// nothing here leaves the customer machine. See [[project_containment_architecture]].
//
// Computed attributes exposed via compute(event) → ctx:
//   - hour_of_day_utc      number 0..23
//   - day_of_week_utc      number 0..6 (Sunday=0)
//   - agent_age_minutes    minutes since the first event observed in this tracker
//   - session_duration_ms  milliseconds since the first event in this tracker
//   - recent_error_rate    fraction 0..1 over the trailing window (PRIOR events
//                          only — the current event isn't counted, so a rule
//                          like "deny if recent_error_rate > 0.5" reflects
//                          the agent's RECENT track record, not itself)
//   - event_count_recent   number of events in the trailing window
//   - event_count_total    total events seen by the tracker
//
// Usage:
//   const tracker = createContextTracker({ recentWindowSize: 20 });
//   for each event {
//     const ctx = tracker.compute(event);
//     const result = evaluate(event, ruleset, ctx);
//     tracker.record(event, { isError: result.decision === 'deny' });
//   }
//
// Order matters: compute() BEFORE evaluate(), record() AFTER. That way
// recent_error_rate describes the past, not the present, and the rule
// is self-consistent.

const DEFAULT_RECENT_WINDOW = 20;

function defaultIsError(event) {
  // Heuristic: treat as error if the event carries an explicit error
  // marker. We deliberately don't synthesize errors from missing fields
  // — false negatives here just mean recent_error_rate underestimates,
  // which is the safe direction. Callers can pass an explicit isError
  // to record() to override.
  if (!event || typeof event !== 'object') return false;
  if (event.is_error === true) return true;
  if (event.error != null) return true;
  if (typeof event.type === 'string' && event.type.includes('error')) return true;
  // tool_result with error content
  if (Array.isArray(event.content)) {
    for (const part of event.content) {
      if (part && part.type === 'tool_result' && part.is_error === true) return true;
    }
  }
  return false;
}

export function createContextTracker(options = {}) {
  const recentWindowSize = options.recentWindowSize ?? DEFAULT_RECENT_WINDOW;
  // Clock injection — Date.now is forbidden in some sandboxes (e.g.
  // workflow scripts) and pinning is essential for testability. Callers
  // can pass options.now = () => fixedEpoch to control the perceived time.
  const now = options.now ?? (() => Date.now());

  // v1.2.0: cap the window to avoid runaway memory if a caller passes
  // something like 1_000_000. The realistic ceiling for "recent" is in
  // the low thousands — anything bigger is no longer "recent" anyway.
  if (!Number.isInteger(recentWindowSize) || recentWindowSize < 1 || recentWindowSize > 10_000) {
    throw new Error(`createContextTracker: recentWindowSize must be an integer in [1, 10000], got ${recentWindowSize}`);
  }

  let firstSeenMs = null;          // ms epoch of the first observation
  let totalCount = 0;              // total events seen
  const recent = [];               // ring buffer of booleans (true = error)
  let errorsInWindow = 0;          // O(1) sum so compute() stays fast

  return {
    // Build a ctx object for the given event. Pure read — no state change.
    // Pass an optional `at` (ms epoch) to override the clock for this
    // call (rare; used by replay scenarios).
    compute(event, at) {
      const nowMs = Number.isFinite(at) ? at : now();
      const wallClock = Number.isFinite(at) ? new Date(at) : new Date(nowMs);
      const ageMs = firstSeenMs == null ? 0 : Math.max(0, nowMs - firstSeenMs);
      const denom = recent.length;
      return {
        hour_of_day_utc: wallClock.getUTCHours(),
        day_of_week_utc: wallClock.getUTCDay(),
        agent_age_minutes: Math.floor(ageMs / 60_000),
        session_duration_ms: ageMs,
        recent_error_rate: denom === 0 ? 0 : errorsInWindow / denom,
        event_count_recent: denom,
        event_count_total: totalCount,
      };
    },

    // Update tracker with the outcome of `event`. Call AFTER compute() +
    // evaluate() for the current event so its outcome enters the window
    // for the NEXT compute() call.
    //
    // Options:
    //   isError  explicit error flag (boolean). When omitted, falls back
    //            to the default heuristic on the event itself.
    record(event, options = {}) {
      if (firstSeenMs == null) firstSeenMs = now();
      totalCount += 1;

      const isError = typeof options.isError === 'boolean'
        ? options.isError
        : defaultIsError(event);

      recent.push(isError);
      if (isError) errorsInWindow += 1;

      // Evict from the head until we're back at window size.
      while (recent.length > recentWindowSize) {
        const dropped = recent.shift();
        if (dropped) errorsInWindow -= 1;
      }
    },

    // Reset all state. Useful at the start of a fresh session, or for
    // tests that want a clean tracker between cases.
    reset() {
      firstSeenMs = null;
      totalCount = 0;
      recent.length = 0;
      errorsInWindow = 0;
    },
  };
}

// Exported for tests + callers who want the same heuristic without going
// through a tracker (e.g. one-off classification).
export { defaultIsError };
