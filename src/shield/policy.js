// Shield policy engine — JSON parser + match evaluator.
// Zero dependencies. JSON intentionally over YAML to keep the SDK dep-free.
//
// Match spec format (matches the future Fortress JSONB schema):
//
//   {
//     "match": {
//       "action_type": "tool_use",
//       "tool_name": { "not_in": ["web_search", "web_fetch"] },
//       "input.url": { "not_regex": "^https://(github|wikipedia)\\.com/" }
//     },
//     "action": "deny",
//     "message": "..."
//   }
//
// Supported conditions on a field value:
//   - literal value         → strict equality
//   - { in: [...] }         → value must be in the list
//   - { not_in: [...] }     → value must NOT be in the list
//   - { regex: "..." }      → string match against the regex
//   - { not_regex: "..." }  → string must NOT match the regex
//   - { regex_any: [...] }  → string matches at least one of the regexes
//
// Field paths use dotted notation (`input.url`, `output.content.text`).

import { readFile } from 'node:fs/promises';

export async function loadPolicies(path) {
  const raw = await readFile(path, 'utf8');
  const data = JSON.parse(raw);
  if (!data.policies || !Array.isArray(data.policies)) {
    throw new Error(`policy file ${path} has no "policies" array`);
  }
  // Pre-compile regex for performance + early failure on bad patterns.
  const VALID_ACTIONS = ['allow', 'deny', 'interrupt'];
  // v1.1.3 Phase 1.D — policy mode: 'enforce' (default) actually enforces
  // the decision via the Anthropic API; 'shadow' computes the decision
  // and logs it but skips enforcement. Shadow is the calibration bench
  // for Guardian Core scoring (Platt scaling, diff-in-diff efficacy)
  // and a safe staging step for new policies before promoting to enforce.
  const VALID_MODES = ['enforce', 'shadow'];
  for (const p of data.policies) {
    compileMatchRegexes(p.match || {});
    if (!VALID_ACTIONS.includes(p.action)) {
      throw new Error(`policy ${p.id || p.name}: unsupported action "${p.action}"`);
    }
    // Default to 'enforce' if mode is omitted → preserves v1.0.x / v1.1.x
    // behavior for policies authored before shadow mode existed.
    if (p.mode == null) p.mode = 'enforce';
    if (!VALID_MODES.includes(p.mode)) {
      throw new Error(`policy ${p.id || p.name}: unsupported mode "${p.mode}" (must be one of: ${VALID_MODES.join(', ')})`);
    }
  }
  // v1.1.2 F-14 (P2 Codex audit): validate the ruleset's default.action
  // against the SAME canonical set as per-policy actions. Before this fix
  // a typo like `default: { action: "drop" }` was accepted silently — at
  // evaluation time evaluate() returned `decision: "drop"`, which the
  // interrupt-mode runtime treated as a no-op (only deny/interrupt trigger
  // termination) and the tool_confirmation-mode runtime left dangling
  // (no allow/deny event sent). Either way the agent ran without
  // enforcement, exactly opposite of the operator's intent.
  data.default = data.default || { action: 'allow' };
  if (!VALID_ACTIONS.includes(data.default.action)) {
    throw new Error(
      `policy file ${path} default.action "${data.default.action}" is invalid — must be one of: ${VALID_ACTIONS.join(', ')}`,
    );
  }
  return data;
}

// ReDoS protection: regexes are loaded from a user-provided JSON policy file
// (LOCAL adapter) AND from Fortress / Guardian-generated rules (FORTRESS
// adapter), so a malicious or buggy pattern (e.g. `(a+)+$`) could pin
// Shield's CPU on a long input — taking the whole enforcement loop down.
// We mitigate three ways:
//   1) Cap the maximum input length passed to any regex test to MAX_REGEX_INPUT
//      bytes. Above that we truncate before testing. Real agent values
//      (URLs, commands, queries, file paths) are well under this in practice.
//   2) Reject obviously dangerous patterns at compile time (heuristic — see
//      SUSPICIOUS_REGEX_PATTERNS below). The list errs toward false positives
//      because Shield runs in the hot path: a rejected rule is loud (the
//      rule is dropped at load time with a clear error) while a runaway
//      regex would silently degrade Shield to "no enforcement" until the
//      operator notices a CPU spike.
//   3) Hard upper bound on the regex source length so a deeply nested
//      pattern can't game the heuristic by spreading the gadget across
//      thousands of chars.
//
// Future work (v1.2+): proper RE2 or safe-regex-2 dependency for thorough
// analysis, or moving evaluation into a worker with a hard CPU timeout.
// We can't ship that today without breaking the zero-runtime-deps promise.
//
// v1.1.4 F-20 (P2 Codex audit): cap reduced from 8192 → 2048 (4×). Worst
// realistic IoC values (URL with long query string, base64 in a path)
// remain comfortably under 2048; the previous 8192 was a defence-in-depth
// holdover that no real workload exercises.
const MAX_REGEX_INPUT = 2048;

// v1.1.4 F-20: heuristic list extended to catch ambiguous alternation
// (`(a|a)*`, `(a|ab)+`, `(.|.)*`) — these don't trip the existing
// nested-quantifier heuristic but exhibit the same exponential behavior
// because every char has two paths to match. The new pattern rejects any
// alternation group immediately followed by `+` or `*`; this is intentionally
// over-broad — a customer who needs `(http|https):` should use either a
// character class (`[a-z]+:`) or move the optional letter (`https?:`).
const SUSPICIOUS_REGEX_PATTERNS = [
  /(\([^)]*[+*][^)]*\))[+*]/,   // (x+)+ or (x*)* — classic catastrophic backtracking
  /(\.\*){3,}/,                  // multiple .* in a row
  // F-20: alternation inside a group, then `+` or `*` — `(a|a)*`, `(a|ab)+`,
  // `(.|.)*`. The `[^)]*\|[^)]*` body requires at least one `|` inside the
  // group; a single-branch group like `(foo)+` is NOT matched.
  /\([^)]*\|[^)]*\)[+*]/,
];

export function validateRegexString(src, where) {
  if (typeof src !== 'string') {
    throw new Error(`policy ${where}: regex must be a string`);
  }
  // v1.1.4 F-20: cap regex source at 1024 chars (was 2000). Real Shield
  // policies are short (URL-prefix match, host-list deny, command-prefix
  // check). A 1KB regex source is already an outlier; anything longer is
  // either pathological or trying to bypass the heuristics by smuggling
  // a gadget across many bytes.
  if (src.length > 1024) {
    throw new Error(`policy ${where}: regex too long (>1024 chars)`);
  }
  for (const sus of SUSPICIOUS_REGEX_PATTERNS) {
    if (sus.test(src)) {
      throw new Error(`policy ${where}: regex looks vulnerable to catastrophic backtracking ("${src.slice(0, 60)}…"). Refusing to load.`);
    }
  }
  return new RegExp(src);
}

export function compileMatchRegexes(match) {
  for (const [field, condition] of Object.entries(match)) {
    if (condition && typeof condition === 'object') {
      if (condition.regex) condition._regex = validateRegexString(condition.regex, `${field}.regex`);
      if (condition.not_regex) condition._not_regex = validateRegexString(condition.not_regex, `${field}.not_regex`);
      if (condition.regex_any) {
        condition._regex_any = condition.regex_any.map((r, i) =>
          validateRegexString(r, `${field}.regex_any[${i}]`));
      }
    }
  }
}

function getNested(obj, path) {
  return path.split('.').reduce((o, k) => (o == null ? undefined : o[k]), obj);
}

// Truncate input before passing to regex test — guards against ReDoS on
// pathologically long values (e.g. an agent that pastes a 5MB string into
// a tool argument).
function safeRegexTest(re, value) {
  if (typeof value !== 'string') return false;
  const s = value.length > MAX_REGEX_INPUT ? value.slice(0, MAX_REGEX_INPUT) : value;
  return re.test(s);
}

function matchValue(value, condition) {
  // Literal scalar match
  if (condition === null || typeof condition !== 'object') {
    return value === condition;
  }
  if (Array.isArray(condition)) {
    return condition.includes(value);
  }
  if (condition.in !== undefined) return condition.in.includes(value);
  if (condition.not_in !== undefined) return !condition.not_in.includes(value);
  if (condition._regex !== undefined) {
    return safeRegexTest(condition._regex, value);
  }
  if (condition._not_regex !== undefined) {
    return typeof value === 'string' && !safeRegexTest(condition._not_regex, value);
  }
  if (condition._regex_any !== undefined) {
    return condition._regex_any.some(r => safeRegexTest(r, value));
  }
  // Unknown condition shape — defensive: fail-closed (no match) so unknown
  // conditions never silently allow events.
  return false;
}

// Evaluate a single policy against an event. Returns true iff every match
// clause is satisfied. A match clause with an undefined target field still
// counts as "no match" rather than "any match".
export function matchesPolicy(event, policy) {
  for (const [field, condition] of Object.entries(policy.match || {})) {
    const value = getNested(event, field);
    if (!matchValue(value, condition)) return false;
  }
  return true;
}

// First-match-wins evaluation. Returns the policy decision and metadata.
export function evaluate(event, ruleset) {
  for (const policy of ruleset.policies) {
    if (matchesPolicy(event, policy)) {
      return {
        decision: policy.action,
        rule_id: policy.id || null,
        rule_name: policy.name || null,
        message: policy.message || null,
        // v1.1.3 Phase 1.D — `mode` propagated so the Shield runtime can
        // decide whether to actually call the Anthropic enforcement API
        // (mode=enforce) or just log the would-be decision (mode=shadow).
        mode: policy.mode || 'enforce',
      };
    }
  }
  return {
    decision: ruleset.default?.action || 'allow',
    rule_id: null,
    rule_name: '(default)',
    message: null,
    // The ruleset-level default has no shadow concept — defaults always
    // enforce (or, when the default is 'allow', do nothing of consequence).
    mode: 'enforce',
  };
}
