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
import { TOOL_USE_FAMILY } from '../sources/contract.js';

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
    // v1.1.5 Phase 1.5 — mark every local-file policy so the signature
    // verifier (src/shield/signature.js) bypasses the Ed25519 chain on
    // these rows. Today the local path and the Fortress path are entirely
    // separate (loadPolicies → local ruleset; FortressPolicySource →
    // cloud ruleset) so this marker is a safety net for future refactors
    // that might mix them. It also documents intent at read time.
    p.__local = true;
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

// v1.4.3 F-40: coerce ONLY a clean decimal-number string to a number, for the
// ordered numeric comparators. Anything else (real number → passthrough;
// hex/exponent/whitespace/Infinity/non-string → returned as-is so the caller's
// Number.isFinite check fails closed). Never used for equality or length_*.
const CLEAN_NUMERIC_STRING = /^-?\d+(\.\d+)?$/;
function asOrderedNumber(value) {
  if (typeof value === 'number') return value;
  if (typeof value === 'string' && CLEAN_NUMERIC_STRING.test(value)) return Number(value);
  return value;
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
  // v1.2.0 — DSL extensions for ABAC / parameter validation.
  // Numeric comparators reject a non-finite CONDITION operand (malformed
  // policy → fail-closed).
  //
  // v1.4.3 F-40 (P2 audit) — the VALUE is run through asOrderedNumber():
  // a real number passes through; a CLEAN decimal-number STRING (e.g. a tool
  // that serializes `bytes` as "1500000") is coerced to its number. Why: a
  // deny threshold like { gt: 1000000 } previously did NOT match a stringified
  // value, so the rule silently no-matched and the action fell through to
  // default-allow — a fail-OPEN on exfil-size / rate thresholds. Coercion is
  // deliberately NARROW: only /^-?\d+(\.\d+)?$/ (no hex, exponent, whitespace,
  // Infinity/NaN). This applies ONLY to the ORDERED comparators below.
  // EQUALITY (literal / in / not_in) stays strict — "3" still never === 3 —
  // and length_* (further down) still measures the raw string/array length.
  if (Number.isFinite(condition.gt)) {
    const v = asOrderedNumber(value);
    return Number.isFinite(v) && v > condition.gt;
  }
  if (Number.isFinite(condition.gte)) {
    const v = asOrderedNumber(value);
    return Number.isFinite(v) && v >= condition.gte;
  }
  if (Number.isFinite(condition.lt)) {
    const v = asOrderedNumber(value);
    return Number.isFinite(v) && v < condition.lt;
  }
  if (Number.isFinite(condition.lte)) {
    const v = asOrderedNumber(value);
    return Number.isFinite(v) && v <= condition.lte;
  }
  // in_range: tuple [min, max] inclusive both sides. An inverted tuple
  // (min > max) fails-closed — most likely an operator typo, never a
  // legitimate "match nothing" intent.
  if (Array.isArray(condition.in_range) && condition.in_range.length === 2) {
    const [min, max] = condition.in_range;
    if (!Number.isFinite(min) || !Number.isFinite(max) || min > max) return false;
    const v = asOrderedNumber(value);
    return Number.isFinite(v) && v >= min && v <= max;
  }
  // length_* operators apply to strings or arrays. Anything else (object,
  // number, null) fails-closed — length is meaningless there.
  if (Number.isFinite(condition.length_gt)) {
    return (typeof value === 'string' || Array.isArray(value)) && value.length > condition.length_gt;
  }
  if (Number.isFinite(condition.length_gte)) {
    return (typeof value === 'string' || Array.isArray(value)) && value.length >= condition.length_gte;
  }
  if (Number.isFinite(condition.length_lt)) {
    return (typeof value === 'string' || Array.isArray(value)) && value.length < condition.length_lt;
  }
  if (Number.isFinite(condition.length_lte)) {
    return (typeof value === 'string' || Array.isArray(value)) && value.length <= condition.length_lte;
  }
  // Unknown condition shape — defensive: fail-closed (no match) so unknown
  // conditions never silently allow events.
  return false;
}

// Evaluate a single policy against an event. Returns true iff every match
// clause is satisfied. A match clause with an undefined target field still
// counts as "no match" rather than "any match".
//
// v1.2.0 — `ctx` is an optional second namespace for runtime-computed
// attributes (hour_of_day_utc, agent_age_minutes, recent_error_rate,
// session_duration_ms — see src/shield/context.js). Field paths in the
// `match` clause that start with the reserved prefix `ctx.` resolve from
// ctx rather than event. Everything else still resolves from event, so
// existing policies keep working unchanged.
//
// The `ctx.` prefix is a reserved namespace: WMA-normalized events never
// have a top-level `ctx` field (normalizeForPolicy never sets one), so
// there's no risk of shadowing. If a future Anthropic event shape ever
// has one, callers can rename their context attributes.
export function matchesPolicy(event, policy, ctx = {}) {
  for (const [field, condition] of Object.entries(policy.match || {})) {
    const value = field.startsWith('ctx.')
      ? getNested(ctx, field.slice(4))
      : getNested(event, field);
    // v1.4.2 F-38 (P0 audit): the action_type field gets tool-family
    // expansion so a rule keyed on the generic `tool_use` catches MCP +
    // custom tool calls too. Every other field uses plain matchValue.
    const matched = field === 'action_type'
      ? matchActionType(value, condition)
      : matchValue(value, condition);
    if (!matched) return false;
  }
  return true;
}

// v1.4.2 F-38 (P0 audit) — action_type matching with tool-family expansion.
//
// Adapters emit three distinct tool-invocation action_types: `tool_use`
// (provider built-ins), `mcp_tool_use` (MCP servers), `custom_tool_use`
// (customer-wired tools). A policy that targets the GENERIC `tool_use` must
// match all three — otherwise a deny/allowlist rule silently misses MCP and
// custom tool calls (e.g. the Deep Researcher "only web_search/web_fetch,
// deny everything else" containment rule had a hole exactly there). The OpenAI
// adapter emits `custom_tool_use` for EVERY tool, so without this a
// `tool_use`-keyed rule matched nothing on that runtime at all.
//
// Expansion is one-directional and conservative: only the generic `tool_use`
// token expands to the family. A policy that names a SPECIFIC member
// (`mcp_tool_use` / `custom_tool_use`) stays an exact match, so an operator
// who deliberately wants to target one surface still can. Non-set conditions
// on action_type (regex, numeric — unusual but legal) fall back to matchValue.
function expandActionTypeTargets(target) {
  return target === 'tool_use' ? TOOL_USE_FAMILY : [target];
}

function matchActionType(value, condition) {
  if (condition === null || typeof condition !== 'object') {
    return expandActionTypeTargets(condition).includes(value);
  }
  if (Array.isArray(condition)) {
    return condition.flatMap(expandActionTypeTargets).includes(value);
  }
  if (condition.in !== undefined) {
    return condition.in.flatMap(expandActionTypeTargets).includes(value);
  }
  if (condition.not_in !== undefined) {
    return !condition.not_in.flatMap(expandActionTypeTargets).includes(value);
  }
  // regex / numeric / unknown shapes on action_type are unusual but legal —
  // defer to the generic matcher (which fails-closed on unknown shapes).
  return matchValue(value, condition);
}

// First-match-wins evaluation. Returns the policy decision and metadata.
// v1.2.0 — accepts an optional `ctx` for runtime-computed attributes;
// see matchesPolicy() above. Omitting ctx preserves v1.1.x behavior.
export function evaluate(event, ruleset, ctx = {}) {
  for (const policy of ruleset.policies) {
    if (matchesPolicy(event, policy, ctx)) {
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
