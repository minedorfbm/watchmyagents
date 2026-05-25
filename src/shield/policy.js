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
  for (const p of data.policies) {
    compileMatchRegexes(p.match || {});
    if (!['allow', 'deny', 'interrupt'].includes(p.action)) {
      throw new Error(`policy ${p.id || p.name}: unsupported action "${p.action}"`);
    }
  }
  data.default = data.default || { action: 'allow' };
  return data;
}

// ReDoS protection: regexes are loaded from a user-provided JSON policy file,
// so a malicious or buggy pattern (e.g. `(a+)+$`) could pin the CPU on a long
// input. We mitigate two ways:
//   1) Cap the maximum input length passed to any regex test to MAX_REGEX_INPUT
//      bytes. Above that we truncate before testing. Real agent values
//      (URLs, commands, queries) are well under this in practice.
//   2) Reject obviously dangerous patterns at compile time (heuristic).
//
// A future v0.5 may add a proper safe-regex-2 dependency for thorough analysis.
const MAX_REGEX_INPUT = 8192;

const SUSPICIOUS_REGEX_PATTERNS = [
  /(\([^)]*[+*][^)]*\))[+*]/,   // (x+)+ or (x*)* — classic catastrophic backtracking
  /(\.\*){3,}/,                  // multiple .* in a row
];

function validateRegexString(src, where) {
  if (typeof src !== 'string') {
    throw new Error(`policy ${where}: regex must be a string`);
  }
  if (src.length > 2000) {
    throw new Error(`policy ${where}: regex too long (>2000 chars)`);
  }
  for (const sus of SUSPICIOUS_REGEX_PATTERNS) {
    if (sus.test(src)) {
      throw new Error(`policy ${where}: regex looks vulnerable to catastrophic backtracking ("${src.slice(0, 60)}…"). Refusing to load.`);
    }
  }
  return new RegExp(src);
}

function compileMatchRegexes(match) {
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
      };
    }
  }
  return {
    decision: ruleset.default?.action || 'allow',
    rule_id: null,
    rule_name: '(default)',
    message: null,
  };
}
