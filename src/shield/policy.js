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

function compileMatchRegexes(match) {
  for (const condition of Object.values(match)) {
    if (condition && typeof condition === 'object') {
      if (condition.regex) condition._regex = new RegExp(condition.regex);
      if (condition.not_regex) condition._not_regex = new RegExp(condition.not_regex);
      if (condition.regex_any) condition._regex_any = condition.regex_any.map(r => new RegExp(r));
    }
  }
}

function getNested(obj, path) {
  return path.split('.').reduce((o, k) => (o == null ? undefined : o[k]), obj);
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
    return typeof value === 'string' && condition._regex.test(value);
  }
  if (condition._not_regex !== undefined) {
    return typeof value === 'string' && !condition._not_regex.test(value);
  }
  if (condition._regex_any !== undefined) {
    return typeof value === 'string' && condition._regex_any.some(r => r.test(value));
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
