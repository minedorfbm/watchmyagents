// WatchMyAgents — main entry point (v1.4 Codex #10).
//
// `import { ... } from 'watchmyagents'` resolves here via the package.json
// `exports['.']` field. For adapter-specific imports (the recommended
// path for v1.4+), use the sub-entries:
//
//   import { openaiAgents } from 'watchmyagents/openai-agents';
//
// This root entry exposes the most stable cross-adapter primitives:
//   - the source-adapter contract (PROVIDERS, ACTION_TYPES, COMPOSITION_PATTERNS,
//     ENFORCEMENT_MODES, validateWMAAction)
//   - the policy engine + context tracker + decision chain that EVERY
//     adapter shares
//   - the Logger
//
// Internal modules (`src/sources/openai-agents-js.js`,
// `src/shield/*.js`, etc.) remain accessible to advanced consumers via
// deep imports, but those paths are NOT part of the stable surface;
// they may move between minor releases. Stick to the sub-entries and
// this root export for production code.

// ── Source-adapter contract ─────────────────────────────────────────
export {
  PROVIDERS,
  ACTION_TYPES,
  STATUS_VALUES,
  ENFORCEMENT_MODES,
  COMPOSITION_PATTERNS,
  validateWMAAction,
} from './sources/contract.js';

// ── Shield engine (policy eval + context + audit chain) ─────────────
export {
  evaluate,
  matchesPolicy,
  loadPolicies,
} from './shield/policy.js';

export { createContextTracker, defaultIsError } from './shield/context.js';

export {
  createDecisionChain,
  verifyDecisionChain,
  buildGenesisMarker,
  newChainId,
  CHAIN_FIELDS,
} from './shield/decision-chain.js';

export { DecisionLogger } from './shield/decisions.js';

// ── Logger ──────────────────────────────────────────────────────────
export { Logger } from './logger.js';
