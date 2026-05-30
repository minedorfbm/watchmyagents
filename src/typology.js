// Agent typology classifier — maps an agent's OBSERVED behaviour to one of the
// 10 Guardian Core archetypes, for Shield template selection / refinement.
//
// Source of truth: GUARDIAN CORE/agent-typology-classification.spec.md (v0.1) +
// GUARDIAN CORE/schemas/agent-classification.schema.json. classifyAgentType()
// returns an object conforming EXACTLY to that schema.
//
// Why behaviour, not config: Anthropic Managed Agents expose their tools as an
// opaque bundle (`agent_toolset_20260401`), so static config can't tell a
// researcher from a coder. We classify from anonymized behavioural signals
// (Containment): per-tool-category FRACTIONS (f_*), boolean local flags (flag_*),
// and aux ratios (aux_*). NEVER raw content — no prompts, no outputs, no names.
//
// ──────────────────────────────────────────────────────────────────────────
// GLOBAL-BASELINE INDEPENDENCE (spec §1, §5 — INVARIANT, read this):
//   The `global-baseline` (5 mandatory fail_closed floors) ALWAYS applies,
//   regardless of the result — or absence — of classification. A bad
//   classification degrades REFINEMENT, never the FLOOR. This classifier MUST
//   NEVER gate, relax, or sit on the critical path of those floors. Nothing
//   returned here can disable a floor. Template swaps bring new *probabilistic*
//   policies in via `shadow` first; mandatory floors are never relaxed during
//   the transition.
// ──────────────────────────────────────────────────────────────────────────
//
// INVARIANTS enforced here:
//   1. Containment — inputs are anonymized fractions/flags/aux ONLY.
//   2. Weights + thresholds come from config (typology-weights.json), never
//      hardcoded in the logic below.
//   3. No easy downgrade — moving to a LESS strict template needs a raised
//      confidence (0.85) AND a longer window (5), per the strictness ranking.
//   4. global-baseline is independent of classification (see banner above).

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

// The 10 archetypes (schema `classified_type` enum, exact order/spelling).
export const ARCHETYPES = [
  'coding', 'devops_infra', 'data_rag', 'customer_facing', 'browser_web',
  'orchestrator', 'workflow_backoffice', 'personal_assistant',
  'transactional_financial', 'generic',
];

// Modifiers (schema enum). They ONLY add restrictions, so they are activatable
// immediately — no asymmetry / hysteresis (spec §6).
export const MODIFIERS = ['autonomy', 'untrusted_input', 'data_sensitivity', 'regulated'];

// ── Config (weights + thresholds + strictness ranking) — loaded once. ───────
// INVARIANT 2: nothing below hardcodes a weight or threshold; everything that
// influences the decision is read from this file.
let _config = null;
export function loadConfig(path = join(__dirname, 'typology-weights.json')) {
  if (_config && path === _config.__path) return _config;
  const raw = JSON.parse(readFileSync(path, 'utf8'));
  raw.__path = path;
  _config = raw;
  return _config;
}
// Test/seam: inject a config object directly.
export function setConfig(cfg) { _config = { ...cfg, __path: '<injected>' }; return _config; }

const sigmoid = (x) => 1 / (1 + Math.exp(-x));
const clamp01 = (x) => Math.max(0, Math.min(1, x));

// Strict comparison helper for re-classification asymmetry. Higher rank =
// stricter template. Moving to >= current rank is an "upgrade" (or lateral);
// moving to a strictly LOWER rank is a "downgrade" (gated).
function strictnessOf(cfg, type) {
  const r = cfg.strictness_rank || {};
  return Number.isFinite(r[type]) ? r[type] : 0;
}

/**
 * Build the canonical feature vector from a loose features object.
 * Only the schema-legal keys are kept; everything is coerced to a number and
 * clamped to [0,1] (the schema requires every feature_vector value in [0,1]).
 * Missing features default to 0 — Containment: an absent signal is "not observed",
 * never inferred from content.
 */
function normalizeFeatures(cfg, features) {
  const fr = cfg.features?.fractions || [];
  const fl = cfg.features?.flags || [];
  const ax = cfg.features?.aux || [];
  const out = {};
  for (const k of [...fr, ...fl, ...ax]) {
    const v = Number(features?.[k]);
    out[k] = Number.isFinite(v) ? clamp01(v) : 0;
  }
  return out;
}

/** score(type) = Σ_i w[type][i] · feature_i  (spec §4). */
function scoreType(weightsForType, fv) {
  let s = 0;
  for (const [feat, w] of Object.entries(weightsForType || {})) {
    s += (Number(w) || 0) * (fv[feat] || 0);
  }
  return s;
}

/**
 * Rank all archetypes by score. Returns the full sorted list plus top1/top2.
 * Tie-break (spec §8): on EQUAL dominance, the STRICTER type wins (conservative).
 * 'generic' is excluded from the positive ranking — it is the fallback only.
 */
function rankTypes(cfg, fv) {
  const scored = ARCHETYPES
    .filter((t) => t !== 'generic')
    .map((t) => ({ type: t, score: scoreType(cfg.weights?.[t], fv) }));
  scored.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    // tie → stricter (higher strictness_rank) first
    return strictnessOf(cfg, b.type) - strictnessOf(cfg, a.type);
  });
  return scored;
}

/**
 * classifyAgentType(features[, prior][, opts]) → object conforming EXACTLY to
 * agent-classification.schema.json.
 *
 * @param {object} features          Anonymized behavioural signals (Containment):
 *   agent_id            {string}    pass-through identifier (no content)
 *   f_code,f_browser,…  {number}    per-category FRACTIONS in [0,1]
 *   flag_deploy,…       {0|1|bool}  local discriminator flags (no content)
 *   aux_autonomy,…      {number}    aux ratios in [0,1]
 *   n_events            {number}    events in the current sliding window
 * @param {object} [prior]           Previous classification result (the caller
 *   threads this so the state machine + asymmetry work across windows). Reads:
 *   classified_type, stage, windows_consistent, strictness_rank,
 *   last_reclassified_at.
 * @param {object} [opts]
 *   regulated {boolean}             tenant/Fortress flag (config-driven, NOT
 *                                   behavioural) → adds the `regulated` modifier
 *   now {string}                    ISO timestamp seam for tests
 *   config {object}                 inject config (else loaded from disk)
 * @returns {object}                 schema-conformant classification result
 */
export function classifyAgentType(features = {}, prior = null, opts = {}) {
  const cfg = opts.config ? setConfig(opts.config) : loadConfig();
  const th = cfg.thresholds || {};
  const sg = cfg.confidence_sigmoid || {};
  const now = opts.now || new Date().toISOString();

  const agent_id = String(features.agent_id ?? prior?.agent_id ?? '');
  const fv = normalizeFeatures(cfg, features);
  // Floor + finiteness guard: the schema declares window_events as integer.
  // Non-finite (Infinity/NaN) → 0 so it can't saturate confidence via log(n).
  const _rawN = Number(features.n_events);
  const nEvents = Number.isFinite(_rawN) ? Math.max(0, Math.floor(_rawN)) : 0;

  // ── Score every archetype, find top1 / top2 / margin (spec §4). ──────────
  const ranked = rankTypes(cfg, fv);
  const top1 = ranked[0] || { type: 'generic', score: 0 };
  const top2 = ranked[1] || { type: 'generic', score: 0 };
  const margin = top1.score - top2.score;

  // confidence = sigmoid(a·top1.score + b·margin + c·log(n_events) + bias).
  // All three terms (top1 score, margin, log n_events) are folded in — NOT just
  // top1.score. Coefficients a/b/c/bias come from config.
  const logN = Math.log(Math.max(1, nEvents));
  const confidence = clamp01(
    sigmoid((sg.a || 0) * top1.score + (sg.b || 0) * margin + (sg.c || 0) * logN + (sg.bias || 0)),
  );

  // ── Candidate type per the gates (spec §4). ──────────────────────────────
  // n_events < MIN_EVENTS               → generic (cold-start)
  // OR confidence < CONF_THRESHOLD      → generic
  // OR margin < MARGIN_MIN              → generic
  // else                                → top1.type
  let candidate;
  const belowMinEvents = nEvents < th.n_events_min;
  const lowConfidence = confidence < th.confidence_min;
  const lowMargin = margin < th.margin_min;

  // Conservative tie-break (spec §8): "en cas d'égalité, choisir le plus strict
  // (conservateur)". When the top two are a near-TIE (|margin| ≤ tie_epsilon)
  // between two REAL types and there is real signal (top1.score > 0), dropping
  // to generic would RELAX protection — so instead we keep the STRICTER of the
  // tied pair. rankTypes() already sorts the stricter type first on an exact
  // tie, so top1 IS the stricter one here. This applies only on a true tie; a
  // genuinely ambiguous low-signal window (no tie, just a small margin) still
  // falls back to generic via the margin gate below.
  const tieEps = th.tie_epsilon ?? 0;
  const isTie = top1.score > 0 && top2.type !== 'generic' && Math.abs(margin) <= tieEps;

  if (belowMinEvents) candidate = 'generic';
  else if (isTie) candidate = top1.type;                  // stricter-wins, conservative
  else if (lowConfidence || lowMargin) candidate = 'generic';
  else candidate = top1.type;

  // ── State machine + re-classification asymmetry (spec §5). ───────────────
  // We accept the prior state as input so the CALLER threads it across windows;
  // this function is otherwise pure for a given (features, prior).
  const priorType = prior?.classified_type || 'generic';
  const priorStage = prior?.stage || 'cold_start';
  const priorWindows = Math.max(0, Math.floor(Number(prior?.windows_consistent) || 0));
  const priorReclassAt = prior?.last_reclassified_at || null;
  // Last real (non-generic) type, threaded across generic gaps. Closes the
  // generic-laundering downgrade bypass: a strict→generic→looser-real sequence
  // must still face the downgrade gate against the ORIGINAL strict rank.
  const priorLastReal = prior?.last_real_type || (priorType !== 'generic' ? priorType : null);
  // The candidate the prior window(s) were already accumulating toward (if any).
  // The caller threads this so a pending change builds consecutive evidence
  // across windows instead of resetting every window.
  const priorPending = prior?.pending_type || null;

  let classified_type = priorType;
  let stage = priorStage;
  let windows_consistent = priorWindows;
  let last_reclassified_at = priorReclassAt;
  // pending_type: the candidate we are accumulating consecutive windows toward
  // but have not yet committed (hysteresis / asymmetry not satisfied). Surfaced
  // in the result so the caller can thread it back next window.
  let pending_type = null;
  let pending_windows = 0;

  if (belowMinEvents) {
    // A low-traffic window must NOT collapse an established type. An adversary
    // could throttle below MIN_EVENTS to shed a strict template (downgrade
    // bypass). If we already hold a real type, RETAIN it (freeze the window
    // count); only a genuinely cold agent (no prior real type) stays generic.
    if (priorType !== 'generic') {
      classified_type = priorType;
      stage = priorStage;
      windows_consistent = priorWindows;
    } else {
      classified_type = 'generic';
      stage = 'cold_start';
      windows_consistent = 0;
    }
  } else if (candidate === priorType) {
    // Same type as last window → accumulate consistency (hysteresis).
    windows_consistent = priorWindows + 1;
    // provisional → stable after STABLE_WINDOWS consecutive consistent windows.
    if (classified_type !== 'generic' && stage !== 'stable' &&
        windows_consistent >= th.stable_windows) {
      stage = 'stable';
    } else if (classified_type !== 'generic' && stage === 'cold_start') {
      stage = 'provisional';
    }
  } else {
    // Type would CHANGE relative to the prior. Decide whether the change is
    // allowed THIS window, or whether we must accumulate more evidence.
    const toRank = strictnessOf(cfg, candidate);
    // Reference rank for downgrade detection: the prior REAL type, or — across a
    // generic gap — the last real type before we fell to generic. Using the
    // last-real reference closes the generic-laundering bypass (strict → generic
    // → looser-real must still face the downgrade gate against the strict rank).
    const refType = (priorType !== 'generic') ? priorType : (priorLastReal || 'generic');
    const refRank = strictnessOf(cfg, refType);
    // A "downgrade" = moving to a real template STRICTLY LESS strict than the
    // reference. Upgrading / lateral is NOT a downgrade. Falling back TO generic
    // is handled below (never relaxes the floor — the global-baseline always applies).
    const isDowngrade = candidate !== 'generic' && refType !== 'generic' && toRank < refRank;

    // Required consecutive-consistent-window count BEFORE applying the change.
    //   Leaving generic (cold_start → provisional): the FIRST window clearing
    //     the gates commits — provisional = "1er type au-dessus du seuil" (§5).
    //   Upgrade / lateral (real → real, equal-or-stricter): normal hysteresis
    //     STABLE_WINDOWS, never relaxes the floor.
    //   Downgrade (real → LESS strict): longer DOWNGRADE_WINDOWS AND a raised
    //     confidence floor (anti mimicry-evasion: an agent must not soften its
    //     protection by imitating a more permissive type).
    const leavingGeneric = priorType === 'generic';
    // Leaving generic is fast (1 window) ONLY when it is not a net downgrade vs
    // the last real type. A net downgrade — even laundered through generic —
    // takes the full gate: longer window AND raised confidence (anti-evasion).
    const neededWindows = isDowngrade ? th.downgrade_windows
                        : (leavingGeneric ? 1 : th.stable_windows);
    const neededConfidence = isDowngrade ? th.downgrade_confidence_min : th.confidence_min;

    // Consecutive consistent windows toward THIS candidate. If the prior window
    // was already accumulating toward the same candidate, continue the count;
    // otherwise this is the first window of a fresh pending change.
    const accWindows = (priorPending === candidate)
      ? Math.max(0, Math.floor(Number(prior?.pending_windows) || 0)) + 1
      : 1;

    if (candidate === 'generic') {
      // Falling back to generic is never a security relaxation we must gate —
      // the global-baseline floor still applies — but we still respect
      // hysteresis so a single noisy window can't flap us out of a real type.
      if (priorType === 'generic') {
        windows_consistent = priorWindows + 1;
        classified_type = 'generic';
        stage = 'cold_start';
      } else {
        // Accumulate toward dropping the type, but keep the (stricter) prior
        // until hysteresis is satisfied — conservative.
        if (accWindows >= th.stable_windows) {
          classified_type = 'generic';
          stage = 'cold_start';
          windows_consistent = 1;
          last_reclassified_at = now;
        } else {
          pending_type = 'generic';
          pending_windows = accWindows;
          // classified_type / stage / windows_consistent unchanged (stay put).
        }
      }
    } else if (confidence >= neededConfidence && accWindows >= neededWindows) {
      // Enough consecutive evidence (counting the current window) to commit the
      // change. The caller threads pending_type/pending_windows so consecutive
      // windows toward the same candidate accumulate.
      classified_type = candidate;
      // A freshly committed type always lands in 'provisional'; it climbs to
      // 'stable' only after STABLE_WINDOWS consecutive same-type windows.
      stage = 'provisional';
      windows_consistent = 1;
      last_reclassified_at = now;
    } else {
      // Not enough evidence yet → keep the prior (stricter-by-default) type and
      // record the pending candidate so the next window can build on it. We do
      // NOT touch windows_consistent of the committed type (it still applies).
      pending_type = candidate;
      pending_windows = accWindows;
    }
  }

  // Stage sanity: generic is always cold_start.
  if (classified_type === 'generic') stage = 'cold_start';

  // Last real (non-generic) type — threaded so a generic gap doesn't erase the
  // downgrade reference (see priorLastReal). Persists across generic windows.
  const last_real_type = (classified_type !== 'generic') ? classified_type : (priorLastReal || null);

  // ── Modifiers (spec §6): additive restrictions, no asymmetry/hysteresis. ──
  const modifiers = [];
  const autonomyLevel = String(features.autonomy_level ?? features.aux_autonomy_level ?? '');
  const auxAutonomy = Number(features.aux_autonomy) || 0;
  // autonomy: explicit level in {act_with_approval, autonomous}, or a high ratio.
  if (['act_with_approval', 'autonomous'].includes(autonomyLevel) || auxAutonomy >= (th.autonomy_modifier_min ?? 0.5)) {
    modifiers.push('autonomy');
  }
  if ((fv.aux_untrusted || 0) > (th.untrusted_modifier_min ?? 0.1)) {
    modifiers.push('untrusted_input');
  }
  if ((fv.aux_sensitive || 0) > (th.sensitive_modifier_min ?? 0)) {
    modifiers.push('data_sensitivity');
  }
  // regulated is tenant/Fortress config — NOT behavioural.
  if (opts.regulated === true) modifiers.push('regulated');

  // ── Payment overlay (spec §3/§5/§6): f_payment > 0 FORCES the transactional
  // profile even when another base type dominates. It is an OVERLAY, not a
  // winner-take-all reclassification: the base type stays, and we surface the
  // overlay in evidence so the Shield layer adds the confirmation/limit
  // policies. Reducing f_payment to flee transactional_financial is neutralized
  // by the downgrade asymmetry + the always-on floor.
  //
  // It is surfaced in `evidence.payment_overlay`, NOT in `modifiers[]`: the
  // schema's modifiers enum is fixed to {autonomy, untrusted_input,
  // data_sensitivity, regulated} — "transactional" is not a legal modifier
  // value, so emitting it there would violate the schema. evidence has no
  // additionalProperties:false, so it is the schema-legal carrier for the overlay.
  const paymentOverlay = (fv.f_payment || 0) > (th.payment_overlay_min ?? 0);

  // ── Evidence (schema-shaped). ────────────────────────────────────────────
  const evidence = {
    window_events: nEvents,
    top2_type: top2.type,
    margin: Number(margin.toFixed(6)),
  };
  // Extra evidence keys are schema-legal (evidence has no additionalProperties:
  // false). Surface the decision context for audit — never raw content.
  if (paymentOverlay) {
    evidence.payment_overlay = {
      active: true,
      f_payment: fv.f_payment,
      adds: 'transactional_financial confirmation/limit policies (overlay, base type unchanged)',
    };
  }
  evidence.confidence_terms = { top1_score: Number(top1.score.toFixed(6)), margin: Number(margin.toFixed(6)), log_n_events: Number(logN.toFixed(6)) };

  return {
    agent_id,
    classified_type,
    confidence: Number(confidence.toFixed(6)),
    stage,
    modifiers,
    evidence,
    feature_vector: fv,
    windows_consistent,
    strictness_rank: strictnessOf(cfg, classified_type),
    ...(last_reclassified_at ? { last_reclassified_at } : {}),
    // Hysteresis carry-over (schema-legal extras: root has no
    // additionalProperties:false). The caller threads these back as part of the
    // `prior` next window so a pending change accumulates consecutive evidence,
    // and so the downgrade reference survives a generic gap (anti-evasion).
    ...(pending_type ? { pending_type, pending_windows } : {}),
    ...(last_real_type ? { last_real_type } : {}),
  };
}

export default classifyAgentType;
