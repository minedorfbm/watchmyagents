// ─────────────────────────────────────────────────────────────────────────
// Ed25519 policy signature verification — v1.1.5 Phase 1.5 (Guardian Core Axis 2)
// ─────────────────────────────────────────────────────────────────────────
//
// Two-level chain of trust:
//
//   ROOT KEY (offline-generated, public key embedded in the SDK)
//     │ signs
//     ▼
//   SIGNING KEY (rotated quarterly by Fortress, distributed in get-policies)
//     │ signs
//     ▼
//   POLICY (each policy.signature is verified against its signing_key)
//
// The root private key NEVER leaves Fortress's secure vault. Signing keys
// rotate without requiring an SDK release because their public keys travel
// in the get-policies response, signed by the root. The SDK only needs to
// know the embedded root public key to validate the whole chain.
//
// Why per-policy signatures (not bundle signatures):
//   - A single corrupted/malicious policy doesn't invalidate the whole
//     ruleset — we drop the invalid one and keep the rest.
//   - Lets us mix "Fortress-signed cloud policies" with "local JSON
//     policies for dev/test" without forcing the local path through the
//     signing pipeline. The local-file adapter sets `__local: true` on
//     its policies to opt out of signature requirements.
//   - Compatible with first-match-wins evaluation: order is preserved,
//     gaps from dropped policies are silently filled by lower-priority
//     rules or the ruleset default.
//
// Zero runtime deps preserved — uses node:crypto's native Ed25519 support
// (Node 16+). No tweetnacl, no @noble/curves.

import { createPublicKey, verify as cryptoVerify } from 'node:crypto';

// ─────────────────────────────────────────────────────────────────────────
// Canonical serialization for signing
// ─────────────────────────────────────────────────────────────────────────
//
// Both ends (signer + verifier) must agree on EXACTLY what bytes are signed.
// We use a deterministic JSON encoding: keys sorted lexicographically at
// every nesting depth, arrays preserved in order, no whitespace, no escape
// variations (JSON.stringify's default escaping is deterministic).
//
// The signed payload for a POLICY excludes the signature field itself plus
// any signer-side bookkeeping (signed_at, signing_key_id are NOT signed —
// they're metadata that travels alongside the signature for verifier
// lookup). The fields we DO sign are the ones whose modification would
// change Shield's decision: rule_id, match, action, message, priority, mode.

const POLICY_SIGNED_FIELDS = ['rule_id', 'match', 'action', 'message', 'priority', 'mode'];

// Recursive deterministic JSON: sorted keys at every depth, arrays kept in
// order. This MUST mirror JSON.stringify's value semantics exactly — the only
// intentional difference is key sorting for determinism. The reason is
// load-bearing: the bytes we hash here have to equal the bytes that land on
// disk after JSON.stringify(record), because the verifier re-reads the disk
// record (already JSON round-tripped) and re-canonicalizes it.
//
// v1.4.2 F-39 (P0 audit) — the previous version emitted the literal token
// `undefined` for object keys / array elements whose value was `undefined`
// (or a function / symbol). JSON.stringify DROPS such object keys and renders
// such array elements as `null`. So a record like { tool_input: { max_uses:
// undefined } } hashed to `{"tool_input":{"max_uses":undefined}}` at write
// time but, after JSON.stringify dropped `max_uses` on disk, re-canonicalized
// to `{"tool_input":{}}` at verify time — chain_hash mismatch on an UNTAMPERED
// record. That broke the tamper-evidence guarantee (false alarms masking real
// tampering) and corrupted the Ed25519 signing domain the same way. The fix
// makes canonicalize JSON-faithful; for JSON-clean data it is byte-identical
// to the old behavior, so existing valid chains keep verifying.
export function canonicalize(value) {
  if (value === null || typeof value !== 'object') {
    // JSON.stringify(undefined | function | symbol) returns `undefined`
    // (the JS value, not a string). Default those to `null` so we never
    // concatenate the literal token `undefined` into the hashed string.
    const enc = JSON.stringify(value);
    return enc === undefined ? 'null' : enc;
  }
  if (Array.isArray(value)) {
    // JSON renders undefined / function / symbol array elements as null —
    // the primitive branch above already returns 'null' for them.
    return '[' + value.map((v) => canonicalize(v)).join(',') + ']';
  }
  // JSON.stringify omits object keys whose value is undefined / a function /
  // a symbol. Mirror that, or the hashed string carries a key that vanishes
  // on disk (the F-39 break).
  const keys = Object.keys(value).sort();
  const pairs = [];
  for (const k of keys) {
    const v = value[k];
    if (v === undefined || typeof v === 'function' || typeof v === 'symbol') continue;
    pairs.push(JSON.stringify(k) + ':' + canonicalize(v));
  }
  return '{' + pairs.join(',') + '}';
}

// Build the byte string the policy signer hashed-and-signed.
// Order: only the fields in POLICY_SIGNED_FIELDS, in their canonical order.
// Missing fields are encoded as `null` so a policy that loses a field on
// the wire (truncation, MITM) fails the signature check rather than
// silently passing under a different shape.
export function policySigningPayload(policy) {
  const obj = {};
  for (const f of POLICY_SIGNED_FIELDS) {
    obj[f] = policy[f] !== undefined ? policy[f] : null;
  }
  return canonicalize(obj);
}

// Build the byte string the ROOT signs when issuing a signing key.
// Order: only kid + pubkey + valid_from + valid_until — all four required.
// `pubkey` is the raw 32-byte Ed25519 public key, base64-encoded.
const SIGNING_KEY_SIGNED_FIELDS = ['kid', 'pubkey', 'valid_from', 'valid_until'];

export function signingKeyPayload(signingKey) {
  const obj = {};
  for (const f of SIGNING_KEY_SIGNED_FIELDS) {
    obj[f] = signingKey[f] !== undefined ? signingKey[f] : null;
  }
  return canonicalize(obj);
}

// ─────────────────────────────────────────────────────────────────────────
// Key parsing
// ─────────────────────────────────────────────────────────────────────────

// Accept either:
//   - a raw 32-byte Ed25519 public key, base64-encoded
//   - a SubjectPublicKeyInfo (SPKI) DER-encoded blob, base64-encoded
//   - a PEM-armored public key
// Returns a node:crypto KeyObject ready for verify().
//
// Errors are surfaced verbatim so the operator sees WHY the key didn't
// load (corrupted base64, wrong curve, etc.) instead of a silent "no
// policies loaded".
export function importEd25519PublicKey(input) {
  if (input == null) throw new Error('importEd25519PublicKey: input is null/undefined');
  if (typeof input === 'string') {
    const trimmed = input.trim();
    if (trimmed.startsWith('-----BEGIN ')) {
      return createPublicKey({ key: trimmed, format: 'pem' });
    }
    // Try raw 32-byte → wrap in SPKI prefix for Ed25519.
    const buf = Buffer.from(trimmed, 'base64');
    if (buf.length === 32) {
      // Ed25519 SPKI prefix (RFC 8410 §4): 0x302a300506032b6570032100
      const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
      return createPublicKey({
        key: Buffer.concat([SPKI_PREFIX, buf]),
        format: 'der',
        type: 'spki',
      });
    }
    // Otherwise assume DER-encoded SPKI.
    return createPublicKey({ key: buf, format: 'der', type: 'spki' });
  }
  if (Buffer.isBuffer(input)) {
    return createPublicKey({ key: input, format: 'der', type: 'spki' });
  }
  throw new Error(`importEd25519PublicKey: unsupported input type ${typeof input}`);
}

// ─────────────────────────────────────────────────────────────────────────
// Low-level verify
// ─────────────────────────────────────────────────────────────────────────

// Verify a base64-encoded Ed25519 signature over a string payload.
// Returns true/false — never throws on a bad signature (operational
// callers want a boolean, not exception flow). Throws only on programmer
// errors (missing key, wrong types).
export function verifyEd25519(publicKey, payloadString, signatureBase64) {
  if (publicKey == null) throw new Error('verifyEd25519: publicKey required');
  if (typeof payloadString !== 'string') throw new Error('verifyEd25519: payload must be a string');
  if (typeof signatureBase64 !== 'string') return false;
  let sigBuf;
  try {
    sigBuf = Buffer.from(signatureBase64, 'base64');
  } catch {
    return false;
  }
  // Ed25519 signatures are exactly 64 bytes — anything else is invalid.
  if (sigBuf.length !== 64) return false;
  try {
    return cryptoVerify(null, Buffer.from(payloadString, 'utf8'), publicKey, sigBuf);
  } catch {
    return false;
  }
}

// ─────────────────────────────────────────────────────────────────────────
// High-level chain verification
// ─────────────────────────────────────────────────────────────────────────

/**
 * Verify a signing key's root signature and parse its public key.
 *
 * @param {object} signingKey
 *   { kid, pubkey, valid_from, valid_until, signed_by_root }
 * @param {KeyObject} rootPublicKey - the embedded SDK root public key
 * @param {Date} [now] - clock for valid_from/valid_until checks (default: real now)
 * @returns {{ ok: true, kid: string, pubkey: KeyObject } | { ok: false, reason: string }}
 */
export function verifySigningKey(signingKey, rootPublicKey, now = new Date()) {
  if (!signingKey || typeof signingKey !== 'object') {
    return { ok: false, reason: 'signing key is not an object' };
  }
  for (const f of SIGNING_KEY_SIGNED_FIELDS) {
    if (signingKey[f] == null) return { ok: false, reason: `signing key missing required field "${f}"` };
  }
  if (typeof signingKey.signed_by_root !== 'string') {
    return { ok: false, reason: 'signing_key.signed_by_root missing or not a string' };
  }
  // Validity window — both ends inclusive per ISO 8601 convention.
  const from = new Date(signingKey.valid_from);
  const until = new Date(signingKey.valid_until);
  if (isNaN(from.getTime()) || isNaN(until.getTime())) {
    return { ok: false, reason: 'invalid valid_from or valid_until ISO date' };
  }
  if (now < from) return { ok: false, reason: `signing key ${signingKey.kid} not yet valid (valid_from ${signingKey.valid_from})` };
  if (now > until) return { ok: false, reason: `signing key ${signingKey.kid} expired (valid_until ${signingKey.valid_until})` };
  // Root signature over canonical {kid, pubkey, valid_from, valid_until}.
  const payload = signingKeyPayload(signingKey);
  if (!verifyEd25519(rootPublicKey, payload, signingKey.signed_by_root)) {
    return { ok: false, reason: `signing key ${signingKey.kid} not signed by trusted root` };
  }
  // Parse the signing key's pubkey itself (must be a valid Ed25519 key).
  let pubkey;
  try {
    pubkey = importEd25519PublicKey(signingKey.pubkey);
  } catch (e) {
    return { ok: false, reason: `signing key ${signingKey.kid} pubkey invalid: ${e.message}` };
  }
  return { ok: true, kid: signingKey.kid, pubkey };
}

/**
 * Verify one policy's signature against its signing key.
 *
 * @param {object} policy   - must include signature + signing_key_id
 * @param {Map<string, KeyObject>} signingKeysByKid - verified signing keys
 * @returns {{ ok: true } | { ok: false, reason: string }}
 */
export function verifyPolicy(policy, signingKeysByKid) {
  if (!policy || typeof policy !== 'object') return { ok: false, reason: 'policy is not an object' };
  // Local-policy escape hatch: the local JSON adapter sets __local: true
  // on its rows so dev/test/CI workflows don't have to involve the
  // signing pipeline. The FortressPolicySource path NEVER sets this.
  if (policy.__local === true) return { ok: true };
  if (typeof policy.signature !== 'string') return { ok: false, reason: `policy ${policy.rule_id || '?'} missing signature` };
  if (typeof policy.signing_key_id !== 'string') return { ok: false, reason: `policy ${policy.rule_id || '?'} missing signing_key_id` };
  const pubkey = signingKeysByKid.get(policy.signing_key_id);
  if (!pubkey) {
    return { ok: false, reason: `policy ${policy.rule_id || '?'} references unknown signing_key_id "${policy.signing_key_id}"` };
  }
  const payload = policySigningPayload(policy);
  if (!verifyEd25519(pubkey, payload, policy.signature)) {
    return { ok: false, reason: `policy ${policy.rule_id || '?'} signature does not verify against signing key ${policy.signing_key_id}` };
  }
  return { ok: true };
}

/**
 * High-level: given a Fortress `get-policies` response and the embedded
 * root pubkey, return { validPolicies, droppedPolicies, validSigningKeys }.
 *
 * Caller is expected to ignore droppedPolicies (with logging) and load
 * validPolicies into the ruleset. Never throws — failure modes are
 * returned in `droppedPolicies[].reason` for the caller to surface.
 *
 * @param {object} opts
 * @param {Array} opts.policies   - raw policies from get-policies response
 * @param {Array} opts.signingKeys - raw signing_keys from response
 * @param {KeyObject} opts.rootPublicKey - SDK-embedded root pubkey
 * @param {Date} [opts.now]
 */
export function verifyPolicyBundle({ policies, signingKeys, rootPublicKey, now = new Date() }) {
  const validSigningKeys = new Map();
  const signingKeyErrors = [];
  for (const sk of signingKeys || []) {
    const r = verifySigningKey(sk, rootPublicKey, now);
    if (r.ok) validSigningKeys.set(r.kid, r.pubkey);
    else signingKeyErrors.push({ kid: sk?.kid || '?', reason: r.reason });
  }
  const validPolicies = [];
  const droppedPolicies = [];
  for (const p of policies || []) {
    const r = verifyPolicy(p, validSigningKeys);
    if (r.ok) validPolicies.push(p);
    else droppedPolicies.push({ rule_id: p?.rule_id || '?', reason: r.reason });
  }
  return { validPolicies, droppedPolicies, validSigningKeys, signingKeyErrors };
}
