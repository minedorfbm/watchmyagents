// Ed25519 policy signature verification — v1.1.5 Phase 1.5
//
// Hermetic tests: we generate fresh root + signing keypairs at the top
// of this file (using node:crypto's native Ed25519, the same primitive
// the prod verifier uses), then exercise every code path of the
// verifier with happy + adversarial fixtures.
//
// Coverage:
//   - canonicalize() determinism (key order, nested objects, arrays)
//   - policySigningPayload() shape (missing fields encoded as null)
//   - importEd25519PublicKey() accepts raw base64 + SPKI DER + PEM
//   - verifyEd25519() boolean returns + bad-signature handling
//   - verifySigningKey(): root chain + validity window + bad payload
//   - verifyPolicy(): signature + unknown kid + missing fields +
//     __local escape hatch
//   - verifyPolicyBundle(): drops bad policies but keeps the good ones,
//     surfaces reasons for the caller to log

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import {
  canonicalize,
  policySigningPayload,
  signingKeyPayload,
  importEd25519PublicKey,
  verifyEd25519,
  verifySigningKey,
  verifyPolicy,
  verifyPolicyBundle,
} from '../src/shield/signature.js';

// ── Fixture keys ────────────────────────────────────────────────────────

const root = generateKeyPairSync('ed25519');
const signing = generateKeyPairSync('ed25519');
const otherRoot = generateKeyPairSync('ed25519');

// Helper: sign payload string with a private key, return base64.
function sig(payload, privateKey) {
  return cryptoSign(null, Buffer.from(payload, 'utf8'), privateKey).toString('base64');
}

// Helper: raw 32-byte Ed25519 pubkey as base64 (the wire format for the
// `pubkey` field of a signing key).
function rawPubB64(keyObj) {
  // node returns SPKI DER which has a 12-byte prefix for Ed25519.
  const spki = keyObj.export({ format: 'der', type: 'spki' });
  return spki.slice(spki.length - 32).toString('base64');
}

const NOW = new Date('2026-06-02T12:00:00.000Z');
const VALID_FROM = '2026-01-01T00:00:00.000Z';
const VALID_UNTIL = '2026-12-31T23:59:59.000Z';

// Build a fully-signed signing-key fixture.
function freshSigningKeyFixture(over = {}) {
  const sk = {
    kid: 'sk-2026-q2',
    pubkey: rawPubB64(signing.publicKey),
    valid_from: VALID_FROM,
    valid_until: VALID_UNTIL,
    ...over,
  };
  sk.signed_by_root = sig(signingKeyPayload(sk), root.privateKey);
  return sk;
}

// Build a fully-signed policy fixture.
function freshPolicyFixture(over = {}) {
  const p = {
    rule_id: 'r-bash-deny',
    match: { tool_name: 'bash' },
    action: 'deny',
    message: 'bash is not allowed',
    priority: 100,
    mode: 'enforce',
    ...over,
  };
  p.signature = sig(policySigningPayload(p), signing.privateKey);
  p.signing_key_id = 'sk-2026-q2';
  return p;
}

// ── canonicalize() ──────────────────────────────────────────────────────

test('canonicalize: sorts keys at every nesting depth', () => {
  const a = canonicalize({ b: 1, a: { z: 1, y: 2 } });
  const b = canonicalize({ a: { y: 2, z: 1 }, b: 1 });
  assert.equal(a, b);
});

test('canonicalize: arrays preserve order', () => {
  assert.equal(canonicalize([3, 1, 2]), '[3,1,2]');
});

test('canonicalize: null + primitives + nested', () => {
  assert.equal(canonicalize(null), 'null');
  assert.equal(canonicalize(42), '42');
  assert.equal(canonicalize('hello'), '"hello"');
  assert.equal(canonicalize({ x: [1, { z: 0 }], y: null }), '{"x":[1,{"z":0}],"y":null}');
});

// ── policySigningPayload() ──────────────────────────────────────────────

test('policySigningPayload: missing fields encoded as null (not omitted)', () => {
  const p = { rule_id: 'r1', action: 'allow', match: {} };
  const payload = policySigningPayload(p);
  // Should contain "message":null, "priority":null, "mode":null
  assert.ok(payload.includes('"message":null'));
  assert.ok(payload.includes('"priority":null'));
  assert.ok(payload.includes('"mode":null'));
});

test('policySigningPayload: signature and signing_key_id are NOT in the payload', () => {
  const p = {
    rule_id: 'r1', action: 'deny', match: {}, message: 'm', priority: 1, mode: 'enforce',
    signature: 'should-not-be-signed-recursively',
    signing_key_id: 'sk-1',
  };
  const payload = policySigningPayload(p);
  assert.ok(!payload.includes('signature'));
  assert.ok(!payload.includes('signing_key_id'));
});

// ── importEd25519PublicKey() ────────────────────────────────────────────

test('importEd25519PublicKey: accepts raw 32-byte base64', () => {
  const k = importEd25519PublicKey(rawPubB64(root.publicKey));
  assert.equal(k.asymmetricKeyType, 'ed25519');
});

test('importEd25519PublicKey: accepts PEM', () => {
  const pem = root.publicKey.export({ format: 'pem', type: 'spki' });
  const k = importEd25519PublicKey(pem);
  assert.equal(k.asymmetricKeyType, 'ed25519');
});

test('importEd25519PublicKey: rejects null', () => {
  assert.throws(() => importEd25519PublicKey(null), /null\/undefined/);
});

// ── verifyEd25519() ─────────────────────────────────────────────────────

test('verifyEd25519: valid signature → true', () => {
  const payload = 'hello world';
  const s = sig(payload, root.privateKey);
  assert.equal(verifyEd25519(root.publicKey, payload, s), true);
});

test('verifyEd25519: tampered payload → false', () => {
  const s = sig('hello', root.privateKey);
  assert.equal(verifyEd25519(root.publicKey, 'hellO', s), false);
});

test('verifyEd25519: wrong key → false', () => {
  const s = sig('hello', root.privateKey);
  assert.equal(verifyEd25519(otherRoot.publicKey, 'hello', s), false);
});

test('verifyEd25519: malformed signature (not 64 bytes) → false (no throw)', () => {
  assert.equal(verifyEd25519(root.publicKey, 'hi', 'aaaa'), false);
});

test('verifyEd25519: non-string signature → false', () => {
  assert.equal(verifyEd25519(root.publicKey, 'hi', null), false);
  assert.equal(verifyEd25519(root.publicKey, 'hi', undefined), false);
});

// ── verifySigningKey() ──────────────────────────────────────────────────

test('verifySigningKey: happy path → { ok: true, kid, pubkey }', () => {
  const sk = freshSigningKeyFixture();
  const r = verifySigningKey(sk, root.publicKey, NOW);
  assert.equal(r.ok, true);
  assert.equal(r.kid, 'sk-2026-q2');
  assert.equal(r.pubkey.asymmetricKeyType, 'ed25519');
});

test('verifySigningKey: signed by WRONG root → ok=false with reason', () => {
  const sk = freshSigningKeyFixture();
  const r = verifySigningKey(sk, otherRoot.publicKey, NOW);
  assert.equal(r.ok, false);
  assert.match(r.reason, /not signed by trusted root/);
});

test('verifySigningKey: tampered pubkey → ok=false (payload changes, sig no longer valid)', () => {
  const sk = freshSigningKeyFixture();
  sk.pubkey = rawPubB64(otherRoot.publicKey);  // swap the pubkey AFTER signing
  const r = verifySigningKey(sk, root.publicKey, NOW);
  assert.equal(r.ok, false);
});

test('verifySigningKey: expired → ok=false with reason', () => {
  const sk = freshSigningKeyFixture({ valid_until: '2026-01-01T00:00:00.000Z' });
  // Re-sign with the modified validity window so the sig itself is fine —
  // we want to test the time check, not the chain.
  sk.signed_by_root = sig(signingKeyPayload(sk), root.privateKey);
  const r = verifySigningKey(sk, root.publicKey, NOW);
  assert.equal(r.ok, false);
  assert.match(r.reason, /expired/);
});

test('verifySigningKey: not yet valid → ok=false with reason', () => {
  const sk = freshSigningKeyFixture({ valid_from: '2027-01-01T00:00:00.000Z' });
  sk.signed_by_root = sig(signingKeyPayload(sk), root.privateKey);
  const r = verifySigningKey(sk, root.publicKey, NOW);
  assert.equal(r.ok, false);
  assert.match(r.reason, /not yet valid/);
});

test('verifySigningKey: missing required field → ok=false', () => {
  const sk = freshSigningKeyFixture();
  delete sk.kid;
  const r = verifySigningKey(sk, root.publicKey, NOW);
  assert.equal(r.ok, false);
  assert.match(r.reason, /missing required field "kid"/);
});

// ── verifyPolicy() ──────────────────────────────────────────────────────

function freshKeysByKid() {
  const sk = freshSigningKeyFixture();
  const r = verifySigningKey(sk, root.publicKey, NOW);
  assert.equal(r.ok, true);
  const m = new Map();
  m.set(r.kid, r.pubkey);
  return m;
}

test('verifyPolicy: happy path → ok', () => {
  const p = freshPolicyFixture();
  assert.deepEqual(verifyPolicy(p, freshKeysByKid()), { ok: true });
});

test('verifyPolicy: __local: true bypasses signature requirement', () => {
  const local = { rule_id: 'local-1', action: 'allow', match: {}, __local: true };
  assert.deepEqual(verifyPolicy(local, new Map()), { ok: true });
});

test('verifyPolicy: missing signature → ok=false', () => {
  const p = freshPolicyFixture();
  delete p.signature;
  const r = verifyPolicy(p, freshKeysByKid());
  assert.equal(r.ok, false);
  assert.match(r.reason, /missing signature/);
});

test('verifyPolicy: unknown signing_key_id → ok=false', () => {
  const p = freshPolicyFixture({ signing_key_id: 'sk-2027-q1' });
  // We must re-sign after changing signing_key_id because the kid does NOT
  // factor into the payload — so re-signing here keeps the sig valid against
  // the original signing key; but the verifier should still drop because
  // the kid is unknown.
  p.signature = sig(policySigningPayload(p), signing.privateKey);
  p.signing_key_id = 'sk-2027-q1';
  const r = verifyPolicy(p, freshKeysByKid());
  assert.equal(r.ok, false);
  assert.match(r.reason, /unknown signing_key_id/);
});

test('verifyPolicy: tampered action → ok=false (payload changed, sig no longer matches)', () => {
  const p = freshPolicyFixture();
  p.action = 'allow';  // flip deny → allow AFTER signing — classic MITM
  const r = verifyPolicy(p, freshKeysByKid());
  assert.equal(r.ok, false);
  assert.match(r.reason, /signature does not verify/);
});

test('verifyPolicy: tampered match → ok=false', () => {
  const p = freshPolicyFixture();
  p.match = { tool_name: 'web_search' };
  const r = verifyPolicy(p, freshKeysByKid());
  assert.equal(r.ok, false);
});

test('verifyPolicy: tampered mode (enforce→shadow) → ok=false', () => {
  // CRITICAL: if mode wasn't part of the signed payload, an attacker could
  // flip enforce→shadow to silently disable a rule. Pin that mode IS signed.
  const p = freshPolicyFixture();
  p.mode = 'shadow';
  const r = verifyPolicy(p, freshKeysByKid());
  assert.equal(r.ok, false);
  assert.match(r.reason, /signature does not verify/);
});

test('verifyPolicy: tampered priority → ok=false (priority IS signed)', () => {
  // First-match-wins means priority controls evaluation order; an
  // attacker promoting a permissive rule above a restrictive one would
  // bypass enforcement. Pin priority IS signed.
  const p = freshPolicyFixture();
  p.priority = 999;
  const r = verifyPolicy(p, freshKeysByKid());
  assert.equal(r.ok, false);
});

// ── verifyPolicyBundle() ────────────────────────────────────────────────

test('verifyPolicyBundle: valid policies pass, bad ones are dropped with reasons', () => {
  const good = freshPolicyFixture({ rule_id: 'good' });
  const bad = freshPolicyFixture({ rule_id: 'bad' });
  bad.action = 'allow';  // tamper after signing
  const sk = freshSigningKeyFixture();
  const r = verifyPolicyBundle({
    policies: [good, bad],
    signingKeys: [sk],
    rootPublicKey: root.publicKey,
    now: NOW,
  });
  assert.equal(r.validPolicies.length, 1);
  assert.equal(r.validPolicies[0].rule_id, 'good');
  assert.equal(r.droppedPolicies.length, 1);
  assert.equal(r.droppedPolicies[0].rule_id, 'bad');
  assert.match(r.droppedPolicies[0].reason, /signature does not verify/);
});

test('verifyPolicyBundle: signing key rejected → policies signed by it are all dropped', () => {
  // Use a signing key signed by the WRONG root.
  const evilSk = {
    kid: 'sk-evil',
    pubkey: rawPubB64(signing.publicKey),
    valid_from: VALID_FROM,
    valid_until: VALID_UNTIL,
  };
  evilSk.signed_by_root = sig(signingKeyPayload(evilSk), otherRoot.privateKey);
  const p = freshPolicyFixture({ rule_id: 'p1' });
  p.signing_key_id = 'sk-evil';
  p.signature = sig(policySigningPayload(p), signing.privateKey);
  const r = verifyPolicyBundle({
    policies: [p],
    signingKeys: [evilSk],
    rootPublicKey: root.publicKey,
    now: NOW,
  });
  assert.equal(r.validPolicies.length, 0);
  assert.equal(r.droppedPolicies.length, 1);
  assert.equal(r.signingKeyErrors.length, 1);
  assert.match(r.signingKeyErrors[0].reason, /not signed by trusted root/);
});

test('verifyPolicyBundle: __local policies pass without any signing key', () => {
  const local = { rule_id: 'local', action: 'allow', match: {}, __local: true };
  const r = verifyPolicyBundle({
    policies: [local],
    signingKeys: [],
    rootPublicKey: root.publicKey,
    now: NOW,
  });
  assert.equal(r.validPolicies.length, 1);
  assert.equal(r.droppedPolicies.length, 0);
});

test('verifyPolicyBundle: empty inputs return empty outputs (no throw)', () => {
  const r = verifyPolicyBundle({
    policies: [],
    signingKeys: [],
    rootPublicKey: root.publicKey,
    now: NOW,
  });
  assert.equal(r.validPolicies.length, 0);
  assert.equal(r.droppedPolicies.length, 0);
  assert.equal(r.validSigningKeys.size, 0);
});

test('verifyPolicyBundle: missing inputs default to empty (no throw)', () => {
  const r = verifyPolicyBundle({ rootPublicKey: root.publicKey, now: NOW });
  assert.equal(r.validPolicies.length, 0);
});
