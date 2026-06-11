// FortressPolicySource signature verification — v1.1.5 Phase 1.5.B
//
// Verifies the integration between fetchPolicies + verifyPolicyBundle +
// compilePolicyFromFortress:
//   - signed policies → loaded into ruleset
//   - tampered policies → dropped + onError fires
//   - signing key rejected → policies signed by it ALL dropped
//   - strict mode (default): unsigned policies dropped
//   - lax mode (constructor opt-in): unsigned policies kept with onError warning
//   - placeholder root pubkey: verification SKIPPED with loud onError, all
//     policies passed through (so dev workflows still work end-to-end)
//
// We stub the network at the fetchPolicies seam: a small in-process
// FortressPolicySource subclass that overrides _refresh's first step,
// returning a synthetic response built from real Ed25519 keypairs.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { FortressPolicySource } from '../src/shield/sources/fortress.js';
import {
  signingKeyPayload, policySigningPayload, importEd25519PublicKey,
} from '../src/shield/signature.js';

// ── Fixture keys ────────────────────────────────────────────────────────

const root = generateKeyPairSync('ed25519');
const signing = generateKeyPairSync('ed25519');

function rawPubB64(keyObj) {
  const spki = keyObj.export({ format: 'der', type: 'spki' });
  return spki.slice(spki.length - 32).toString('base64');
}
function sig(payload, privKey) {
  return cryptoSign(null, Buffer.from(payload, 'utf8'), privKey).toString('base64');
}

const VALID_FROM = '2026-01-01T00:00:00.000Z';
const VALID_UNTIL = '2026-12-31T23:59:59.000Z';

function freshSigningKey() {
  const sk = { kid: 'sk-q', pubkey: rawPubB64(signing.publicKey), valid_from: VALID_FROM, valid_until: VALID_UNTIL };
  sk.signed_by_root = sig(signingKeyPayload(sk), root.privateKey);
  return sk;
}

function freshSignedPolicy(over = {}) {
  const p = {
    rule_id: 'r-bash',
    name: 'no-bash',
    match: { tool_name: 'bash' },
    action: 'deny',
    message: 'no bash',
    priority: 100,
    mode: 'enforce',
    ...over,
  };
  p.signature = sig(policySigningPayload(p), signing.privateKey);
  p.signing_key_id = 'sk-q';
  return p;
}

// ── Test harness: subclass that injects a fake fetchPolicies response ───
//
// We override fetchPolicies via prototype-style monkeypatch on the
// MODULE, but cleaner: subclass and override the private fetch step.
// Since fetchPolicies is a free function in the module, the simplest
// hermetic approach is to write a tiny wrapper class that bypasses
// fetchPolicies entirely and drives _verifyAndFilter directly through
// _refresh's logic. We do that by directly calling the public method
// we care about: _verifyAndFilter.

class TestFortressSource extends FortressPolicySource {
  constructor(opts) {
    super({ apiKey: 'k', base: 'https://x', ...opts });
  }
  // Expose the private verifier for direct testing without HTTP.
  verifyForTest(rawPolicies, rawSigningKeys) {
    return this._verifyAndFilter(rawPolicies, rawSigningKeys);
  }
}

// ── Tests ───────────────────────────────────────────────────────────────

// NOTE — v1.1.5 release: the placeholder root was flipped to the real
// production pubkey on 2026-06-02. The placeholder-mode path is now
// covered by reading the constants directly rather than building a live
// FortressPolicySource. The next root rotation (every 2y or compromise)
// will go back through a brief placeholder window in the RC build —
// keep this test shape alive for that scenario.
test('1.5.B placeholder root flag: post-release, IS_PLACEHOLDER must be false', async () => {
  // Pin the release invariant: a v1.1.5+ ships with a real root,
  // never with the placeholder, and never with a null ROOT_PUBLIC_KEY.
  const { WMA_FORTRESS_ROOT_IS_PLACEHOLDER, WMA_FORTRESS_ROOT_PUBKEY_B64 } =
    await import('../src/shield/root-key.js');
  assert.equal(WMA_FORTRESS_ROOT_IS_PLACEHOLDER, false, 'must NOT ship a placeholder root in a released SDK');
  assert.equal(WMA_FORTRESS_ROOT_PUBKEY_B64.length, 44, 'real root pubkey is exactly 44 base64 chars');
  assert.notEqual(WMA_FORTRESS_ROOT_PUBKEY_B64.indexOf('PLACEHOLDER'), 0, 'must not still start with PLACEHOLDER');
  // Also sanity-check it decodes to 32 bytes (Ed25519 raw pubkey).
  assert.equal(Buffer.from(WMA_FORTRESS_ROOT_PUBKEY_B64, 'base64').length, 32);
});

test('1.5.B real root: bundle signed by the WRONG root (test fixture) is fully rejected in strict mode', () => {
  // The TestFortressSource now uses the REAL production root pubkey
  // baked into src/shield/root-key.js. Our test fixture's `root` keypair
  // is a different one, so policies signed by it must NOT verify.
  // This double-checks the production root is actually being consulted.
  const errors = [];
  const src = new TestFortressSource({ onError: (e) => errors.push(e.message) });
  const p1 = freshSignedPolicy({ rule_id: 'r-1' });  // signed with test signing key
  const out = src.verifyForTest([p1], [freshSigningKey()]);  // signing key signed with test root
  assert.equal(out.length, 0, 'strict mode drops every policy whose chain does not reach the embedded real root');
  // Two errors expected: the signing key is rejected ("not signed by trusted root")
  // AND the policy's signing_key_id then points to nothing valid.
  assert.ok(errors.some(e => /not signed by trusted root/i.test(e)));
});

// The remaining tests exercise STRICT mode by injecting a "real" root.
// We use Object.defineProperty to monkey-patch the module's ROOT_PUBLIC_KEY
// constant... actually we can't, ESM exports are immutable. Instead, we
// build a dedicated harness that does the verification with the right
// root, bypassing the module-level constant.

import { verifyPolicyBundle } from '../src/shield/signature.js';

// Drop-in test for the same logic _verifyAndFilter implements, but with
// the test's own root pubkey. Mirrors the real method 1:1.
function verifyWithRoot({ rawPolicies, rawSigningKeys, rootPubKey, strict, onError }) {
  const bundle = verifyPolicyBundle({
    policies: rawPolicies || [], signingKeys: rawSigningKeys || [], rootPublicKey: rootPubKey,
  });
  for (const ke of bundle.signingKeyErrors) onError(new Error(`signing key "${ke.kid}": ${ke.reason}`));
  for (const dp of bundle.droppedPolicies) {
    const verb = strict ? 'DROPPING' : 'WARNING (lax mode)';
    onError(new Error(`${verb} policy "${dp.rule_id}": ${dp.reason}`));
  }
  return strict ? bundle.validPolicies : (rawPolicies || []);
}

test('1.5.B strict mode: valid signed policy passes', () => {
  const errors = [];
  const out = verifyWithRoot({
    rawPolicies: [freshSignedPolicy()],
    rawSigningKeys: [freshSigningKey()],
    rootPubKey: root.publicKey, strict: true,
    onError: (e) => errors.push(e.message),
  });
  assert.equal(out.length, 1);
  assert.equal(out[0].rule_id, 'r-bash');
  assert.equal(errors.length, 0, 'no warnings on a valid bundle');
});

test('1.5.B strict mode: tampered action → policy DROPPED + onError fires', () => {
  const p = freshSignedPolicy();
  p.action = 'allow';  // flip after signing
  const errors = [];
  const out = verifyWithRoot({
    rawPolicies: [p], rawSigningKeys: [freshSigningKey()],
    rootPubKey: root.publicKey, strict: true,
    onError: (e) => errors.push(e.message),
  });
  assert.equal(out.length, 0, 'tampered policy dropped');
  assert.ok(errors.some(e => /DROPPING/.test(e) && /signature does not verify/.test(e)));
});

test('1.5.B strict mode: tampered mode (enforce→shadow) → policy DROPPED', () => {
  // Critical security pin: an attacker MUST NOT be able to silently
  // demote a deny rule from enforce to shadow.
  const p = freshSignedPolicy();
  p.mode = 'shadow';
  const errors = [];
  const out = verifyWithRoot({
    rawPolicies: [p], rawSigningKeys: [freshSigningKey()],
    rootPubKey: root.publicKey, strict: true,
    onError: (e) => errors.push(e.message),
  });
  assert.equal(out.length, 0);
});

test('1.5.B strict mode: unsigned policy → DROPPED + onError fires', () => {
  const unsigned = { rule_id: 'r-x', action: 'deny', match: {} };
  const errors = [];
  const out = verifyWithRoot({
    rawPolicies: [unsigned], rawSigningKeys: [freshSigningKey()],
    rootPubKey: root.publicKey, strict: true,
    onError: (e) => errors.push(e.message),
  });
  assert.equal(out.length, 0);
  assert.ok(errors.some(e => /missing signature/.test(e)));
});

test('1.5.B strict mode: signing key rejected → ALL policies signed by it dropped', () => {
  const otherRoot = generateKeyPairSync('ed25519');
  // Forge a signing key signed by the WRONG root.
  const evilSk = { kid: 'sk-evil', pubkey: rawPubB64(signing.publicKey), valid_from: VALID_FROM, valid_until: VALID_UNTIL };
  evilSk.signed_by_root = sig(signingKeyPayload(evilSk), otherRoot.privateKey);
  const p = freshSignedPolicy({ rule_id: 'r-x' });
  p.signing_key_id = 'sk-evil';
  p.signature = sig(policySigningPayload(p), signing.privateKey);
  const errors = [];
  const out = verifyWithRoot({
    rawPolicies: [p], rawSigningKeys: [evilSk],
    rootPubKey: root.publicKey, strict: true,
    onError: (e) => errors.push(e.message),
  });
  assert.equal(out.length, 0);
  assert.ok(errors.some(e => /not signed by trusted root/.test(e)));
  assert.ok(errors.some(e => /unknown signing_key_id/.test(e)));
});

test('1.5.B lax mode: unsigned policy KEPT but onError warning fires', () => {
  const unsigned = { rule_id: 'r-x', action: 'deny', match: {} };
  const errors = [];
  const out = verifyWithRoot({
    rawPolicies: [unsigned], rawSigningKeys: [freshSigningKey()],
    rootPubKey: root.publicKey, strict: false,
    onError: (e) => errors.push(e.message),
  });
  assert.equal(out.length, 1, 'lax mode keeps unsigned policies');
  assert.ok(errors.some(e => /WARNING \(lax mode\)/.test(e)));
});

test('1.5.B lax mode: tampered policy STILL KEPT (caller signalled trust degradation)', () => {
  // Lax mode is explicitly opt-in by ops to handle a Fortress signing
  // pipeline outage. In that state the operator has accepted "I'm
  // running without signature enforcement until the pipeline is back".
  // Drop nothing; let the warnings speak.
  const p = freshSignedPolicy();
  p.action = 'allow';
  const errors = [];
  const out = verifyWithRoot({
    rawPolicies: [p], rawSigningKeys: [freshSigningKey()],
    rootPubKey: root.publicKey, strict: false,
    onError: (e) => errors.push(e.message),
  });
  assert.equal(out.length, 1);
  assert.ok(errors.some(e => /WARNING \(lax mode\)/.test(e)));
});

test('1.5.B strict mode: mixed bundle — keep valid, drop invalid, surface both', () => {
  const good = freshSignedPolicy({ rule_id: 'good' });
  const tampered = freshSignedPolicy({ rule_id: 'tampered' });
  tampered.action = 'allow';
  const unsigned = { rule_id: 'unsigned', action: 'deny', match: {} };
  const errors = [];
  const out = verifyWithRoot({
    rawPolicies: [good, tampered, unsigned],
    rawSigningKeys: [freshSigningKey()],
    rootPubKey: root.publicKey, strict: true,
    onError: (e) => errors.push(e.message),
  });
  assert.equal(out.length, 1);
  assert.equal(out[0].rule_id, 'good');
  assert.equal(errors.length, 2, 'both invalid policies surface as warnings');
});

// ── Constructor wiring ──────────────────────────────────────────────────

test('1.5.B FortressPolicySource constructor: requireSignedPolicies defaults to strict', () => {
  // No env, no opt → strict mode.
  delete process.env.WMA_REQUIRE_SIGNED_POLICIES;
  const src = new FortressPolicySource({ apiKey: 'k', base: 'https://x' });
  assert.equal(src.requireSignedPolicies, true);
});

test('1.5.B FortressPolicySource constructor: env var WMA_REQUIRE_SIGNED_POLICIES=false switches to lax', () => {
  process.env.WMA_REQUIRE_SIGNED_POLICIES = 'false';
  try {
    const src = new FortressPolicySource({ apiKey: 'k', base: 'https://x' });
    assert.equal(src.requireSignedPolicies, false);
  } finally {
    delete process.env.WMA_REQUIRE_SIGNED_POLICIES;
  }
});

test('1.5.B FortressPolicySource constructor: explicit option wins over env var', () => {
  process.env.WMA_REQUIRE_SIGNED_POLICIES = 'false';
  try {
    const src = new FortressPolicySource({ apiKey: 'k', base: 'https://x', requireSignedPolicies: true });
    assert.equal(src.requireSignedPolicies, true);
  } finally {
    delete process.env.WMA_REQUIRE_SIGNED_POLICIES;
  }
});

// ── F-48 (v1.4.2, P2 audit) — fail-closed when a refresh drops everything ──
//
// A successful refresh that SENT policies but compiled NONE (all dropped by
// signature verification or compile validation) must NOT install the empty
// { default: allow } ruleset — that silently disarms Shield. We drive
// _refresh hermetically via the _fetchPolicies seam, in LAX mode so an
// unsigned policy is kept by verification and we control drop-vs-keep purely
// through compile validity (action good/bogus).

class DriveFortress extends FortressPolicySource {
  constructor(opts = {}) {
    // lax mode → unsigned policies survive _verifyAndFilter; compile decides.
    super({ apiKey: 'k', base: 'https://x', requireSignedPolicies: false, ...opts });
    this._next = { policies: [], signing_keys: [], fetched_at: '2026-06-11T00:00:00Z' };
  }
  setNext(policies) { this._next = { ...this._next, policies }; }
  async _fetchPolicies() { return this._next; }
}

const okPolicy = (id = 'r-ok') => ({ rule_id: id, name: id, match: { tool_name: 'bash' }, action: 'deny', priority: 100, mode: 'enforce' });
const bogusPolicy = (id = 'r-bad') => ({ rule_id: id, name: id, match: { tool_name: 'bash' }, action: 'TOTALLY_BOGUS', priority: 100, mode: 'enforce' });

test('F-48: all policies dropped + no prior ruleset → FAIL-CLOSED to deny-by-default', async () => {
  const errors = [];
  const src = new DriveFortress({ onError: (e) => errors.push(e) });
  src.setNext([bogusPolicy()]);                 // server sent 1, it won't compile
  await src._refresh({ initial: false });
  assert.equal(src.current().default.action, 'deny', 'must NOT be allow-everything');
  assert.equal(src.current().policies.length, 0);
  assert.ok(errors.some((e) => /FAIL-CLOSED/.test(e.message)), 'a loud fail-closed error must fire');
});

test('F-48: a legitimately empty response (server sent 0) installs allow as intended', async () => {
  const src = new DriveFortress();
  src.setNext([]);                              // operator cleared all policies
  await src._refresh({ initial: false });
  assert.equal(src.current().default.action, 'allow', 'empty-by-design is not a drop → allow');
  assert.equal(src.current().policies.length, 0);
});

test('F-48: all-dropped AFTER a good refresh → retains last-known-good ruleset', async () => {
  const errors = [];
  const src = new DriveFortress({ onError: (e) => errors.push(e) });
  // 1) good refresh installs a compilable policy
  src.setNext([okPolicy('r-keep')]);
  await src._refresh({ initial: false });
  assert.equal(src.current().policies.length, 1);
  // 2) next refresh drops everything → must KEEP the prior policy, not wipe it
  src.setNext([bogusPolicy()]);
  await src._refresh({ initial: false });
  assert.equal(src.current().policies.length, 1, 'last-known-good ruleset retained');
  assert.equal(src.current().policies[0].id || src.current().policies[0].rule_id, 'r-keep');
  assert.ok(errors.some((e) => /retaining last-known-good/i.test(e.message)));
});

test('F-48: WMA_SHIELD_FAIL_MODE=open opt-out preserves the pre-F-48 allow behavior', async () => {
  const src = new DriveFortress({ failMode: 'open' });
  src.setNext([bogusPolicy()]);
  await src._refresh({ initial: false });
  assert.equal(src.current().default.action, 'allow', 'fail-open opt-out installs allow');
  assert.equal(src.current().policies.length, 0);
});

test('F-48: failMode defaults to closed; env=open flips it', () => {
  assert.equal(new FortressPolicySource({ apiKey: 'k', base: 'https://x' }).failMode, 'closed');
  process.env.WMA_SHIELD_FAIL_MODE = 'open';
  try {
    assert.equal(new FortressPolicySource({ apiKey: 'k', base: 'https://x' }).failMode, 'open');
  } finally {
    delete process.env.WMA_SHIELD_FAIL_MODE;
  }
});
