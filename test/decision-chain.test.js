// Decision audit chain — v1.2.0.
//
// Locks the contract of src/shield/decision-chain.js plus its end-to-end
// wiring through DecisionLogger + Logger. The chain is the local piece
// of tamper-evidence for shield_decision NDJSON; an investigator who
// suspects log doctoring runs verifyDecisionChain() over the filtered
// file and gets either OK (with segment count) or the exact index where
// the chain breaks.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  createDecisionChain,
  verifyDecisionChain,
  buildGenesisMarker,
  newChainId,
  CHAIN_FIELDS,
} from '../src/shield/decision-chain.js';
import { canonicalize } from '../src/shield/signature.js';
import { DecisionLogger } from '../src/shield/decisions.js';

// ── Chain construction ────────────────────────────────────────────────

test('v1.2.0 chain: wrap() adds prev_hash + chain_hash without mutating input', () => {
  const genesis = buildGenesisMarker({ agentId: 'a', sessionId: 's', startedAtIso: '2026-06-09T00:00:00Z', chainId: 'c1' });
  const chain = createDecisionChain({ genesis });

  const body = { id: 'evt-1', action_type: 'shield_decision', decision: 'deny' };
  const wrapped = chain.wrap(body);

  // Input wasn't mutated.
  assert.equal('prev_hash' in body, false);
  assert.equal('chain_hash' in body, false);

  // Output carries both link fields.
  assert.equal(wrapped.prev_hash, genesis);
  assert.equal(typeof wrapped.chain_hash, 'string');
  assert.equal(wrapped.chain_hash.length, 64); // sha256 hex

  // Original fields preserved verbatim.
  assert.equal(wrapped.id, 'evt-1');
  assert.equal(wrapped.action_type, 'shield_decision');
  assert.equal(wrapped.decision, 'deny');
});

test('v1.2.0 chain: chain_hash is deterministic and reproducible', () => {
  // Same body + same prev_hash → same chain_hash. This is the property
  // the verifier relies on.
  const genesis = 'genesis:test';
  const c1 = createDecisionChain({ genesis });
  const c2 = createDecisionChain({ genesis });
  const body = { id: 'x', action_type: 'shield_decision', decision: 'allow', sequence_number: 1 };
  const w1 = c1.wrap(body);
  const w2 = c2.wrap(body);
  assert.equal(w1.chain_hash, w2.chain_hash);
});

test('v1.2.0 chain: hash recomputation matches the documented formula', () => {
  // Lock the wire format: sha256(prev_hash || '|' || canonical(body sans chain fields)).
  // If anyone "optimizes" the hash input we want this test to scream.
  const genesis = 'genesis:explicit';
  const chain = createDecisionChain({ genesis });
  const body = { a: 1, b: 'two', c: [3, 4] };
  const wrapped = chain.wrap(body);

  const expected = createHash('sha256')
    .update(genesis + '|' + canonicalize(body))
    .digest('hex');
  assert.equal(wrapped.chain_hash, expected);
});

test('v1.2.0 chain: prev_hash advances to previous chain_hash', () => {
  const chain = createDecisionChain({ genesis: 'genesis:abc' });
  const a = chain.wrap({ id: 'a' });
  const b = chain.wrap({ id: 'b' });
  const c = chain.wrap({ id: 'c' });

  assert.equal(a.prev_hash, 'genesis:abc');
  assert.equal(b.prev_hash, a.chain_hash);
  assert.equal(c.prev_hash, b.chain_hash);
  assert.equal(chain.state().prev_hash, c.chain_hash);
  assert.equal(chain.state().count, 3);
});

test('v1.2.0 chain: wrap() rejects malformed bodies (fail-loud)', () => {
  const chain = createDecisionChain({ genesis: 'genesis:x' });
  assert.throws(() => chain.wrap(null), /plain object/);
  assert.throws(() => chain.wrap('string'), /plain object/);
  assert.throws(() => chain.wrap([1, 2, 3]), /plain object/);
});

test('v1.2.0 chain: constructor rejects empty / non-string genesis', () => {
  assert.throws(() => createDecisionChain({}), /genesis/);
  assert.throws(() => createDecisionChain({ genesis: '' }), /genesis/);
  assert.throws(() => createDecisionChain({ genesis: 42 }), /genesis/);
});

test('v1.2.0 chain: CHAIN_FIELDS export is the canonical pair', () => {
  // Other modules use this constant to filter out chain fields when
  // they want the "raw" body. Lock the value.
  assert.deepEqual([...CHAIN_FIELDS].sort(), ['chain_hash', 'prev_hash']);
});

test('v1.2.0 chain: buildGenesisMarker is structured and inspectable', () => {
  const g = buildGenesisMarker({
    agentId: 'agent-42',
    sessionId: 'sess-xyz',
    startedAtIso: '2026-06-09T12:00:00.000Z',
    chainId: 'chain-001',
  });
  assert.match(g, /^genesis:agent-42:sess-xyz:2026-06-09T12:00:00\.000Z:chain-001$/);
});

test('v1.2.0 chain: newChainId returns a fresh UUID each call', () => {
  const a = newChainId(), b = newChainId();
  assert.notEqual(a, b);
  assert.match(a, /^[0-9a-f-]{36}$/);
});

// ── Verifier ──────────────────────────────────────────────────────────

test('v1.2.0 verify: empty file returns OK with zero segments', () => {
  const r = verifyDecisionChain([]);
  assert.deepEqual(r, { ok: true, count: 0, segments: 0 });
});

test('v1.2.0 verify: single-segment chain verifies clean', () => {
  const chain = createDecisionChain({ genesis: 'genesis:s' });
  const records = [
    chain.wrap({ id: 'a', n: 1 }),
    chain.wrap({ id: 'b', n: 2 }),
    chain.wrap({ id: 'c', n: 3 }),
  ];
  const r = verifyDecisionChain(records);
  assert.equal(r.ok, true);
  assert.equal(r.count, 3);
  assert.equal(r.segments, 1);
});

test('v1.2.0 verify: detects in-place modification of a record body', () => {
  const chain = createDecisionChain({ genesis: 'genesis:tampered' });
  const records = [
    chain.wrap({ id: 'a', decision: 'allow' }),
    chain.wrap({ id: 'b', decision: 'allow' }),
    chain.wrap({ id: 'c', decision: 'deny' }),
  ];
  // Attacker tries to flip a denial to an allow without re-hashing.
  records[2].decision = 'allow';
  const r = verifyDecisionChain(records);
  assert.equal(r.ok, false);
  assert.equal(r.broken_at, 2);
  assert.match(r.reason, /chain_hash recomputation mismatch/);
});

test('v1.2.0 verify: detects record insertion (prev_hash mismatch on next)', () => {
  const chain = createDecisionChain({ genesis: 'genesis:ins' });
  const a = chain.wrap({ id: 'a' });
  const b = chain.wrap({ id: 'b' });
  // Attacker forges a record between a and b with a, b's prev_hash.
  const fake = { id: 'fake', prev_hash: a.chain_hash, chain_hash: 'deadbeef'.repeat(8) };
  const records = [a, fake, b];
  const r = verifyDecisionChain(records);
  assert.equal(r.ok, false);
  // Index 1 fails: its chain_hash doesn't recompute.
  assert.equal(r.broken_at, 1);
});

test('v1.2.0 verify: detects record deletion (mid-chain prev_hash gap)', () => {
  const chain = createDecisionChain({ genesis: 'genesis:del' });
  const a = chain.wrap({ id: 'a' });
  const b = chain.wrap({ id: 'b' });
  const c = chain.wrap({ id: 'c' });
  // Attacker drops b. The remaining records now show a → c, but c's
  // prev_hash still references b → mismatch.
  const r = verifyDecisionChain([a, c]);
  assert.equal(r.ok, false);
  assert.equal(r.broken_at, 1);
  assert.match(r.reason, /prev_hash mismatch/);
});

test('v1.2.0 verify: detects deletion of the final record cluster (truncation)', () => {
  // Truncation alone is silent — there's no successor record to scream.
  // This is a known limitation of any append-only hash chain. We assert
  // the limitation explicitly so anyone reading the test knows.
  const chain = createDecisionChain({ genesis: 'genesis:trunc' });
  const records = [
    chain.wrap({ id: 'a' }),
    chain.wrap({ id: 'b' }),
    chain.wrap({ id: 'c' }),
  ];
  // Truncate the last record.
  const truncated = records.slice(0, 2);
  const r = verifyDecisionChain(truncated);
  assert.equal(r.ok, true, 'pure truncation cannot be detected locally — guarded against by Fortress ingest in a future revision');
});

test('v1.2.0 verify: multi-segment file with valid genesis-restart is accepted', () => {
  // Simulate two Shield runs writing to the same NDJSON file: each run
  // has its own genesis marker, and the verifier walks both segments.
  const chainA = createDecisionChain({ genesis: 'genesis:run-1' });
  const chainB = createDecisionChain({ genesis: 'genesis:run-2' });
  const records = [
    chainA.wrap({ id: 'a1' }),
    chainA.wrap({ id: 'a2' }),
    chainB.wrap({ id: 'b1' }),  // new segment starts here
    chainB.wrap({ id: 'b2' }),
  ];
  const r = verifyDecisionChain(records);
  assert.equal(r.ok, true);
  assert.equal(r.segments, 2);
});

test('v1.2.0 verify: non-genesis prev_hash mismatch at segment boundary is rejected', () => {
  // If a record's prev_hash doesn't match the previous record's
  // chain_hash AND doesn't look like a genesis marker, that's a tamper
  // signal (or a corrupt restart).
  const chain = createDecisionChain({ genesis: 'genesis:seg' });
  const a = chain.wrap({ id: 'a' });
  const fake = { id: 'fake', prev_hash: 'random-not-genesis', chain_hash: 'deadbeef'.repeat(8) };
  const r = verifyDecisionChain([a, fake]);
  assert.equal(r.ok, false);
  assert.match(r.reason, /not a genesis marker/);
});

test('v1.2.0 verify: rejects malformed records (missing fields)', () => {
  const r1 = verifyDecisionChain([{ id: 'no-chain' }]);
  assert.equal(r1.ok, false);
  assert.match(r1.reason, /missing prev_hash or chain_hash/);

  const r2 = verifyDecisionChain([{ id: 'partial', prev_hash: 'x' }]);
  assert.equal(r2.ok, false);
  assert.match(r2.reason, /missing prev_hash or chain_hash/);
});

test('v1.2.0 verify: rejects non-array input', () => {
  const r = verifyDecisionChain('not-an-array');
  assert.equal(r.ok, false);
  assert.equal(r.broken_at, -1);
});

// ── End-to-end via DecisionLogger ─────────────────────────────────────

test('v1.2.0 e2e: DecisionLogger writes chain-augmented shield_decision lines', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'wma-chain-'));
  try {
    const dl = new DecisionLogger({ logDir: dir, agentId: 'agent-x', sessionId: 'sess-y' });

    const w1 = await dl.record({
      sourceEvent: { id: 'evt-1', type: 'agent.tool_use', tool_name: 'bash' },
      decision: 'deny', ruleId: 'r1', ruleName: 'block-bash', message: 'nope',
      decidedInMs: 2, mode: 'enforce',
    });
    const w2 = await dl.record({
      sourceEvent: { id: 'evt-2', type: 'agent.tool_use', tool_name: 'web_search' },
      decision: 'allow', ruleId: null, ruleName: '(default)', message: null,
      decidedInMs: 1, mode: 'enforce',
    });

    // Each return value carries the chain fields.
    assert.equal(typeof w1.prev_hash, 'string');
    assert.equal(typeof w1.chain_hash, 'string');
    assert.equal(w2.prev_hash, w1.chain_hash, 'second row chains to first');

    // Read the file back and verify the on-disk shape.
    const day = new Date().toISOString().slice(0, 10);
    const path = join(dir, 'agent-x', `${day}.ndjson`);
    const text = await readFile(path, 'utf8');
    const lines = text.trim().split('\n').map(l => JSON.parse(l));
    assert.equal(lines.length, 2);
    assert.equal(lines[0].action_type, 'shield_decision');
    assert.equal(lines[0].chain_hash, w1.chain_hash);
    assert.equal(lines[1].prev_hash, lines[0].chain_hash);

    // Verifier accepts the file.
    const r = verifyDecisionChain(lines.filter(l => l.action_type === 'shield_decision'));
    assert.equal(r.ok, true);
    assert.equal(r.count, 2);
    assert.equal(r.segments, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('v1.2.0 e2e: verifier catches on-disk tamper of a shield_decision line', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'wma-chain-tamper-'));
  try {
    const dl = new DecisionLogger({ logDir: dir, agentId: 'agent-t', sessionId: 'sess-t' });
    await dl.record({
      sourceEvent: { id: 'evt-1', tool_name: 'bash' },
      decision: 'deny', ruleId: 'r1', ruleName: 'block-bash',
      message: 'denied', decidedInMs: 1, mode: 'enforce',
    });
    await dl.record({
      sourceEvent: { id: 'evt-2', tool_name: 'web_search' },
      decision: 'allow', ruleId: null, ruleName: '(default)',
      message: null, decidedInMs: 1, mode: 'enforce',
    });

    const day = new Date().toISOString().slice(0, 10);
    const path = join(dir, 'agent-t', `${day}.ndjson`);
    const text = await readFile(path, 'utf8');
    const lines = text.trim().split('\n').map(l => JSON.parse(l));

    // Simulate post-write tamper: flip the first decision from deny to allow.
    lines[0].output.decision = 'allow';

    const r = verifyDecisionChain(lines.filter(l => l.action_type === 'shield_decision'));
    assert.equal(r.ok, false);
    assert.equal(r.broken_at, 0);
    assert.match(r.reason, /chain_hash recomputation mismatch/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ── F-39 (v1.4.2, P0 audit) — undefined-valued fields must not break the chain ──

test('F-39: a body with an undefined-valued nested field still verifies after a disk round-trip', () => {
  // THE BUG: canonicalize emitted the literal token `undefined` for such a
  // key at write time, but JSON.stringify DROPS it on disk, so the verifier
  // (re-reading the JSON-parsed record) re-canonicalized to a different
  // string → chain_hash mismatch on an UNTAMPERED record.
  const genesis = buildGenesisMarker({ agentId: 'a', sessionId: 's', startedAtIso: '2026-06-09T00:00:00Z', chainId: 'c1' });
  const chain = createDecisionChain({ genesis });

  // Realistic shape: decisions.js embeds the raw source event input verbatim
  // (input.tool_input = sourceEvent.input). An object-literal-constructed
  // event can carry undefined-valued optional fields.
  const wrapped = chain.wrap({
    id: 'evt-1',
    action_type: 'shield_decision',
    input: { tool_input: { url: 'http://x', max_uses: undefined, retries: undefined } },
    output: { decision: 'deny', rule_id: undefined },
  });

  // Round-trip exactly as the NDJSON writer + reader do.
  const onDisk = JSON.parse(JSON.stringify(wrapped));

  const r = verifyDecisionChain([onDisk]);
  assert.equal(r.ok, true, `untampered record with undefined fields must verify; got ${JSON.stringify(r)}`);
  assert.equal(r.count, 1);
});

test('F-39: undefined fields do not mask a REAL tamper (still detected)', () => {
  const genesis = buildGenesisMarker({ agentId: 'a', sessionId: 's', startedAtIso: '2026-06-09T00:00:00Z', chainId: 'c1' });
  const chain = createDecisionChain({ genesis });
  const wrapped = chain.wrap({
    id: 'evt-1', action_type: 'shield_decision',
    input: { tool_input: { url: 'http://x', max_uses: undefined } },
    output: { decision: 'deny' },
  });
  const onDisk = JSON.parse(JSON.stringify(wrapped));
  // Tamper: flip the decision.
  onDisk.output.decision = 'allow';
  const r = verifyDecisionChain([onDisk]);
  assert.equal(r.ok, false);
  assert.equal(r.broken_at, 0);
});

test('F-39: canonicalize matches JSON.stringify key/element semantics (sorted)', () => {
  // Object keys with undefined/function/symbol values are dropped; array
  // elements of those types become null — exactly JSON.stringify's rules.
  const obj = { z: 1, a: undefined, b: function () {}, c: [1, undefined, 'x'], d: 'y' };
  const viaCanon = canonicalize(JSON.parse(JSON.stringify(obj)));
  const viaCanonDirect = canonicalize(obj);
  assert.equal(viaCanonDirect, viaCanon, 'canonicalize must equal canonicalize-after-JSON-roundtrip');
  assert.equal(viaCanonDirect, '{"c":[1,null,"x"],"d":"y","z":1}');
});
